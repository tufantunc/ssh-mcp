import type { ClientChannel } from 'ssh2';
import type { CommandResult, SessionInfo, SessionStatus } from '../types.js';
import { tracer } from '../observability/tracer.js';

const ANSI_REGEX = /\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r/g;

function stripAnsi(text: string): string {
  return text.replace(ANSI_REGEX, '');
}

export abstract class Session {
  readonly id: string;
  readonly name: string;
  readonly profile: string;
  readonly type: 'interactive' | 'background';
  readonly createdAt: Date;
  lastActivity: Date;
  ttlMs: number;
  protected _status: SessionStatus = 'active';

  constructor(id: string, name: string, profile: string, type: 'interactive' | 'background', ttlMs: number) {
    this.id = id;
    this.name = name;
    this.profile = profile;
    this.type = type;
    this.createdAt = new Date();
    this.lastActivity = new Date();
    this.ttlMs = ttlMs;
  }

  get status(): SessionStatus {
    return this._status;
  }

  isExpired(): boolean {
    return Date.now() - this.lastActivity.getTime() > this.ttlMs;
  }

  protected touch(): void {
    this.lastActivity = new Date();
  }

  abstract run(command: string, timeoutMs?: number): Promise<CommandResult>;
  abstract close(): Promise<void>;

  markDisconnected(): void {
    if (this._status === 'active') {
      this._status = 'disconnected';
    }
  }

  toInfo(): SessionInfo {
    return {
      id: this.id,
      name: this.name,
      profile: this.profile,
      type: this.type,
      status: this._status,
      createdAt: this.createdAt,
      lastActivity: this.lastActivity,
      ttlMs: this.ttlMs,
    };
  }
}

export class InteractiveSession extends Session {
  private stream: ClientChannel;
  private cwd = '~';
  private outputBuffer = '';
  private static MAX_OUTPUT = 1_048_576;

  constructor(id: string, name: string, profile: string, stream: ClientChannel, ttlMs: number) {
    super(id, name, profile, 'interactive', ttlMs);
    this.stream = stream;
    stream.on('close', () => {
      this._status = 'closed';
    });
  }

  async run(command: string, timeoutMs = 60_000): Promise<CommandResult> {
    if (this._status !== 'active') {
      throw new Error(`Session ${this.name} is not active (status: ${this._status})`);
    }

    const span = tracer.startSpan('ssh.session.run');
    span.setAttribute('session.id', this.id);
    span.setAttribute('session.name', this.name);

    const marker = this.generateMarker();
    const sentinel = `SSHMCP_END_${marker}`;
    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      let buffer = '';
      let resolved = false;

      const timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          this.stream.removeListener('data', dataHandler);
          reject(new Error(`Command timed out after ${timeoutMs}ms in session ${this.name}`));
        }
      }, timeoutMs);

      const sentinelRegex = new RegExp(`${sentinel}__(\\d+)__`);

      const dataHandler = (data: Buffer) => {
        buffer += data.toString();
        if (buffer.length > InteractiveSession.MAX_OUTPUT * 2) {
          buffer = buffer.slice(-InteractiveSession.MAX_OUTPUT * 2);
        }

        const match = buffer.match(sentinelRegex);
        if (match && !resolved) {
          resolved = true;
          clearTimeout(timeoutId);
          this.stream.removeListener('data', dataHandler);

          const exitCode = parseInt(match[1]);

          const sentinelLineIdx = buffer.indexOf(`${sentinel}__`);
          let beforeSentinel = buffer.substring(0, sentinelLineIdx);

          const cleaned = stripAnsi(beforeSentinel);
          const lines = cleaned.split('\n');

          const outputLines: string[] = [];
          for (let i = 1; i < lines.length; i++) {
            const line = lines[i];
            if (line.includes('printf') && line.includes(sentinel.slice(0, 10))) break;
            if (/^[^$]*\$?\s*printf\s+/.test(line) && line.includes(sentinel.slice(0, 10))) break;
            outputLines.push(line);
          }

          let output = outputLines.join('\n').replace(/^\n+/, '').replace(/\n+$/, '');

          if (command.trim().startsWith('cd ')) {
            this.cwd = command.trim().slice(3) || '~';
          }

          this.touch();
          this.outputBuffer = output;

          resolve({
            stdout: output,
            stderr: '',
            exitCode,
            durationMs: Date.now() - startTime,
            cwd: this.cwd,
            sessionId: this.id,
            profile: this.profile,
          });
          span.setAttribute('ssh.exitCode', exitCode);
          span.end();
        }
      };

      this.stream.on('data', dataHandler);
      this.stream.write(`${command}\n`);
      this.stream.write(`printf '%s__%s__\\n' '${sentinel}' "$?"\n`);
    });
  }

  private generateMarker(): string {
    return Math.random().toString(36).substring(2, 14) + Date.now().toString(36);
  }

  async close(): Promise<void> {
    try {
      this.stream.end();
    } catch { /* ignore */ }
    this._status = 'closed';
  }

  get currentCwd(): string {
    return this.cwd;
  }
}

export class BackgroundSession extends Session {
  private stream: ClientChannel;
  private ringBuffer: string[] = [];
  private ringBytes = 0;
  private ringMax = 10_000;
  private exitCode: number | null = null;
  private static RING_CHAR_LIMIT = 100_000;

  constructor(id: string, name: string, profile: string, stream: ClientChannel, ttlMs: number) {
    super(id, name, profile, 'background', ttlMs);
    this.stream = stream;
    stream.on('data', (data: Buffer) => {
      const text = data.toString();
      const lines = text.split('\n');
      for (const line of lines) {
        this.ringBuffer.push(line);
        this.ringBytes += line.length + 1;
      }
      this.trimRingBuffer();
      this.touch();
    });
    stream.on('close', (code: number) => {
      this.exitCode = code;
      this._status = this.isExpired() ? 'expired' : 'closed';
    });
  }

  private trimRingBuffer(): void {
    while (this.ringBytes > BackgroundSession.RING_CHAR_LIMIT && this.ringBuffer.length > 0) {
      const removed = this.ringBuffer.shift()!;
      this.ringBytes -= removed.length + 1;
    }
    if (this.ringBuffer.length > this.ringMax) {
      const drop = this.ringBuffer.splice(0, this.ringBuffer.length - this.ringMax);
      for (const d of drop) {
        this.ringBytes -= d.length + 1;
      }
    }
  }

  readOutput(lines = 50): string {
    return this.ringBuffer.slice(-lines).join('\n');
  }

  isRunning(): boolean {
    return this._status === 'active';
  }

  getExitCode(): number | null {
    return this.exitCode;
  }

  async run(_command: string): Promise<CommandResult> {
    throw new Error('Background sessions do not support run(). The command was started when the session was opened.');
  }

  async close(): Promise<void> {
    try { this.stream.close(); } catch { /* ignore */ }
    this._status = 'closed';
  }
}
