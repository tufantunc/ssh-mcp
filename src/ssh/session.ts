import type { ClientChannel } from 'ssh2';
import type { CommandResult, SessionInfo, SessionStatus } from '../types.js';
import { tracer } from '../observability/tracer.js';

const ANSI_REGEX = /\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r/g;

export function stripAnsi(text: string): string {
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
  /** Absolute lifetime cap, measured from createdAt. Undefined = no cap. */
  readonly maxLifetimeMs?: number;
  protected _status: SessionStatus = 'active';

  constructor(
    id: string,
    name: string,
    profile: string,
    type: 'interactive' | 'background',
    ttlMs: number,
    maxLifetimeMs?: number,
  ) {
    this.id = id;
    this.name = name;
    this.profile = profile;
    this.type = type;
    this.createdAt = new Date();
    this.lastActivity = new Date();
    this.ttlMs = ttlMs;
    this.maxLifetimeMs = maxLifetimeMs;
  }

  get status(): SessionStatus {
    return this._status;
  }

  isExpired(): boolean {
    // The idle TTL alone never fires for a chatty background process, because
    // every data chunk touches lastActivity. The absolute cap is what actually
    // bounds a `tail -f`-style session.
    if (this.maxLifetimeMs !== undefined && Date.now() - this.createdAt.getTime() > this.maxLifetimeMs) {
      return true;
    }
    return Date.now() - this.lastActivity.getTime() > this.ttlMs;
  }

  protected touch(): void {
    this.lastActivity = new Date();
  }

  abstract run(command: string, timeoutMs?: number, abortSignal?: AbortSignal): Promise<CommandResult>;
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
  private static MAX_OUTPUT = 1_048_576;

  constructor(id: string, name: string, profile: string, stream: ClientChannel, ttlMs: number) {
    super(id, name, profile, 'interactive', ttlMs);
    this.stream = stream;
    stream.on('close', () => {
      this._status = 'closed';
    });
  }

  async run(command: string, timeoutMs = 60_000, abortSignal?: AbortSignal): Promise<CommandResult> {
    if (this._status !== 'active') {
      throw new Error(`Session ${this.name} is not active (status: ${this._status})`);
    }

    const span = tracer.startSpan('ssh.session.run');
    span.setAttribute('session.id', this.id);
    span.setAttribute('session.name', this.name);

    const marker = this.generateMarker();
    // Split literals: the shell assembles these at runtime, so the *echoed*
    // command line never contains the assembled marker — only the command's
    // actual output does. That is what makes the parse below deterministic
    // instead of a guess about which echoed line to skip.
    const beginParts = ['SSHMCP_BEG', `_${marker}`];
    const endParts = ['SSHMCP_END', `_${marker}`];
    const beginMarker = beginParts.join('');
    const endMarker = endParts.join('');
    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      let buffer = '';
      let resolved = false;
      // Assigned below; declared here so every settle path can detach it.
      let detachAbort = () => { /* no abort signal */ };

      const timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          this.stream.removeListener('data', dataHandler);
          detachAbort();
          try { this.stream.write('\x03'); } catch { /* */ }
          setTimeout(() => { try { this.stream.signal('TERM'); } catch { /* */ } }, 500);
          span.end();
          reject(new Error(`Command timed out after ${timeoutMs}ms in session ${this.name}`));
        }
      }, timeoutMs);

      // The trailer carries the exit code and the shell's real CWD, so neither
      // has to be inferred (cwd used to be guessed from the command text, which
      // was wrong for relative paths, `cd -`, symlinks and `cd` with no arg).
      const endRegex = new RegExp(`${endMarker}__(\\d+)__([^\\r\\n]*)`);

      const dataHandler = (data: Buffer) => {
        const prevLength = buffer.length;
        buffer += data.toString();
        if (buffer.length > InteractiveSession.MAX_OUTPUT * 2) {
          buffer = buffer.slice(-InteractiveSession.MAX_OUTPUT * 2);
        }

        // The marker can only appear at the tail, so search the newly-arrived
        // bytes plus an overlap rather than rescanning the whole buffer on
        // every chunk — that was O(total x buffer) for a chatty command. The
        // cheap indexOf also gates the ANSI strip, which is the expensive part.
        const searchFrom = Math.max(0, Math.min(prevLength, buffer.length) - endMarker.length - 32);
        if (resolved || buffer.indexOf(endMarker, searchFrom) === -1) return;

        const cleaned = stripAnsi(buffer);
        const match = cleaned.match(endRegex);
        if (match && !resolved) {
          resolved = true;
          clearTimeout(timeoutId);
          this.stream.removeListener('data', dataHandler);
          detachAbort();

          const exitCode = parseInt(match[1]);
          const reportedCwd = match[2].trim();

          // Output is exactly what lies between the two printed markers.
          // Anything before the begin marker — the echoed command, leftover
          // shell init, a prompt that PS1="" had not suppressed yet — is
          // discarded by construction rather than by counting lines.
          const beginIdx = cleaned.indexOf(beginMarker);
          const afterBegin = beginIdx >= 0
            ? cleaned.slice(cleaned.indexOf('\n', beginIdx) + 1)
            : cleaned;
          const endIdx = afterBegin.indexOf(endMarker);
          const between = endIdx >= 0 ? afterBegin.slice(0, endIdx) : afterBegin;

          const output = between.replace(/^\n+/, '').replace(/\n+$/, '');

          if (reportedCwd) this.cwd = reportedCwd;

          this.touch();

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

      if (abortSignal) {
        if (abortSignal.aborted) {
          resolved = true;
          clearTimeout(timeoutId);
          span.end();
          reject(new Error('Command aborted before execution'));
          return;
        }
        const onAbort = () => {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeoutId);
            this.stream.removeListener('data', dataHandler);
            try { this.stream.write('\x03'); } catch { /* */ }
            setTimeout(() => { try { this.stream.signal('TERM'); } catch { /* */ } }, 1000);
            span.end();
            reject(new Error('Command aborted'));
          }
        };
        abortSignal.addEventListener('abort', onAbort, { once: true });
        // Without this the listener outlived the run, and its closure retained
        // the run's buffer (up to 2MB) for the lifetime of the signal.
        detachAbort = () => abortSignal.removeEventListener('abort', onAbort);
      }

      this.stream.on('data', dataHandler);
      // One line, so the PTY produces exactly one echo and it necessarily
      // precedes the begin marker's output. Written as three lines, the shell
      // echoed each just before running it, interleaving the echoes of the
      // command and the trailer *after* the begin marker — right in the middle
      // of what we treat as output.
      //
      // The markers are printed from split literals, so the echo of this line
      // never contains an assembled marker; only the shell's own output does.
      this.stream.write(
        `printf '%s%s\\n' '${beginParts[0]}' '${beginParts[1]}'; ` +
        `${command}; ` +
        `printf '%s%s__%s__%s\\n' '${endParts[0]}' '${endParts[1]}' "$?" "$PWD"\n`,
      );
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

  /** Record the shell's starting directory when the profile sets a workdir. */
  setCwd(dir: string): void {
    this.cwd = dir;
  }
}

export class BackgroundSession extends Session {
  private stream: ClientChannel;
  private ringBuffer: string[] = [];
  private ringBytes = 0;
  private ringMax = 10_000;
  /** Tail of the last chunk when it did not end on a line boundary. */
  private partialLine = '';
  private exitCode: number | null = null;
  private static RING_CHAR_LIMIT = 100_000;

  constructor(id: string, name: string, profile: string, stream: ClientChannel, ttlMs: number, maxLifetimeMs?: number) {
    super(id, name, profile, 'background', ttlMs, maxLifetimeMs);
    this.stream = stream;
    stream.on('data', (data: Buffer) => {
      // Splitting each chunk independently corrupted the output twice over: a
      // line spanning two chunks became two entries (readOutput joins with
      // '\n', inventing a break that was never in the stream), and a chunk
      // ending on '\n' produced a trailing '' entry, so a blank line was
      // inserted between every chunk. Carry the incomplete tail instead.
      const text = this.partialLine + data.toString();
      const lines = text.split('\n');
      this.partialLine = lines.pop() ?? '';
      for (const line of lines) {
        this.ringBuffer.push(line);
        this.ringBytes += line.length + 1;
      }
      this.trimRingBuffer();
      this.touch();
    });
    stream.on('close', (code: number) => {
      // Flush a final line that never got its newline.
      if (this.partialLine) {
        this.ringBuffer.push(this.partialLine);
        this.ringBytes += this.partialLine.length + 1;
        this.partialLine = '';
        this.trimRingBuffer();
      }
      this.exitCode = code;
      this._status = this.isExpired() ? 'expired' : 'closed';
    });
  }

  /**
   * Evict from the head in one splice. Looping `shift()` moved every remaining
   * element per evicted line, so a chatty process paid O(lines x buffer) on the
   * shared event loop once the buffer was full.
   */
  private trimRingBuffer(): void {
    let dropCount = 0;
    let freed = 0;

    while (
      this.ringBytes - freed > BackgroundSession.RING_CHAR_LIMIT &&
      dropCount < this.ringBuffer.length
    ) {
      freed += this.ringBuffer[dropCount].length + 1;
      dropCount++;
    }

    const remaining = this.ringBuffer.length - dropCount;
    if (remaining > this.ringMax) {
      const extra = remaining - this.ringMax;
      for (let i = 0; i < extra; i++) {
        freed += this.ringBuffer[dropCount + i].length + 1;
      }
      dropCount += extra;
    }

    if (dropCount > 0) {
      this.ringBuffer.splice(0, dropCount);
      this.ringBytes -= freed;
    }
  }

  readOutput(lines = 50): string {
    // Include the in-flight partial line so output that has not yet ended with
    // a newline is still visible to a caller polling the session.
    const all = this.partialLine ? [...this.ringBuffer, this.partialLine] : this.ringBuffer;
    return all.slice(-lines).join('\n');
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
