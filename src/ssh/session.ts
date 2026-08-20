import type { ClientChannel } from 'ssh2';
import { randomBytes } from 'crypto';
import type { CommandResult, SessionInfo, SessionStatus } from '../types.js';
import { tracer } from '../observability/tracer.js';
import { terminateChannel, waitForChannelClose } from './channel-signal.js';

const ANSI_REGEX = /\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r/g;

export function stripAnsi(text: string): string {
  return text.replace(ANSI_REGEX, '');
}

/**
 * Trim leading and trailing newlines by index rather than with /^\n+/ and
 * /\n+$/.
 *
 * The trailing pattern is unanchored at the start, so on output that is mostly
 * newlines but does not end in one the engine retries `\n+` from every offset:
 * quadratic in the length of the output. That output is whatever the remote
 * command printed and the session buffer holds up to 2 MB of it, which measured
 * at roughly 25 minutes of blocked event loop — and the loop is shared by every
 * session and connection this server has open.
 */
/**
 * A per-command marker separating the command's own output from the trailer
 * carrying `$?` and `$PWD`.
 *
 * Guessing one is enough to forge an exit code or a working directory — a
 * failed command reported as successful, in a server whose whole claim is an
 * auditable record of what ran. Every marker is written to the remote host in
 * the clear, so anything watching that session collects a stream of them, and
 * Math.random() is reconstructible from such a stream.
 *
 * base64url keeps the value safe both inside the single-quoted printf that
 * emits it and inside the RegExp built from it: no quotes, no metacharacters.
 */
export function generateSessionMarker(): string {
  return randomBytes(12).toString('base64url');
}

export function trimNewlines(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && text.charCodeAt(start) === 10) start++;
  while (end > start && text.charCodeAt(end - 1) === 10) end--;
  return start === 0 && end === text.length ? text : text.slice(start, end);
}

/**
 * What closing a session achieved.
 *
 * Three states because there are three genuinely different answers, and the first version
 * of this had only two — it computed the third and threw it away, so `close-session`
 * reported `'closed'` for a command that had survived INT, TERM *and* KILL. That is the
 * same false claim the exec path stopped making.
 *
 * - `'closed'` — the channel closed. For a background session that means the command is
 *   gone; for an interactive one, that its shell was ended.
 * - `'stop-unconfirmed'` — the ladder was dispatched and the channel was still open when
 *   the budget ran out. The strongest available evidence that the stop did not take: a
 *   process in uninterruptible sleep, or a server that refuses signal requests at all
 *   (sshd under a forced command or a subsystem, and Dropbear).
 * - `'unsignalled'` — nothing could be dispatched, so nothing was asked of the host.
 */
export type CloseOutcome = 'closed' | 'stop-unconfirmed' | 'unsignalled';

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
  abstract close(): Promise<CloseOutcome>;

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

          const output = trimNewlines(between);

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
    return generateSessionMarker();
  }

  async close(): Promise<CloseOutcome> {
    try {
      this.stream.end();
    } catch { /* ignore */ }
    this._status = 'closed';
    // Nothing remote is signalled here: an interactive session's stop is `^C` written into
    // its live pty during a command, and closing the session just ends the shell.
    return 'closed';
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

  async close(): Promise<CloseOutcome> {
    // Signalled, not just closed. A background session runs on an exec channel, and
    // closing such a channel was measured not to stop the command (#146) — so
    // `close-session` reported `status: 'closed'` while `tail -f` kept running on the
    // host, which is the same false claim the exec path stopped making.
    const dispatched = terminateChannel(this.stream);
    // Our side is closed either way — the session is being torn down and the caller is not
    // getting it back. What varies is whether the *host* stopped, which the outcome carries.
    this._status = 'closed';
    if (!dispatched) return 'unsignalled';

    // Awaited, because the ladder's later rungs are timers and whatever happens next may
    // tear the transport down: `SSHConnection.close()` ends the client immediately after
    // `closeAll()` returns, and shutdown calls `process.exit`. Returning early meant a
    // command that ignored INT received nothing further and survived — the KILL rung
    // exists precisely for that command. Bounded by the ladder's own length, so a command
    // that dies to INT costs one round trip rather than three seconds.
    //
    // Skipped entirely when nothing was dispatched: no rung can be delivered through a
    // transport that refused the first one, including the `channel.close()` rung, so
    // `'close'` would never arrive and the wait was measured burning its full 3.5s for
    // nothing.
    //
    // The old `stream.close()` released the channel synchronously; this releases it when
    // the ladder finishes, which is why the wait is here rather than left to the caller.
    return (await waitForChannelClose(this.stream)) ? 'closed' : 'stop-unconfirmed';
  }
}
