import type { ClientChannel } from 'ssh2';
import type { Profile, SessionOpts } from '../types.js';
import { InteractiveSession, BackgroundSession, stripAnsi, type Session , type CloseOutcome } from './session.js';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { openWithRetry } from './channel-retry.js';
import { randomUUID } from 'crypto';

/**
 * How the manager reaches the SSH connection.
 *
 * Deliberately narrow: the manager opens channels and reports channel
 * open/close, but knows nothing about connecting, reconnecting or exec. That
 * keeps session bookkeeping — which grows with every session feature — out of
 * the connection lifecycle it kept getting tangled with.
 */
export interface SessionManagerDeps {
  /**
   * Read on every call rather than snapshotted at construction: limits,
   * timeouts and workdir all come from the profile, and the profile object can
   * be replaced (a config reload, or a test adjusting a limit).
   */
  profile(): Profile;
  openShell(): Promise<ClientChannel>;
  openExec(command: string): Promise<ClientChannel>;
  onChannelOpened(): void;
  onChannelClosed(): void;
}

/** Owns the named sessions of a single SSH connection. */
export class SessionManager {
  private sessions = new Map<string, Session>();

  constructor(private deps: SessionManagerDeps) {}

  get size(): number {
    return this.sessions.size;
  }

  async open(opts: SessionOpts): Promise<Session> {
    const profile = this.deps.profile();

    if (this.sessions.size >= profile.sessionMaxPerConnection) {
      throw new Error(
        `Session limit reached for ${profile.name} (max: ${profile.sessionMaxPerConnection})`,
      );
    }
    if (this.sessions.has(opts.name)) {
      throw new Error(`Session "${opts.name}" already exists on ${profile.name}`);
    }

    const ttlMs = opts.ttlMs ?? profile.sessionIdleTimeoutMs;
    const id = randomUUID();

    if (opts.type === 'interactive') {
      return this.openInteractive(id, opts.name, ttlMs);
    }
    if (!opts.command) throw new Error('Background sessions require a command');
    return this.openBackground(id, opts.name, opts.command, ttlMs);
  }

  /**
   * Register a session and tie its lifetime to its channel.
   *
   * The eviction is guarded: close() only ends the stream, so a channel's
   * 'close' can arrive long after the same name was reused, and an unguarded
   * delete would evict the *new* session — leaving its channel open but
   * unreachable through get/list/close/reap.
   */
  private register(name: string, session: Session, stream: ClientChannel): void {
    this.sessions.set(name, session);
    this.deps.onChannelOpened();

    stream.on('close', () => {
      this.deps.onChannelClosed();
      if (this.sessions.get(name) === session) this.sessions.delete(name);
    });
  }

  private async openInteractive(id: string, name: string, ttlMs: number): Promise<Session> {
    let stream: ClientChannel;
    try {
      stream = await openWithRetry(() => this.deps.openShell());
    } catch (err) {
      throw new Error(`Failed to open interactive session: ${err instanceof Error ? err.message : String(err)}`);
    }

    const session = new InteractiveSession(id, name, this.deps.profile().name, stream, ttlMs);
    this.register(name, session, stream);
    try {
      await this.primeShell(stream, session);
    } catch (err) {
      await session.close().catch(() => { /* channel already going away */ });
      this.sessions.delete(name);
      throw err;
    }
    return session;
  }


  /**
   * Quiet the shell down and confirm it can run the session protocol — in one
   * round trip.
   *
   * Priming suppresses the prompt, history and bracketed paste, all of which
   * would otherwise land in command output. The readiness marker at the end
   * doubles as the handshake: it comes back only from a shell that can run
   * `printf`, which is the same capability every later command depends on.
   *
   * This replaced two weaker mechanisms. Waiting for a prompt with /[#$>]\s*$/
   * was a guess that failed on busybox ash (its prompt is followed by a
   * cursor-position query) and would silently "succeed" on cmd.exe, which
   * presents a `>` prompt and then cannot run a single command — every call
   * afterwards sat until the 60s command timeout with nothing useful to say.
   */
  private primeShell(stream: ClientChannel, session: InteractiveSession): Promise<void> {
    const { workdir, name: profileName } = this.deps.profile();
    // Split literals: the echoed input never contains the assembled marker, so
    // only the shell's own output can satisfy the match.
    const parts = ['SSHMCP_RDY', `_${randomUUID()}`];
    const marker = parts.join('');

    return new Promise((resolve, reject) => {
      let buffer = '';
      let settled = false;

      const settle = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        stream.removeListener('data', onData);
        err ? reject(err) : resolve();
      };

      const onData = (data: Buffer) => {
        buffer += data.toString();
        if (stripAnsi(buffer).includes(marker)) settle();
      };

      const timer = setTimeout(() => settle(new Error(
        `Interactive sessions are not supported on ${profileName}: its shell did not complete the ` +
        'session handshake. The protocol requires a POSIX shell (sh/bash/ash/zsh); cmd.exe and ' +
        'PowerShell do not provide it. Use read-command / run-command instead, which work on any shell.',
      )), 5000);

      stream.on('data', onData);
      stream.write('PS1=""\n');
      stream.write('set +o history 2>/dev/null\n');
      stream.write('bind "set enable-bracketed-paste off" 2>/dev/null\n');
      if (workdir) {
        stream.write(`cd ${shellSingleQuote(workdir)}\n`);
        session.setCwd(workdir);
      }
      stream.write(`printf '%s%s\\n' '${parts[0]}' '${parts[1]}'\n`);
    });
  }

  private async openBackground(id: string, name: string, command: string, ttlMs: number): Promise<Session> {
    let stream: ClientChannel;
    try {
      stream = await openWithRetry(() => this.deps.openExec(command));
    } catch (err) {
      throw new Error(`Failed to open background session: ${err instanceof Error ? err.message : String(err)}`);
    }

    const profile = this.deps.profile();
    const session = new BackgroundSession(
      id, name, profile.name, stream, ttlMs, profile.sessionBackgroundMaxMs,
    );
    this.register(name, session, stream);
    return session;
  }

  get(name: string): Session | undefined {
    return this.sessions.get(name);
  }

  list(): Session[] {
    return Array.from(this.sessions.values());
  }

  async close(name: string): Promise<CloseOutcome> {
    const session = this.sessions.get(name);
    if (!session) throw new Error(`Session "${name}" not found on ${this.deps.profile().name}`);
    const outcome = await session.close();
    this.sessions.delete(name);
    return outcome;
  }

  async closeAll(): Promise<void> {
    for (const name of [...this.sessions.keys()]) {
      await this.close(name).catch(() => {});
    }
  }

  reapExpired(): void {
    for (const [name, session] of this.sessions) {
      if (session.isExpired()) {
        session.close().catch(() => {});
        this.sessions.delete(name);
      }
    }
  }

  markAllDisconnected(): void {
    for (const session of this.sessions.values()) {
      session.markDisconnected();
    }
  }
}
