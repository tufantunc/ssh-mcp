import type { ClientChannel } from 'ssh2';
import type { Profile, SessionOpts } from '../types.js';
import { InteractiveSession, BackgroundSession, stripAnsi, type Session } from './session.js';
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
    await this.primeShell(stream, session);
    return session;
  }

  /**
   * Quiet the shell down before the caller runs anything: no prompt, no
   * history, no bracketed paste — all of which would otherwise land in command
   * output. Resolves on the first prompt, with a ceiling so an exotic shell
   * that never matches cannot hang the open.
   */
  private primeShell(stream: ClientChannel, session: InteractiveSession): Promise<void> {
    const { workdir } = this.deps.profile();

    return new Promise((resolve) => {
      let settled = false;
      let initBuffer = '';

      const finish = (delayMs: number) => {
        if (settled) return;
        settled = true;
        stream.removeListener('data', initHandler);
        clearTimeout(ceiling);
        setTimeout(resolve, delayMs);
      };

      const initHandler = (data: Buffer) => {
        initBuffer += data.toString();
        // Strip ANSI before looking for the prompt. busybox ash follows its
        // prompt with a cursor-position query (ESC[6n), so the raw buffer ends
        // in an escape sequence rather than "$ " — the match failed and every
        // session open on such a shell waited out the 3s ceiling instead.
        const visible = stripAnsi(initBuffer);
        if (!/[#$>]\s*$/.test(visible) && initBuffer.length <= 1000) return;

        stream.write('PS1=""\n');
        stream.write('set +o history 2>/dev/null\n');
        stream.write('bind "set enable-bracketed-paste off" 2>/dev/null\n');
        if (workdir) {
          stream.write(`cd ${shellSingleQuote(workdir)}\n`);
          session.setCwd(workdir);
        }
        finish(200);
      };

      const ceiling = setTimeout(() => finish(0), 3000);
      stream.on('data', initHandler);
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

  async close(name: string): Promise<void> {
    const session = this.sessions.get(name);
    if (!session) throw new Error(`Session "${name}" not found on ${this.deps.profile().name}`);
    await session.close();
    this.sessions.delete(name);
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
