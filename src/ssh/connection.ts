import { Client, type ClientChannel, type ConnectConfig, type ExecOptions } from 'ssh2';
import type { ConnectionInfo, Profile, ResolvedCredentials, ExecOpts, CommandResult, SessionOpts } from '../types.js';
import { FROZEN_ALGORITHMS } from './algorithms.js';
import { verifyHostKey, fingerprintPublicKey, type HostKeyMode } from './host-key.js';
import type { Session, CloseOutcome } from './session.js';
import { SessionManager } from './session-manager.js';
import type { Span } from '@opentelemetry/api';
import { tracer } from '../observability/tracer.js';
import { redactText } from '../guard/redactor.js';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { openWithRetry } from './channel-retry.js';
import { terminateChannel, COULD_NOT_SIGNAL } from './channel-signal.js';

/**
 * Stop the command behind `channel`, record why on the span, and return the sentence the
 * rejection should carry.
 *
 * Module scope rather than a closure inside `exec`: it captures nothing but the span, and
 * at module scope it is directly testable with a stub span and a fake channel. It exists
 * at all because the three settle paths used to inline this, and two of them computed the
 * "unstopped" value for the message and then dropped it before the span — so
 * `ssh.unstopped` was structurally incapable of being true for a cancelled command, which
 * is the most common way an MCP client stops one.
 */
export function stopAndDescribe(
  span: Span,
  reason: 'ssh.timedOut' | 'ssh.aborted',
  channel: ClientChannel | null,
): string {
  span.setAttribute(reason, true);
  // A null channel means the exec callback has not arrived yet. It does NOT mean nothing is
  // running — ssh2 invokes that callback on CHANNEL_SUCCESS, which OpenSSH sends after
  // forking the command — but there is nothing to warn about either: `onExecChannel` stops
  // such a late channel the moment it arrives. Warning here would put "may still be
  // running" on every timeout that races a slow channel open, and a warning that fires when
  // nothing is wrong stops being read.
  //
  // Recorded as its own attribute rather than as `ssh.unstopped: false`, which would assert
  // a clean stop this path cannot yet know about. The late-arrival handler emits the real
  // answer on its own span.
  if (channel === null) {
    span.setAttribute('ssh.stopDeferred', true);
    return '';
  }
  const dispatched = terminateChannel(channel);
  // Set on every settle path, always, so "stopped cleanly" and "ran an older build" are not
  // the same absent-attribute query.
  span.setAttribute('ssh.unstopped', !dispatched);
  return dispatched ? '' : COULD_NOT_SIGNAL;
}

export class SSHConnection {
  readonly profile: Profile;
  private client: Client | null = null;
  private credentials: ResolvedCredentials;
  private readonly sessions: SessionManager;
  private activeChannels = 0;
  private connecting: Promise<void> | null = null;
  private connected = false;
  private connectedAt: Date | null = null;
  private lastActivity = new Date();
  private knownHostsStore: Map<string, string>;
  private hostKeyMode: HostKeyMode;
  private bastionSock: ClientChannel | null;

  constructor(
    profile: Profile,
    credentials: ResolvedCredentials,
    knownHostsStore: Map<string, string>,
    hostKeyMode: HostKeyMode = 'tofu',
    bastionSock?: ClientChannel,
  ) {
    this.profile = profile;
    this.credentials = credentials;
    this.knownHostsStore = knownHostsStore;
    this.hostKeyMode = hostKeyMode;
    this.bastionSock = bastionSock ?? null;

    this.sessions = new SessionManager({
      // Live read: the profile object can be replaced after construction.
      profile: () => this.profile,
      // ensureConnected inside the callback, not just before the retry: these
      // run under openWithRetry, and Dropbear drops the whole connection under
      // channel churn rather than merely refusing the channel. openSession does
      // check the link first, but the link can die between that check and the
      // channel opening — and then every retry reached getClient() on a dead
      // client and threw the same "SSH connection not established", so the retry
      // re-ran a corpse three times. SftpClient already did it this way.
      openShell: async () => {
        await this.ensureConnected();
        return new Promise<ClientChannel>((resolve, reject) => {
          this.getClient().shell(
            { term: 'xterm-256color', cols: 200, rows: 50 },
            (err, stream) => (err ? reject(err) : resolve(stream)),
          );
        });
      },
      openExec: async (command) => {
        await this.ensureConnected();
        return new Promise<ClientChannel>((resolve, reject) => {
          this.getClient().exec(
            this.applyWorkdir(command),
            (err, stream) => (err ? reject(err) : resolve(stream)),
          );
        });
      },
      onChannelOpened: () => { this.activeChannels++; },
      onChannelClosed: () => { this.activeChannels--; },
    });
  }

  async ensureConnected(): Promise<void> {
    if (this.isConnected()) return;
    if (this.connecting) return this.connecting;

    this.connecting = this.connect();
    return this.connecting;
  }

  private async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      // Every handler below acts on `client`, not `this.client`, and only
      // mutates shared state while it is still the current client. A late event
      // from a superseded attempt must not tear down the connection that
      // replaced it.
      const client = new Client();
      this.client = client;
      const isCurrent = () => this.client === client;

      let settled = false;
      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        if (isCurrent()) this.connecting = null;
        fn();
      };

      const timeoutId = setTimeout(() => {
        settle(() => {
          try { client.end(); } catch { /* already gone */ }
          if (isCurrent()) this.client = null;
          reject(new Error('SSH connection timeout'));
        });
      }, 20000);

      client.on('ready', () => {
        settle(() => {
          this.connected = true;
          this.connectedAt = new Date();
          this.lastActivity = new Date();
          resolve();
        });
      });

      client.on('error', (err: Error) => {
        settle(() => {
          if (isCurrent()) this.client = null;
          reject(new Error(`SSH connection error: ${err.message}`));
        });
      });

      // 'end'/'close' also fire long after a successful handshake, when the
      // connection drops — that path must clear connection state but leave the
      // already-resolved promise alone.
      const onDisconnect = (reason: string) => () => {
        if (!isCurrent()) return;
        this.connected = false;
        this.sessions.markAllDisconnected();
        this.client = null;
        this.connectedAt = null;
        // Without clearing the timer here, a handshake that fails via a clean
        // TCP close left a 20s bomb armed: it would later end a *newer* client
        // mid-handshake and null its `connecting`, leaving that attempt hung.
        settle(() => reject(new Error(`SSH connection ${reason} during handshake`)));
      };

      client.on('end', onDisconnect('ended'));
      client.on('close', onDisconnect('closed'));

      const connectConfig: ConnectConfig = {
        host: this.profile.host,
        port: this.profile.port,
        username: this.profile.user,
        algorithms: FROZEN_ALGORITHMS as ConnectConfig['algorithms'],
        hostVerifier: (key: Buffer) => {
          // The pin used to be checked here, as a `return false` ahead of
          // verifyHostKey. That made it reject-only: a *matching* pin fell
          // through and was refused anyway under `strict`, whose store can never
          // be populated. Passing it in puts one function in charge of the whole
          // decision, and `return false` gave ssh2 a generic handshake failure
          // where verifyHostKey raises a message that names what decided.
          return verifyHostKey(
            this.profile.host,
            this.profile.port,
            fingerprintPublicKey(key),
            this.knownHostsStore,
            this.hostKeyMode,
            this.profile.trustedHostKey,
          );
        },
        readyTimeout: 20000,
        keepaliveInterval: 15000,
        keepaliveCountMax: 3,
      };

      if (this.credentials.agentSocket) {
        connectConfig.agent = this.credentials.agentSocket;
      }
      if (this.credentials.privateKey) {
        connectConfig.privateKey = this.credentials.certificate
          ? this.credentials.privateKey + '\n' + this.credentials.certificate
          : this.credentials.privateKey;
        if (this.credentials.passphrase) {
          connectConfig.passphrase = this.credentials.passphrase;
        }
      }
      if (this.credentials.password) {
        connectConfig.password = this.credentials.password;
      }
      if (this.bastionSock) {
        connectConfig.sock = this.bastionSock;
      }

      client.connect(connectConfig);
    });
  }

  isConnected(): boolean {
    return this.connected && this.client !== null;
  }

  getClient(): Client {
    if (!this.client) throw new Error('SSH connection not established');
    return this.client;
  }

  getSudoPassword(): string | undefined {
    return this.credentials.sudoPassword;
  }

  /**
   * Prefix a command with the profile's working directory, if configured.
   * Applied here rather than at the tool layer so the string the policy engine
   * classified is never the string that carries the `&&`.
   */
  private applyWorkdir(command: string): string {
    if (!this.profile.workdir) return command;
    return `cd ${shellSingleQuote(this.profile.workdir)} && ${command}`;
  }

  async exec(rawCommand: string, opts: ExecOpts = {}): Promise<CommandResult> {
    await this.ensureConnected();
    const command = this.applyWorkdir(rawCommand);
    const timeoutMs = opts.timeoutMs ?? this.profile.timeout;
    const startTime = Date.now();

    const span = tracer.startSpan('ssh.exec');
    span.setAttribute('ssh.host', this.profile.host);
    span.setAttribute('ssh.port', this.profile.port);
    span.setAttribute('ssh.command', redactText(command));

    return new Promise((resolve, reject) => {
      let activeStream: ClientChannel | null = null;
      let resolved = false;

      const timeoutId = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          const note = stopAndDescribe(span, 'ssh.timedOut', activeStream);
          span.end();
          reject(new Error(`Command timed out after ${timeoutMs}ms${note}`));
        }
      }, timeoutMs);

      const execOpts: ExecOptions = {};
      if (opts.tty || this.profile.tty) {
        execOpts.pty = { term: 'xterm-256color', cols: 200, rows: 50 };
      }

      // Retried: some servers (Dropbear especially) intermittently refuse a
      // channel right after a previous one was released. Only the open is
      // retried — once a stream exists, nothing here re-runs the command.
      const openExecChannel = async () => {
        // Re-established per attempt: the refusal can be a dropped connection
        // rather than a refused channel.
        await this.ensureConnected();
        const activeClient = this.getClient();
        return new Promise<ClientChannel>((res, rej) => {
          activeClient.exec(command, execOpts, (err, stream) => (err ? rej(err) : res(stream)));
        });
      };

      const onExecChannel = (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeoutId);
            span.end();
            reject(new Error(`SSH exec error: ${err.message}`));
          }
          return;
        }
        // The promise may already have settled — the timeout can fire while
        // `openWithRetry` is still in flight, and ssh2 only invokes this callback once
        // the server has replied CHANNEL_SUCCESS, which OpenSSH sends *after* forking
        // the command. Without this the command ran to completion on the host after the
        // caller had been told it timed out, holding a channel and discarding its
        // output: #146 exactly, in the one path the first fix did not cover.
        if (resolved) {
          // On its own span: the exec span was ended when the promise settled, and an
          // attribute set on an ended span is silently dropped. Without this the one
          // outcome `stopAndDescribe` deferred would be unobservable — the shape this
          // whole change exists to remove.
          const late = tracer.startSpan('ssh.exec.lateStop');
          late.setAttribute('ssh.host', this.profile.host);
          late.setAttribute('ssh.unstopped', !terminateChannel(stream));
          late.end();
          return;
        }

        activeStream = stream;
        this.activeChannels++;

        let stdout = '';
        let stderr = '';
        const maxOutput = this.profile.maxOutputBytes;
        let lastProgressSent = 0;
        const PROGRESS_INTERVAL = 500;

        if (opts.stdin) {
          try { stream.write(opts.stdin); } catch { /* */ }
        }
        try { stream.end(); } catch { /* */ }

        if (opts.abortSignal) {
          if (opts.abortSignal.aborted) {
            resolved = true;
            clearTimeout(timeoutId);
            // Decremented here rather than on 'close', because the close listener
            // below is never attached on this path. The channel now outlives the
            // count by as long as the kill ladder takes.
            this.activeChannels--;
            // client.exec() has already dispatched the command, so rejecting
            // without signalling left it running to completion on the host and
            // held a channel until it finished. Closing the channel does not stop
            // it either — only a delivered signal does (#146).
            const note = stopAndDescribe(span, 'ssh.aborted', stream);
            span.end();
            reject(new Error(`Command aborted before execution${note}`));
            return;
          }
          const onAbort = () => {
            if (!resolved) {
              resolved = true;
              clearTimeout(timeoutId);
              const note = stopAndDescribe(span, 'ssh.aborted', stream);
              span.end();
              reject(new Error(`Command aborted${note}`));
            }
          };
          opts.abortSignal.addEventListener('abort', onAbort, { once: true });
          stream.on('close', () => { opts.abortSignal!.removeEventListener('abort', onAbort); });
        }

        stream.on('data', (data: Buffer) => {
          if (stdout.length < maxOutput) stdout += data.toString();
          if (opts.onProgress && Date.now() - lastProgressSent >= PROGRESS_INTERVAL) {
            lastProgressSent = Date.now();
            let tail = stdout;
            for (let i = 0; i < 3; i++) {
              const idx = tail.lastIndexOf('\n', tail.length - 2);
              if (idx < 0) break;
              tail = tail.substring(idx + 1);
            }
            opts.onProgress(stdout.length, redactText(tail.trim(), { entropyScan: true }));
          }
        });
        stream.stderr.on('data', (data: Buffer) => {
          if (stderr.length < maxOutput) stderr += data.toString();
        });

        stream.on('close', (code: number, signal: string) => {
          this.activeChannels--;
          if (!resolved) {
            resolved = true;
            clearTimeout(timeoutId);
            this.lastActivity = new Date();
            resolve({
              stdout,
              stderr,
              exitCode: code,
              durationMs: Date.now() - startTime,
              profile: this.profile.name,
              signal: signal || undefined,
            });
            span.setAttribute('ssh.exitCode', code);
            if (signal) span.setAttribute('ssh.signal', signal);
            span.end();
          }
        });
      };

      openWithRetry(openExecChannel).then(
        (stream) => onExecChannel(undefined, stream),
        (err: Error) => onExecChannel(err, undefined as unknown as ClientChannel),
      );
    });
  }

  // ─── Sessions (delegated to SessionManager) ──────────────────────────

  async openSession(opts: SessionOpts): Promise<Session> {
    await this.ensureConnected();
    return this.sessions.open(opts);
  }

  getSession(name: string): Session | undefined {
    return this.sessions.get(name);
  }

  listSessions(): Session[] {
    return this.sessions.list();
  }

  async closeSession(name: string): Promise<CloseOutcome> {
    return this.sessions.close(name);
  }

  async reapExpiredSessions(): Promise<void> {
    return this.sessions.reapExpired();
  }

  async close(): Promise<void> {
    await this.sessions.closeAll();
    if (this.client) {
      this.client.end();
      this.client = null;
    }
    this.connecting = null;
    this.connected = false;
    this.connectedAt = null;
  }

  toInfo(): ConnectionInfo {
    return {
      profile: this.profile.name,
      host: this.profile.host,
      port: this.profile.port,
      user: this.profile.user,
      status: this.isConnected() ? 'connected' : 'closed',
      sessionCount: this.sessions.size,
      activeChannels: this.activeChannels,
      connectedAt: this.connectedAt || undefined,
      lastActivity: this.lastActivity,
    };
  }
}
