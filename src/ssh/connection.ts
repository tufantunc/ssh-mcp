import { Client, type ClientChannel, type ConnectConfig } from 'ssh2';
import type { ConnectionInfo, Profile, ResolvedCredentials, ExecOpts, CommandResult, SessionOpts } from '../types.js';
import { FROZEN_ALGORITHMS } from './algorithms.js';
import { verifyHostKey, fingerprintPublicKey, type HostKeyMode } from './host-key.js';
import { InteractiveSession, BackgroundSession, type Session } from './session.js';
import { randomUUID } from 'crypto';
import { tracer } from '../observability/tracer.js';
import { redactText } from '../guard/redactor.js';

export class SSHConnection {
  readonly profile: Profile;
  private client: Client | null = null;
  private credentials: ResolvedCredentials;
  private sessions = new Map<string, Session>();
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
  }

  async ensureConnected(): Promise<void> {
    if (this.isConnected()) return;
    if (this.connecting) return this.connecting;

    this.connecting = this.connect();
    return this.connecting;
  }

  private async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.client = new Client();

      const timeoutId = setTimeout(() => {
        this.client?.end();
        this.client = null;
        this.connecting = null;
        reject(new Error('SSH connection timeout'));
      }, 20000);

      this.client.on('ready', () => {
        clearTimeout(timeoutId);
        this.connecting = null;
        this.connected = true;
        this.connectedAt = new Date();
        this.lastActivity = new Date();
        resolve();
      });

      this.client.on('error', (err: Error) => {
        clearTimeout(timeoutId);
        this.client = null;
        this.connecting = null;
        reject(new Error(`SSH connection error: ${err.message}`));
      });

      this.client.on('end', () => {
        this.connected = false;
        this.markSessionsDisconnected();
        this.client = null;
        this.connectedAt = null;
        if (this.connecting) {
          this.connecting = null;
          reject(new Error('SSH connection ended during handshake'));
        }
      });

      this.client.on('close', () => {
        this.connected = false;
        this.markSessionsDisconnected();
        this.client = null;
        this.connectedAt = null;
        if (this.connecting) {
          this.connecting = null;
          reject(new Error('SSH connection closed during handshake'));
        }
      });

      const connectConfig: ConnectConfig = {
        host: this.profile.host,
        port: this.profile.port,
        username: this.profile.user,
        algorithms: FROZEN_ALGORITHMS as ConnectConfig['algorithms'],
        hostVerifier: (key: Buffer) => {
          const fp = fingerprintPublicKey(key);
          if (this.profile.trustedHostKey && fp !== this.profile.trustedHostKey) {
            return false;
          }
          return verifyHostKey(
            this.profile.host,
            this.profile.port,
            fp,
            this.knownHostsStore,
            this.hostKeyMode,
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

      this.client.connect(connectConfig);
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

  async exec(command: string, opts: ExecOpts = {}): Promise<CommandResult> {
    await this.ensureConnected();
    const client = this.getClient();
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
          if (activeStream) {
            try { activeStream.signal('INT'); } catch { /* */ }
            setTimeout(() => {
              try { activeStream?.signal('TERM'); } catch { /* */ }
              setTimeout(() => { try { activeStream?.close(); } catch { /* */ } }, 1000);
            }, 1000);
          }
          reject(new Error(`Command timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);

      const execOpts: any = {};
      if (opts.tty || this.profile.tty) {
        execOpts.pty = { term: 'xterm-256color', cols: 200, rows: 50 };
      }

      client.exec(command, execOpts, (err, stream) => {
        if (err) {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeoutId);
            reject(new Error(`SSH exec error: ${err.message}`));
          }
          return;
        }
        activeStream = stream;
        this.activeChannels++;

        let stdout = '';
        let stderr = '';
        const maxOutput = 1_048_576; // 1MB cap
        let lastProgressSent = 0;
        const PROGRESS_INTERVAL = 500;

        if (opts.stdin) {
          try { stream.write(opts.stdin); } catch { /* */ }
        }
        try { stream.end(); } catch { /* */ }

        if (opts.abortSignal) {
          opts.abortSignal.addEventListener('abort', () => {
            if (!resolved) {
              try { stream.signal('INT'); } catch { /* */ }
              setTimeout(() => {
                try { stream.signal('TERM'); } catch { /* */ }
                setTimeout(() => { try { stream.close(); } catch { /* */ } }, 1000);
              }, 1000);
            }
          }, { once: true });
        }

        stream.on('data', (data: Buffer) => {
          if (stdout.length < maxOutput) stdout += data.toString();
          if (opts.onProgress && Date.now() - lastProgressSent >= PROGRESS_INTERVAL) {
            lastProgressSent = Date.now();
            const tail = stdout.split('\n').filter(Boolean).slice(-3).join('\n');
            opts.onProgress(stdout.length, tail);
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
      });
    });
  }

  async openSession(opts: SessionOpts): Promise<Session> {
    await this.ensureConnected();

    if (this.sessions.size >= this.profile.sessionMaxPerConnection) {
      throw new Error(
        `Session limit reached for ${this.profile.name} (max: ${this.profile.sessionMaxPerConnection})`,
      );
    }

    if (this.sessions.has(opts.name)) {
      throw new Error(`Session "${opts.name}" already exists on ${this.profile.name}`);
    }

    const ttl = opts.ttlMs ?? this.profile.sessionIdleTimeoutMs;
    const id = randomUUID();

    if (opts.type === 'interactive') {
      return this.openInteractiveSession(id, opts.name, ttl);
    } else {
      if (!opts.command) throw new Error('Background sessions require a command');
      return this.openBackgroundSession(id, opts.name, opts.command, ttl);
    }
  }

  private openInteractiveSession(id: string, name: string, ttlMs: number): Promise<Session> {
    const client = this.getClient();

    return new Promise((resolve, reject) => {
      client.shell({ term: 'xterm-256color', cols: 200, rows: 50 }, (err, stream) => {
        if (err) {
          reject(new Error(`Failed to open interactive session: ${err.message}`));
          return;
        }
        const session = new InteractiveSession(id, name, this.profile.name, stream, ttlMs);
        this.sessions.set(name, session);
        this.activeChannels++;

        stream.on('close', () => {
          this.activeChannels--;
          this.sessions.delete(name);
        });

        let initBuffer = '';
        const initHandler = (data: Buffer) => {
          initBuffer += data.toString();
          if (/[#$>]\s*$/.test(initBuffer) || initBuffer.length > 1000) {
            stream.removeListener('data', initHandler);
            stream.write('PS1=""\n');
            stream.write('set +o history 2>/dev/null\n');
            stream.write('bind "set enable-bracketed-paste off" 2>/dev/null\n');
            setTimeout(() => resolve(session), 200);
          }
        };
        stream.on('data', initHandler);

        setTimeout(() => {
          stream.removeListener('data', initHandler);
          resolve(session);
        }, 3000);
      });
    });
  }

  private openBackgroundSession(id: string, name: string, command: string, ttlMs: number): Promise<Session> {
    const client = this.getClient();

    return new Promise((resolve, reject) => {
      client.exec(command, (err, stream) => {
        if (err) {
          reject(new Error(`Failed to open background session: ${err.message}`));
          return;
        }
        const session = new BackgroundSession(id, name, this.profile.name, stream, ttlMs);
        this.sessions.set(name, session);
        this.activeChannels++;

        stream.on('close', () => {
          this.activeChannels--;
          this.sessions.delete(name);
        });

        resolve(session);
      });
    });
  }

  getSession(name: string): Session | undefined {
    return this.sessions.get(name);
  }

  listSessions(): Session[] {
    return Array.from(this.sessions.values());
  }

  async closeSession(name: string): Promise<void> {
    const session = this.sessions.get(name);
    if (!session) throw new Error(`Session "${name}" not found on ${this.profile.name}`);
    await session.close();
    this.sessions.delete(name);
  }

  reapExpiredSessions(): void {
    for (const [name, session] of this.sessions) {
      if (session.isExpired()) {
        session.close().catch(() => {});
        this.sessions.delete(name);
      }
    }
  }

  private markSessionsDisconnected(): void {
    for (const session of this.sessions.values()) {
      session.markDisconnected();
    }
  }

  async close(): Promise<void> {
    for (const [name] of this.sessions) {
      await this.closeSession(name).catch(() => {});
    }
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
