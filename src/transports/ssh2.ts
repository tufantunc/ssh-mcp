import { Client, ClientChannel } from 'ssh2';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import {
  ISshTransport,
  ExecOptions,
  ExecElevatedOptions,
  ExecResult,
  TransportConfig,
} from './types.js';
import { escapeCommandForShell } from '../utils/shell.js';

/**
 * Connection manager extracted verbatim from upstream src/index.ts. Behaviour
 * is preserved byte-for-byte. It is re-exported from src/index.ts so existing
 * tests (persistent-connection.test.ts) continue to import it.
 */
export interface SSHConfig {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  suPassword?: string;
  sudoPassword?: string;
}

export class SSHConnectionManager {
  private conn: Client | null = null;
  private sshConfig: SSHConfig;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;
  private suShell: any = null;
  private suPromise: Promise<void> | null = null;
  private isElevated = false;

  constructor(config: SSHConfig) {
    this.sshConfig = config;
  }

  async connect(): Promise<void> {
    if (this.conn && this.isConnected()) {
      return;
    }
    if (this.isConnecting && this.connectionPromise) {
      return this.connectionPromise;
    }

    this.isConnecting = true;
    this.connectionPromise = new Promise((resolve, reject) => {
      this.conn = new Client();

      const timeoutId = setTimeout(() => {
        this.conn?.end();
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'SSH connection timeout'));
      }, 30000);

      this.conn.on('ready', async () => {
        clearTimeout(timeoutId);
        this.isConnecting = false;
        if (this.sshConfig.suPassword && !process.env.SSH_MCP_TEST) {
          try {
            await this.ensureElevated();
          } catch (err) {
            // Do not reject connection; commands fall back to non-elevated.
          }
        }
        resolve();
      });

      this.conn.on('error', (err: Error) => {
        clearTimeout(timeoutId);
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      });

      this.conn.on('end', () => {
        console.error('SSH connection ended');
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
      });

      this.conn.on('close', () => {
        console.error('SSH connection closed');
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
      });

      this.conn.connect(this.sshConfig);
    });

    return this.connectionPromise;
  }

  isConnected(): boolean {
    return this.conn !== null && (this.conn as any)._sock && !(this.conn as any)._sock.destroyed;
  }

  getSudoPassword(): string | undefined {
    return this.sshConfig.sudoPassword;
  }

  getSuPassword(): string | undefined {
    return this.sshConfig.suPassword;
  }

  async setSuPassword(pwd?: string): Promise<void> {
    this.sshConfig.suPassword = pwd;
    if (pwd) {
      try {
        await this.ensureElevated();
      } catch (err) {
        console.error('setSuPassword: failed to elevate to su shell:', err);
      }
    } else {
      if (this.suShell) {
        try { this.suShell.end(); } catch (e) { /* ignore */ }
        this.suShell = null;
        this.isElevated = false;
      }
    }
  }

  async ensureElevated(): Promise<void> {
    if (this.isElevated && this.suShell) return;
    if (!this.sshConfig.suPassword) return;
    if (this.suPromise) return this.suPromise;

    this.suPromise = new Promise((resolve, reject) => {
      const conn = this.getConnection();

      const timeoutId = setTimeout(() => {
        this.suPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'su elevation timed out'));
      }, 10000);

      conn.shell({ term: 'xterm', cols: 80, rows: 24 }, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          clearTimeout(timeoutId);
          this.suPromise = null;
          reject(new McpError(ErrorCode.InternalError, `Failed to start interactive shell for su: ${err.message}`));
          return;
        }

        let buffer = '';
        let passwordSent = false;
        const cleanup = () => {
          try { stream.removeAllListeners('data'); } catch (e) { /* ignore */ }
        };

        const onData = (data: Buffer) => {
          const text = data.toString();
          buffer += text;

          if (!passwordSent && /password[: ]/i.test(buffer)) {
            passwordSent = true;
            stream.write(this.sshConfig.suPassword + '\n');
          }

          if (passwordSent) {
            if (/#/.test(buffer)) {
              clearTimeout(timeoutId);
              cleanup();
              this.suShell = stream;
              this.isElevated = true;
              this.suPromise = null;
              resolve();
              return;
            }
          }

          if (/authentication failure|incorrect password|su: .*failed|su: failure/i.test(buffer)) {
            clearTimeout(timeoutId);
            cleanup();
            this.suPromise = null;
            reject(new McpError(ErrorCode.InternalError, `su authentication failed: ${buffer}`));
            return;
          }
        };

        stream.on('data', onData);
        stream.on('close', () => {
          clearTimeout(timeoutId);
          if (!this.isElevated) {
            this.suPromise = null;
            reject(new McpError(ErrorCode.InternalError, 'su shell closed before elevation completed'));
          }
        });

        stream.write('su -\n');
      });
    });

    return this.suPromise;
  }

  async ensureConnected(): Promise<void> {
    if (!this.isConnected()) {
      await this.connect();
    }
  }

  getConnection(): Client {
    if (!this.conn) {
      throw new McpError(ErrorCode.InternalError, 'SSH connection not established');
    }
    return this.conn;
  }

  /** Internal accessor used by execSshCommandWithConnection and Ssh2Transport. */
  getSuShell(): any {
    return this.suShell;
  }

  /** Internal mutator used by tool handlers that update config after construction. */
  updateSudoPassword(pwd?: string): void {
    this.sshConfig.sudoPassword = pwd;
  }

  close(): void {
    if (this.conn) {
      if (this.suShell) {
        try { this.suShell.end(); } catch (e) { /* ignore */ }
        this.suShell = null;
        this.isElevated = false;
      }
      this.conn.end();
      this.conn = null;
    }
  }
}

/**
 * Ssh2Transport — ISshTransport adapter around SSHConnectionManager.
 *
 * Behaviour: preserves the upstream implementation exactly. If the underlying
 * manager has an active `suShell` (created by ensureElevated), exec()
 * routes through it. Otherwise it uses `conn.exec()`.
 */
export class Ssh2Transport implements ISshTransport {
  readonly name = 'ssh2' as const;
  private manager: SSHConnectionManager;

  constructor(private cfg: TransportConfig) {
    const sshCfg: SSHConfig = {
      host: cfg.host,
      port: cfg.port,
      username: cfg.username,
      password: cfg.password,
      privateKey: cfg.privateKey,
      suPassword: cfg.suPassword,
      sudoPassword: cfg.sudoPassword,
    };
    this.manager = new SSHConnectionManager(sshCfg);
  }

  /** Exposed for legacy tests and tool handlers that need direct manager access. */
  getManager(): SSHConnectionManager {
    return this.manager;
  }

  async init(): Promise<void> {
    await this.manager.connect();
  }

  async exec(command: string, opts: ExecOptions): Promise<ExecResult> {
    await this.manager.ensureConnected();

    // Mirror upstream behaviour: if suPassword was configured, ensure elevation
    // before executing. Idempotent; no-op if already elevated.
    if (this.manager.getSuPassword()) {
      try {
        await Promise.race([
          this.manager.ensureElevated(),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Elevation timeout')), 5000)),
        ]);
      } catch (err) {
        // Fall back to non-elevated execution on elevation failure.
      }
    }

    return this.runOnConnection(command, opts);
  }

  async execElevated(command: string, opts: ExecElevatedOptions): Promise<ExecResult> {
    if (opts.mode === 'sudo') {
      const pwd = opts.password ?? this.manager.getSudoPassword();
      const wrapped = buildSudoWrapper(command, pwd);
      return this.exec(wrapped, opts);
    }
    // mode === 'su' — configure password on manager, ensure elevation, then exec
    if (opts.password) {
      await this.manager.setSuPassword(opts.password);
    }
    return this.exec(command, opts);
  }

  async close(): Promise<void> {
    this.manager.close();
  }

  /**
   * ssh2 keeps a persistent Client socket established at init() time, so live
   * connection status is the underlying manager's socket state.
   */
  isConnected(): boolean {
    return this.manager.isConnected();
  }

  private runOnConnection(command: string, opts: ExecOptions): Promise<ExecResult> {
    return new Promise((resolve) => {
      let timeoutId: NodeJS.Timeout;
      let isResolved = false;
      const timeoutMs = opts.timeoutMs;

      const conn = this.manager.getConnection();
      const shell = this.manager.getSuShell();

      timeoutId = setTimeout(() => {
        if (!isResolved) {
          isResolved = true;
          resolve({
            stdout: '',
            stderr: `Command execution timed out after ${timeoutMs}ms`,
            exitCode: null,
            category: 'timeout',
          });
        }
      }, timeoutMs);

      if (shell) {
        let buffer = '';
        const dataHandler = (data: Buffer) => {
          const text = data.toString();
          buffer += text;

          if (/#/.test(buffer)) {
            if (!isResolved) {
              isResolved = true;
              clearTimeout(timeoutId);
              const lines = buffer.split('\n');
              const output = lines.slice(1, -1).join('\n');
              resolve({
                stdout: output + (output ? '\n' : ''),
                stderr: '',
                exitCode: 0,
              });
            }
            shell.removeListener('data', dataHandler);
          }
        };

        shell.on('data', dataHandler);
        shell.write(command + '\n');
        return;
      }

      conn.exec(command, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            resolve({
              stdout: '',
              stderr: `SSH exec error: ${err.message}`,
              exitCode: null,
              category: 'transport',
            });
          }
          return;
        }

        let stdout = '';
        let stderr = '';

        if (opts.stdin && opts.stdin.length > 0) {
          try {
            stream.write(opts.stdin);
          } catch (e) {
            console.error('Error writing to stdin:', e);
          }
        }
        try { stream.end(); } catch (e) { /* ignore */ }

        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });
        stream.on('close', (code: number, _signal: string) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            const exitCode = code ?? 0;
            resolve({
              stdout,
              stderr,
              exitCode,
              category: exitCode !== 0 ? 'remote_exit' : undefined,
            });
          }
        });
      });
    });
  }
}

/** Build a sudo-wrapped command exactly the way upstream sudo-exec tool does. */
export function buildSudoWrapper(command: string, sudoPassword?: string): string {
  const escaped = command.replace(/'/g, "'\\''");
  if (!sudoPassword) {
    return `sudo -n sh -c '${escaped}'`;
  }
  const pwdEscaped = sudoPassword.replace(/'/g, "'\\''");
  return `printf '%s\\n' '${pwdEscaped}' | sudo -p "" -S sh -c '${escaped}'`;
}
