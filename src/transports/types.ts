/**
 * Pluggable SSH transport abstraction.
 *
 * Two implementations:
 *   - Ssh2Transport   (default; uses mscdex/ssh2 library)
 *   - OpenSshTransport (opt-in via --transport=openssh or --kerberos; spawns ssh binary)
 *
 * Transport chosen at startup via factory. Tool handlers consume ExecResult
 * and map to MCP responses.
 */

export type ErrorCategory =
  | 'auth'        // bad password / bad key / Kerberos ticket missing or expired
  | 'host_key'    // StrictHostKeyChecking rejection
  | 'connect'     // TCP/DNS failure
  | 'timeout'     // exec exceeded deadline
  | 'remote_exit' // ran but exited non-zero
  | 'transport';  // ssh2/openssh internal error (spawn failed, etc.)

export interface ExecOptions {
  /** Hard ceiling; transport must enforce and return category='timeout' on breach. */
  timeoutMs: number;
  /** Piped into remote stdin (e.g. sudo password). */
  stdin?: string;
  /** Request TTY allocation (needed for su -tt flow). */
  pty?: boolean;
}

export type ElevationMode = 'sudo' | 'su';

export interface ExecElevatedOptions extends ExecOptions {
  mode: ElevationMode;
  /** sudo -S stdin password, or su password. Optional for passwordless sudo. */
  password?: string;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  /** Non-null only when killed by signal (POSIX). Always null on Windows. */
  signal?: string;
  /** Set when exec failed in a classifiable way. Undefined on success. */
  category?: ErrorCategory;
}

/**
 * Transport contract. Implementations decide connection-lifetime strategy
 * internally (ssh2 keeps one persistent Client; openssh spawns per command
 * because ControlMaster is unsupported on Windows).
 */
export interface ISshTransport {
  readonly name: 'ssh2' | 'openssh';

  /** Prepare resources. Connect ssh2 Client, verify ssh binary exists, etc. */
  init(): Promise<void>;

  /** Run a single remote command. */
  exec(command: string, opts: ExecOptions): Promise<ExecResult>;

  /** Elevated (sudo or su) exec. Transport handles the elevation mechanics. */
  execElevated(command: string, opts: ExecElevatedOptions): Promise<ExecResult>;

  /** Release resources. Idempotent — safe to call multiple times. */
  close(): Promise<void>;
}

/** Auth mode for OpenSshTransport. Ssh2Transport selects auth from SshConfig fields. */
export type AuthMode = 'kerberos' | 'key' | 'password';

/**
 * Unified config shared by both transports. Supersedes the original SSHConfig.
 * Backwards-compatible: ssh2 path reads the legacy fields (host/port/username/
 * password/privateKey/suPassword/sudoPassword) unchanged.
 */
export interface TransportConfig {
  // Connection
  host: string;
  port: number;
  username: string;

  // Auth (legacy, used by both transports)
  password?: string;
  privateKey?: string;  // private-key contents (not path)
  suPassword?: string;
  sudoPassword?: string;

  // OpenSshTransport only
  transport?: 'ssh2' | 'openssh';
  authMode?: AuthMode;
  keyPath?: string;     // path to key file (openssh uses -i)
  kerberos?: boolean;
  gssapiDelegateCredentials?: 'yes' | 'no';
  knownHostsFile?: string;
  strictHostKeyChecking?: 'yes' | 'no' | 'accept-new';
}

/**
 * Named server configuration for multi-host mode. Emits TransportConfig
 * at registry time, plus a required `name` that the MCP tools reference
 * via `connectionName`.
 */
export interface ServerConfig extends TransportConfig {
  /** Unique identifier referenced by MCP tools' connectionName argument. */
  name: string;
  /**
   * Optional human-readable source description from TOML, surfaced by
   * approval prompts and read-only status surfaces (e.g. the WebUI).
   */
  description?: string;
  /** Per-source approval override. */
  approval?: {
    mode?: import('../approval/types.js').ApprovalMode;
  };
}
