#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client, ClientChannel } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createHash, createHmac } from 'crypto';
import { readFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

// Example usage: node build/index.js --host=1.2.3.4 --port=22 --user=root --password=pass --key=path/to/key --timeout=5000 --disableSudo
function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string | null> = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const equalIndex = arg.indexOf('=');
      if (equalIndex === -1) {
        // Flag without value
        config[arg.slice(2)] = null;
      } else {
        // Key=value pair
        config[arg.slice(2, equalIndex)] = arg.slice(equalIndex + 1);
      }
    }
  }
  return config;
}
const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';
const argvConfig = (isCliEnabled || isTestMode) ? parseArgv() : {} as Record<string, string>;

// Credential resolution: an explicit CLI flag always takes precedence over the
// environment variable. Passing secrets via env vars keeps them out of the
// process argument list (visible to other local users via `ps`/proc) and out of
// committed MCP client configs. `undefined` means "not provided"; for the su/sudo
// passwords we preserve the existing null/undefined distinction used downstream.
function resolveSecret(flag: string | null | undefined, env: string | undefined): string | null | undefined {
  if (flag !== undefined) return flag;       // flag wins (including bare flag => null)
  if (env !== undefined && env !== '') return env;
  return undefined;
}

const HOST = argvConfig.host ?? process.env.SSH_MCP_HOST;
const PORT = argvConfig.port ? parseInt(argvConfig.port) : (process.env.SSH_MCP_PORT ? parseInt(process.env.SSH_MCP_PORT) : 22);
const USER = argvConfig.user ?? process.env.SSH_MCP_USER;
const PASSWORD = resolveSecret(argvConfig.password, process.env.SSH_MCP_PASSWORD) ?? undefined;
const SUPASSWORD = resolveSecret(argvConfig.suPassword, process.env.SSH_MCP_SU_PASSWORD);
const SUDOPASSWORD = resolveSecret(argvConfig.sudoPassword, process.env.SSH_MCP_SUDO_PASSWORD);
const DISABLE_SUDO = argvConfig.disableSudo !== undefined;
const KEY = argvConfig.key ?? process.env.SSH_MCP_KEY_PATH;

// Host key verification settings (defends against man-in-the-middle attacks).
// By default the server verifies the host key against the user's known_hosts file
// and refuses to connect if it is not found there. A pinned fingerprint may be
// supplied with --hostFingerprint, and verification can be disabled (with a loud
// warning) using --insecureHostKey for ephemeral/throwaway hosts.
const HOST_FINGERPRINT = argvConfig.hostFingerprint ?? process.env.SSH_MCP_HOST_FINGERPRINT ?? undefined;
const KNOWN_HOSTS_PATH = argvConfig.knownHosts ?? process.env.SSH_MCP_KNOWN_HOSTS ?? join(homedir(), '.ssh', 'known_hosts');
const INSECURE_HOST_KEY = argvConfig.insecureHostKey !== undefined || process.env.SSH_MCP_INSECURE_HOST_KEY === '1';
const DEFAULT_TIMEOUT = argvConfig.timeout ? parseInt(argvConfig.timeout) : 60000; // 60 seconds default timeout
// Max characters configuration:
// - Default: 1000 characters
// - When set via --maxChars:
//   * a positive integer enforces that limit
//   * 0 or a negative value disables the limit (no max)
//   * the string "none" (case-insensitive) disables the limit (no max)
const MAX_CHARS_RAW = argvConfig.maxChars;
const MAX_CHARS = (() => {
  if (typeof MAX_CHARS_RAW === 'string') {
    const lowered = MAX_CHARS_RAW.toLowerCase();
    if (lowered === 'none') return Infinity;
    const parsed = parseInt(MAX_CHARS_RAW);
    if (isNaN(parsed)) return 1000;
    if (parsed <= 0) return Infinity;
    return parsed;
  }
  return 1000;
})();

function validateConfig(config: Record<string, string | null>) {
  const errors = [];
  if (!config.host) errors.push('Missing required --host');
  if (!config.user) errors.push('Missing required --user');
  if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');
  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

if (isCliEnabled) {
  validateConfig(argvConfig);
}

// Command sanitization and validation
export function sanitizeCommand(command: string): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }

  const trimmedCommand = command.trim();
  if (!trimmedCommand) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }

  // Length check
  if (Number.isFinite(MAX_CHARS) && trimmedCommand.length > (MAX_CHARS as number)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Command is too long (max ${MAX_CHARS} characters)`
    );
  }

  return trimmedCommand;
}

function sanitizePassword(password: string | undefined): string | undefined {
  if (typeof password !== 'string') return undefined;
  // minimal check, do not log or modify content
  if (password.length === 0) return undefined;
  return password;
}

// Escape command for use in shell contexts (like pkill)
export function escapeCommandForShell(command: string): string {
  // Replace single quotes with escaped single quotes
  return command.replace(/'/g, "'\"'\"'");
}

// Strip CR/LF (and collapse whitespace) from a description before appending it as
// a shell comment. Without this, a newline in the description would terminate the
// comment and inject an extra command line into the shell.
export function sanitizeDescription(description: string): string {
  return description.replace(/[\r\n]+/g, ' ').replace(/#/g, '\\#').trim();
}

// Build a `printf` invocation that emits a unique sentinel line. The embedded ""
// splits the literal so the sentinel string appears only in the command's OUTPUT,
// never in the PTY's echo of the input. This lets us detect command boundaries in
// a persistent root shell reliably, even when a command's own output contains '#'
// or other prompt-like characters (the previous heuristic broke on such output).
export function sentinelEcho(label: string, token: string, suffix = ''): string {
  return `printf '%s\\n' "SSH_MCP""_${label}_${token}${suffix}"`;
}

// --- Host key verification helpers (defense against MITM) ---

// OpenSSH-style SHA256 fingerprint ("SHA256:<base64 without padding>") of a raw
// host key buffer, matching `ssh-keygen -lf`.
export function sshKeyFingerprintSha256(key: Buffer): string {
  return 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
}

// Whether a raw host key buffer matches an expected fingerprint. Accepts modern
// SHA256 fingerprints ("SHA256:..." or bare base64) and legacy MD5 hex
// fingerprints ("MD5:aa:bb:..." or "aa:bb:...").
export function matchesFingerprint(key: Buffer, expected: string): boolean {
  const exp = expected.trim();
  const isMd5 = /^MD5:/i.test(exp) || /^([0-9a-f]{2}:){15}[0-9a-f]{2}$/i.test(exp);
  if (isMd5) {
    const got = createHash('md5').update(key).digest('hex');
    const want = exp.replace(/^MD5:/i, '').replace(/:/g, '').toLowerCase();
    return got === want;
  }
  const got = createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
  const want = exp.replace(/^SHA256:/i, '').replace(/=+$/, '');
  return got === want;
}

// Whether a host field from a known_hosts line matches one of the candidate
// host identifiers. Supports plain comma-separated patterns and hashed
// (|1|salt|hash) entries.
function knownHostsFieldMatches(hostField: string, candidates: string[]): boolean {
  if (hostField.startsWith('|1|')) {
    const segs = hostField.split('|'); // ['', '1', <b64 salt>, <b64 hash>]
    if (segs.length < 4) return false;
    let salt: Buffer;
    try { salt = Buffer.from(segs[2], 'base64'); } catch { return false; }
    const expectedHash = segs[3];
    return candidates.some((h) => createHmac('sha1', salt).update(h).digest('base64') === expectedHash);
  }
  const patterns = hostField.split(',');
  return patterns.some((p) => candidates.includes(p));
}

// Whether the given known_hosts content contains an entry for this host:port
// whose key exactly matches the presented host key.
export function knownHostsHasKey(content: string, host: string, port: number, key: Buffer): boolean {
  // OpenSSH records non-default ports as "[host]:port"; port 22 is stored bare.
  const candidates = port === 22 ? [host] : [`[${host}]:${port}`];
  const b64key = key.toString('base64');
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    let parts = line.split(/\s+/);
    if (parts[0].startsWith('@')) parts = parts.slice(1); // @cert-authority / @revoked markers
    if (parts.length < 3) continue;
    const [hostField, , keyData] = parts;
    if (keyData !== b64key) continue;
    if (knownHostsFieldMatches(hostField, candidates)) return true;
  }
  return false;
}

export interface HostKeyVerifyOptions {
  host: string;
  port: number;
  hostFingerprint?: string;
  insecure?: boolean;
}

// Decide whether to accept a presented host key. Pure/synchronous so it can be
// unit tested; the caller is responsible for reading known_hosts from disk.
export function verifyHostKeySync(
  key: Buffer,
  opts: HostKeyVerifyOptions,
  knownHostsContent?: string,
): { ok: boolean; reason: string } {
  if (opts.insecure) {
    return { ok: true, reason: 'host key verification disabled (--insecureHostKey)' };
  }
  if (opts.hostFingerprint) {
    if (matchesFingerprint(key, opts.hostFingerprint)) {
      return { ok: true, reason: 'host key matches pinned fingerprint' };
    }
    return {
      ok: false,
      reason: `host key fingerprint mismatch (presented ${sshKeyFingerprintSha256(key)})`,
    };
  }
  if (knownHostsContent && knownHostsHasKey(knownHostsContent, opts.host, opts.port, key)) {
    return { ok: true, reason: 'host key found in known_hosts' };
  }
  return {
    ok: false,
    reason:
      `host key not found in known_hosts (presented ${sshKeyFingerprintSha256(key)}). ` +
      'Add it to your known_hosts, pin it with --hostFingerprint, or use --insecureHostKey to disable verification.',
  };
}

// SSH Connection Manager to maintain persistent connection
export interface SSHConfig {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  suPassword?: string;
  sudoPassword?: string;  // Password for sudo commands specifically (if different from suPassword)
  hostFingerprint?: string;   // Pinned host key fingerprint (SHA256 or MD5)
  knownHostsPath?: string;    // Path to known_hosts (defaults to ~/.ssh/known_hosts)
  insecureHostKey?: boolean;  // Disable host key verification (vulnerable to MITM)
}

// Build the ssh2 connect config, injecting a hostVerifier so we never silently
// accept an unverified host key (ssh2 auto-accepts when no verifier is supplied).
export function buildConnectConfig(sshConfig: SSHConfig): any {
  const cfg: any = { ...sshConfig };
  const { host, port, hostFingerprint, insecureHostKey } = sshConfig;
  const knownHostsPath = sshConfig.knownHostsPath || join(homedir(), '.ssh', 'known_hosts');

  cfg.hostVerifier = (key: Buffer): boolean => {
    let knownHostsContent: string | undefined;
    if (!insecureHostKey && !hostFingerprint) {
      try { knownHostsContent = readFileSync(knownHostsPath, 'utf8'); } catch { /* treat as empty */ }
    }
    const result = verifyHostKeySync(
      key,
      { host, port, hostFingerprint, insecure: insecureHostKey },
      knownHostsContent,
    );
    if (insecureHostKey) {
      console.error(
        'WARNING: SSH host key verification is DISABLED (--insecureHostKey). ' +
        'The connection is vulnerable to man-in-the-middle attacks.',
      );
    } else if (!result.ok) {
      console.error(`SSH host key verification failed: ${result.reason}`);
    }
    return result.ok;
  };
  return cfg;
}

export class SSHConnectionManager {
  private conn: Client | null = null;
  private sshConfig: SSHConfig;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;
  private suShell: any = null;  // Store the elevated shell session
  private suPromise: Promise<void> | null = null;
  private isElevated = false;  // Track if we're in su mode
  private tokenSeq = 0;        // Monotonic counter for unique command sentinels

  constructor(config: SSHConfig) {
    this.sshConfig = config;
  }

  // Unique-per-command token used to fence command output in the persistent shell.
  nextToken(): string {
    this.tokenSeq += 1;
    return 'k' + this.tokenSeq.toString(36) + 'z';
  }

  async connect(): Promise<void> {
    if (this.conn && this.isConnected()) {
      return; // Already connected
    }

    if (this.isConnecting && this.connectionPromise) {
      return this.connectionPromise; // Wait for ongoing connection
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
      }, 30000); // 30 seconds connection timeout

      this.conn.on('ready', async () => {
        clearTimeout(timeoutId);
        this.isConnecting = false;

        // In test mode, don't wait for su elevation during connection setup, as it
        // may cause JSON-RPC server initialization to hang. Instead, elevation will
        // be triggered on-demand when a command is executed.
        // In production, elevation during connection is desirable for robustness.
        if (this.sshConfig.suPassword && !process.env.SSH_MCP_TEST) {
          try {
            await this.ensureElevated();
          } catch (err) {
            // Do not reject the connection; just log the error. Subsequent commands
            // will either use the su shell if available or fall back to normal execution.
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

      this.conn.connect(buildConnectConfig(this.sshConfig));
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
      // If clearing suPassword, drop any existing suShell
      if (this.suShell) {
        try { this.suShell.end(); } catch (e) { /* ignore */ }
        this.suShell = null;
        this.isElevated = false;
      }
    }
  }

  private async ensureElevated(): Promise<void> {
    if (this.isElevated && this.suShell) return;
    if (!this.sshConfig.suPassword) return;

    if (this.suPromise) return this.suPromise;

    this.suPromise = new Promise((resolve, reject) => {
      const conn = this.getConnection();

      // Add a safety timeout so elevation doesn't hang forever
      const timeoutId = setTimeout(() => {
        this.suPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'su elevation timed out'));
      }, 10000);  // 10 second timeout for elevation

      conn.shell({ term: 'xterm', cols: 80, rows: 24 }, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          clearTimeout(timeoutId);
          this.suPromise = null;
          reject(new McpError(ErrorCode.InternalError, `Failed to start interactive shell for su: ${err.message}`));
          return;
        }

        let buffer = '';
        let passwordSent = false;
        let probeSent = false;
        const readyToken = this.nextToken();
        const readyRe = new RegExp('SSH_MCP_READY_' + readyToken);
        const authFailRe = /authentication failure|incorrect password|su: .*fail/i;
        const cleanup = () => {
          try { stream.removeAllListeners('data'); } catch (e) { /* ignore */ }
        };
        const fail = (msg: string) => {
          clearTimeout(timeoutId);
          cleanup();
          try { stream.end(); } catch (e) { /* ignore */ }
          this.suPromise = null;
          reject(new McpError(ErrorCode.InternalError, msg));
        };

        const onData = (data: Buffer) => {
          buffer += data.toString();

          // If we haven't sent the password yet, look for the password prompt.
          if (!passwordSent && /password[: ]/i.test(buffer)) {
            passwordSent = true;
            buffer = '';  // reset so stale output can't trigger the checks below
            stream.write(this.sshConfig.suPassword + '\n');
            // Turn off PTY echo so command input isn't mixed into command output,
            // then emit a unique readiness sentinel. If su failed, this runs in the
            // unprivileged shell and would still print READY — so the auth-failure
            // check below (which su prints first) takes precedence.
            stream.write('stty -echo 2>/dev/null\n');
            stream.write(sentinelEcho('READY', readyToken) + '\n');
            probeSent = true;
            return;
          }

          // Detect authentication failure messages before accepting the shell.
          if (passwordSent && authFailRe.test(buffer)) {
            fail('su authentication failed');
            return;
          }

          // Accept the elevated shell only once our readiness sentinel is echoed back.
          if (probeSent && readyRe.test(buffer)) {
            clearTimeout(timeoutId);
            cleanup();
            this.suShell = stream;
            this.isElevated = true;
            this.suPromise = null;
            resolve();
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

        // Kick off the su command
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

let connectionManager: SSHConnectionManager | null = null;

const server = new McpServer(
  {
    name: 'SSH MCP Server',
    version: '1.5.0',
  },
  {
    capabilities: {
      resources: {},
      tools: {},
    },
  },
);

server.tool(
  "exec",
  "Execute a shell command on the remote SSH server and return the output.",
  {
    command: z.string().describe("Shell command to execute on the remote SSH server"),
    description: z.string().optional().describe("Optional description of what this command will do"),
  },
  async ({ command, description }) => {
    // Sanitize command input
    const sanitizedCommand = sanitizeCommand(command);

    try {
      // Initialize connection manager if not already done
      if (!connectionManager) {
        if (!HOST || !USER) {
          throw new McpError(ErrorCode.InvalidParams, 'Missing required host or username');
        }
        const sshConfig: SSHConfig = {
          host: HOST,
          port: PORT,
          username: USER,
          hostFingerprint: HOST_FINGERPRINT,
          knownHostsPath: KNOWN_HOSTS_PATH,
          insecureHostKey: INSECURE_HOST_KEY,
        };

        if (PASSWORD) {
          sshConfig.password = PASSWORD;
        } else if (KEY) {
          const fs = await import('fs/promises');
          sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
        }

        if (SUPASSWORD !== null && SUPASSWORD !== undefined) {
          sshConfig.suPassword = sanitizePassword(SUPASSWORD);
        }
        connectionManager = new SSHConnectionManager(sshConfig);
      }

      // Ensure connection is active (reconnect if needed)
      await connectionManager.ensureConnected();

      // If a suPassword was provided, explicitly wait for elevation before executing.
      // This is critical: ensureElevated is idempotent and will return immediately if
      // already elevated, so this ensures we have a su shell before we try to use it.
      if ((connectionManager as any).getSuPassword && (connectionManager as any).getSuPassword()) {
        try {
          const elevationPromise = (connectionManager as any).ensureElevated();
          // Add a short timeout for elevation to complete
          await Promise.race([
            elevationPromise,
            new Promise((_, reject) => setTimeout(() => reject(new Error('Elevation timeout')), 5000))
          ]);
        } catch (err) {
          // Log but don't fail; fall back to non-elevated execution if elevation times out
        }
      }

      // Append description as comment if provided
      const commandWithDescription = description
        ? `${sanitizedCommand} # ${sanitizeDescription(description)}`
        : sanitizedCommand;

      const result = await execSshCommandWithConnection(connectionManager, commandWithDescription);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// Expose sudo-exec tool unless explicitly disabled
if (!DISABLE_SUDO) {
  server.tool(
    "sudo-exec",
    "Execute a shell command on the remote SSH server using sudo. Will use sudo password if provided, otherwise assumes passwordless sudo.",
    {
      command: z.string().describe("Shell command to execute with sudo on the remote SSH server"),
      description: z.string().optional().describe("Optional description of what this command will do"),
    },
    async ({ command, description }) => {
      const sanitizedCommand = sanitizeCommand(command);

      try {
        if (!connectionManager) {
          if (!HOST || !USER) {
            throw new McpError(ErrorCode.InvalidParams, 'Missing required host or username');
          }

          const sshConfig: SSHConfig = {
            host: HOST,
            port: PORT || 22,
            username: USER,
            hostFingerprint: HOST_FINGERPRINT,
            knownHostsPath: KNOWN_HOSTS_PATH,
            insecureHostKey: INSECURE_HOST_KEY,
          };
          if (PASSWORD) {
            sshConfig.password = PASSWORD;
          } else if (KEY) {
            const fs = await import('fs/promises');
            sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
          }
          if (SUPASSWORD !== null && SUPASSWORD !== undefined) {
            sshConfig.suPassword = sanitizePassword(SUPASSWORD);
          }
          if (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined) {
            sshConfig.sudoPassword = sanitizePassword(SUDOPASSWORD);
          }
          connectionManager = new SSHConnectionManager(sshConfig);
        }

        await connectionManager.ensureConnected();

        // If suPassword or sudoPassword were provided on this call but the
        // existing connection manager was created earlier without them,
        // update the manager's values so the subsequent sudo-exec call uses
        // the latest passwords.
        if (SUPASSWORD !== null && SUPASSWORD !== undefined) {
          await connectionManager.setSuPassword(sanitizePassword(SUPASSWORD));
        }
        if (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined) {
          // update sudoPassword on the manager instance
          (connectionManager as any).sshConfig = { ...(connectionManager as any).sshConfig, sudoPassword: sanitizePassword(SUDOPASSWORD) };
        }

        let wrapped: string;
        const sudoPassword = connectionManager.getSudoPassword();

        // Append description as comment if provided
        const commandWithDescription = description
          ? `${sanitizedCommand} # ${sanitizeDescription(description)}`
          : sanitizedCommand;

        if (!sudoPassword) {
          // No password provided, use -n to fail if sudo requires a password
          wrapped = `sudo -n sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
          return await execSshCommandWithConnection(connectionManager, wrapped);
        }

        // Password provided — feed it to `sudo -S` over the channel's stdin instead
        // of embedding it in the command string. Embedding it (e.g. via `printf <pwd> |`)
        // would expose the password in the remote process list (`ps`) and shell history.
        // `-p ""` suppresses the prompt and `-k` ignores any cached credentials so the
        // password is always read from the first line of stdin.
        wrapped = `sudo -p "" -S -k sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
        return await execSshCommandWithConnection(connectionManager, wrapped, sudoPassword + '\n');
      } catch (err: any) {
        if (err instanceof McpError) throw err;
        throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
      }
    }
  );
}

// New function that uses persistent connection
export async function execSshCommandWithConnection(manager: SSHConnectionManager, command: string, stdin?: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;

    const conn = manager.getConnection();
    const shell = (manager as any).suShell;  // Use su shell if available

    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);

    // If we have an active su shell, use it directly (commands run as root in session).
    // We fence the command between two unique sentinels so we can locate its exact
    // output regardless of what the command prints, and capture its exit code.
    if (shell) {
      let buffer = '';
      const token = manager.nextToken();
      const beginRe = new RegExp('SSH_MCP_BEGIN_' + token + '\\r?\\n');
      const endRe = new RegExp('SSH_MCP_END_' + token + ':(\\d+)');

      const dataHandler = (data: Buffer) => {
        buffer += data.toString();

        const endMatch = buffer.match(endRe);
        if (!endMatch) return;
        if (isResolved) return;
        isResolved = true;
        clearTimeout(timeoutId);
        shell.removeListener('data', dataHandler);

        // Output is everything between the begin sentinel's output line and the
        // end sentinel. (PTY echo is disabled during elevation, so input lines
        // don't appear here.)
        const beginMatch = buffer.match(beginRe);
        let output = beginMatch
          ? buffer.slice((beginMatch.index as number) + beginMatch[0].length, endMatch.index)
          : buffer.slice(0, endMatch.index);
        output = output.replace(/\r/g, '').replace(/\n+$/, '');

        resolve({
          content: [{
            type: 'text',
            text: output + (output ? '\n' : ''),
          }],
        });
      };

      shell.on('data', dataHandler);
      // Begin sentinel, the command, then an end sentinel carrying the exit code.
      shell.write(sentinelEcho('BEGIN', token) + '\n');
      shell.write(command + '\n');
      shell.write('__rc=$?; ' + sentinelEcho('END', token, ':$__rc') + '\n');
      return;
    }

    // No persistent su shell; use normal exec with optional password piping
    conn.exec(command, (err: Error | undefined, stream: ClientChannel) => {
      if (err) {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timeoutId);
          reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
        }
        return;
      }

      let stdout = '';
      let stderr = '';

      // If stdin provided (e.g., sudo password), write it
      if (stdin && stdin.length > 0) {
        try {
          stream.write(stdin);
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

      stream.on('close', (code: number, signal: string) => {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timeoutId);
          if (stderr) {
            reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
          } else {
            resolve({
              content: [{
                type: 'text',
                text: stdout,
              }],
            });
          }
        }
      });
    });
  });
}

// Keep the old function for backward compatibility (used in tests)
export async function execSshCommand(sshConfig: any, command: string, stdin?: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;

    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        // Try to abort the running command before closing connection
        const abortTimeout = setTimeout(() => {
          // If abort command itself times out, force close connection
          conn.end();
        }, 5000); // 5 second timeout for abort command

        conn.exec('timeout 3s pkill -f \'' + escapeCommandForShell(command) + '\' 2>/dev/null || true', (err: Error | undefined, abortStream: ClientChannel | undefined) => {
          if (abortStream) {
            abortStream.on('close', () => {
              clearTimeout(abortTimeout);
              conn.end();
            });
          } else {
            clearTimeout(abortTimeout);
            conn.end();
          }
        });
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);

    conn.on('ready', () => {
      conn.exec(command, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
          }
          conn.end();
          return;
        }
        // If stdin provided, write it to the stream and end stdin
        if (stdin && stdin.length > 0) {
          try {
            stream.write(stdin);
          } catch (e) {
            // ignore
          }
        }
        try { stream.end(); } catch (e) { /* ignore */ }
        let stdout = '';
        let stderr = '';
        stream.on('close', (code: number, signal: string) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            conn.end();
            if (stderr) {
              reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
            } else {
              resolve({
                content: [{
                  type: 'text',
                  text: stdout,
                }],
              });
            }
          }
        });
        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });
      });
    });
    conn.on('error', (err: Error) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      }
    });
    conn.connect(buildConnectConfig(sshConfig));
  });
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SSH MCP Server running on stdio");

  // Handle graceful shutdown
  const cleanup = () => {
    console.error("Shutting down SSH MCP Server...");
    if (connectionManager) {
      connectionManager.close();
      connectionManager = null;
    }
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => {
    if (connectionManager) {
      connectionManager.close();
    }
  });
}

// Initialize server in test mode for automated tests
if (isTestMode) {
  const transport = new StdioServerTransport();
  server.connect(transport).catch(error => {
    console.error("Fatal error connecting server:", error);
    process.exit(1);
  });
}
// Start server in CLI mode
else if (isCliEnabled) {
  main().catch((error) => {
    console.error("Fatal error in main():", error);
    if (connectionManager) {
      connectionManager.close();
    }
    process.exit(1);
  });
}

export { parseArgv, validateConfig };