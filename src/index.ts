#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client, ClientChannel } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { execSync } from 'child_process';
import { homedir } from 'os';
import { existsSync } from 'fs';
import { join } from 'path';

// Resolve a shell alias by running the user's shell
export function resolveShellAlias(aliasName: string): string | null {
  const shell = process.env.SHELL || '/bin/bash';

  try {
    // Use interactive shell to load aliases, then output the alias definition
    // Works with both bash and zsh
    const result = execSync(
      `${shell} -i -c "type ${aliasName}" 2>/dev/null`,
      { encoding: 'utf8', timeout: 5000 }
    ).trim();

    // Parse different shell output formats:
    // zsh: "web: aliased to ssh root@185.66.200.78"
    // bash: "web is aliased to 'ssh root@185.66.200.78'"

    let sshCommand: string | null = null;

    // zsh format: "name: aliased to command"
    const zshMatch = result.match(/^[^:]+:\s*aliased to\s+(.+)$/);
    if (zshMatch) {
      sshCommand = zshMatch[1];
    }

    // bash format: "name is aliased to 'command'" or "name is aliased to `command`"
    const bashMatch = result.match(/^[^\s]+\s+is\s+aliased\s+to\s+['`](.+)['`]$/);
    if (bashMatch) {
      sshCommand = bashMatch[1];
    }

    // Also handle alias output without quotes (some shells)
    const simpleMatch = result.match(/^[^\s]+\s+is\s+aliased\s+to\s+(.+)$/);
    if (!sshCommand && simpleMatch) {
      sshCommand = simpleMatch[1].replace(/^['"`]|['"`]$/g, '');
    }

    return sshCommand;
  } catch (error) {
    return null;
  }
}

// Parse SSH connection details from an SSH command string
export interface ParsedSSHCommand {
  user?: string;
  host?: string;
  port?: number;
  key?: string;
}

export function parseSSHCommand(sshCommand: string): ParsedSSHCommand {
  const result: ParsedSSHCommand = {};

  // Remove 'ssh' prefix if present
  let cmd = sshCommand.trim();
  if (cmd.startsWith('ssh ')) {
    cmd = cmd.slice(4).trim();
  } else if (cmd === 'ssh') {
    return result;
  }

  // Parse options and arguments
  const parts = cmd.split(/\s+/);
  let i = 0;

  while (i < parts.length) {
    const part = parts[i];

    // Port: -p <port>
    if (part === '-p' && i + 1 < parts.length) {
      const portNum = parseInt(parts[i + 1], 10);
      if (!isNaN(portNum)) {
        result.port = portNum;
      }
      i += 2;
      continue;
    }

    // Identity file: -i <keyfile>
    if (part === '-i' && i + 1 < parts.length) {
      let keyPath = parts[i + 1];
      // Expand ~ to home directory
      if (keyPath.startsWith('~')) {
        keyPath = join(homedir(), keyPath.slice(1));
      }
      result.key = keyPath;
      i += 2;
      continue;
    }

    // Skip other options that take arguments
    if (part.match(/^-[oJLRDwbcemFIOSTW]$/) && i + 1 < parts.length) {
      i += 2;
      continue;
    }

    // Skip flag-only options
    if (part.startsWith('-')) {
      i++;
      continue;
    }

    // This should be user@host or just host
    const userHostMatch = part.match(/^(?:([^@]+)@)?(.+)$/);
    if (userHostMatch) {
      if (userHostMatch[1]) {
        result.user = userHostMatch[1];
      }
      result.host = userHostMatch[2];
    }

    i++;
    // After finding host, stop (remaining args are remote commands)
    break;
  }

  return result;
}

// Resolve alias and return merged config
export async function resolveAliasConfig(aliasName: string): Promise<ParsedSSHCommand | null> {
  const sshCommand = resolveShellAlias(aliasName);
  if (!sshCommand) {
    return null;
  }

  // Verify it's an SSH command
  if (!sshCommand.startsWith('ssh ') && sshCommand !== 'ssh') {
    return null;
  }

  return parseSSHCommand(sshCommand);
}

// Example usage: node build/index.js --host=1.2.3.4 --port=22 --user=root --password=pass --key=path/to/key --timeout=5000 --disableSudo
// Or with alias: node build/index.js --alias=myserver
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

// Resolve alias if provided
let aliasConfig: ParsedSSHCommand = {};
if (argvConfig.alias) {
  const resolved = resolveShellAlias(argvConfig.alias);
  if (resolved) {
    aliasConfig = parseSSHCommand(resolved);
  } else {
    console.error(`Warning: Could not resolve alias '${argvConfig.alias}'`);
  }
}

// Merge config: explicit args override alias values
const HOST = argvConfig.host || aliasConfig.host;
const PORT = argvConfig.port ? parseInt(argvConfig.port) : (aliasConfig.port || 22);
const USER = argvConfig.user || aliasConfig.user;
const PASSWORD = argvConfig.password;
const SUPASSWORD = argvConfig.suPassword;
const SUDOPASSWORD = argvConfig.sudoPassword;
const DISABLE_SUDO = argvConfig.disableSudo !== undefined;
const KEY = argvConfig.key || aliasConfig.key;
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

function validateConfig(config: Record<string, string | null>, resolved: { host?: string; user?: string }) {
  const errors = [];
  const hasHost = config.host || resolved.host;
  const hasUser = config.user || resolved.user;

  if (!hasHost) errors.push('Missing required --host (or use --alias)');
  if (!hasUser) errors.push('Missing required --user (or use --alias)');
  if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');
  if (config.alias && !resolved.host) errors.push(`Could not resolve alias '${config.alias}' or alias is not an SSH command`);
  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

if (isCliEnabled) {
  validateConfig(argvConfig, aliasConfig);
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

// SSH Connection Manager to maintain persistent connection
export interface SSHConfig {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  suPassword?: string;
  sudoPassword?: string;  // Password for sudo commands specifically (if different from suPassword)
}

export class SSHConnectionManager {
  private conn: Client | null = null;
  private sshConfig: SSHConfig;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;
  private suShell: any = null;  // Store the elevated shell session
  private suPromise: Promise<void> | null = null;
  private isElevated = false;  // Track if we're in su mode

  constructor(config: SSHConfig) {
    this.sshConfig = config;
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
        const cleanup = () => {
          try { stream.removeAllListeners('data'); } catch (e) { /* ignore */ }
        };

        const onData = (data: Buffer) => {
          const text = data.toString();
          buffer += text;

          // If we haven't sent the password yet, look for the password prompt
          if (!passwordSent && /password[: ]/i.test(buffer)) {
            passwordSent = true;
            stream.write(this.sshConfig.suPassword + '\n');
            // Don't return; keep looking for root prompt
          }

          // After password is sent, look for any root indicator
          // Look for '#' which indicates root prompt (may be followed by spaces, escape codes, etc)
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

          // Detect authentication failure messages
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

const server = new McpServer({
  name: 'SSH MCP Server',
  version: '1.5.0',
  capabilities: {
    resources: {},
    tools: {},
  },
});

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
        ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
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
          ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
          : sanitizedCommand;

        if (!sudoPassword) {
          // No password provided, use -n to fail if sudo requires a password
          wrapped = `sudo -n sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
        } else {
          // Password provided — pipe it into sudo using printf. This avoids complex
          // PTY/stdin handling on the SSH channel and is simpler and more reliable.
          const pwdEscaped = sudoPassword.replace(/'/g, "'\\''");
          wrapped = `printf '%s\\n' '${pwdEscaped}' | sudo -p "" -S sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
        }

        return await execSshCommandWithConnection(connectionManager, wrapped);
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

    // If we have an active su shell, use it directly (commands run as root in session)
    if (shell) {
      let buffer = '';

      const dataHandler = (data: Buffer) => {
        const text = data.toString();
        buffer += text;

        // Wait for root prompt (#) to know command is complete
        // Match # which indicates root prompt (may be followed by spaces, escape codes, etc)
        if (/#/.test(buffer)) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);

            // Extract output: remove the command echo and final prompt
            const lines = buffer.split('\n');
            // First line is often the echoed command; last line is the prompt
            let output = lines.slice(1, -1).join('\n');

            resolve({
              content: [{
                type: 'text',
                text: output + (output ? '\n' : ''),
              }],
            });
          }
          shell.removeListener('data', dataHandler);
        }
      };

      shell.on('data', dataHandler);
      // Send command immediately; shell is ready after elevation
      shell.write(command + '\n');
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
    conn.connect(sshConfig);
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