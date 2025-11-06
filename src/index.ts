#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client, ClientChannel } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

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

const HOST = argvConfig.host;
const PORT = argvConfig.port ? parseInt(argvConfig.port) : 22;
const USER = argvConfig.user;
const PASSWORD = argvConfig.password;
const SUPASSWORD = argvConfig.suPassword;
const SUDOPASSWORD = argvConfig.sudoPassword;
const DISABLE_SUDO = argvConfig.disableSudo !== undefined;
const KEY = argvConfig.key;
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
        console.error('SSH connection established');
        
          // If suPassword is provided, attempt to elevate to su shell in background
          // Do not block connection establishment on elevation (it may take time);
          // elevation is attempted asynchronously and errors are logged.
          if (this.sshConfig.suPassword) {
            this.ensureElevated().then(() => {
              console.error('Successfully elevated to su shell');
            }).catch((err) => {
              console.error('Failed to elevate to su shell:', err);
              // Do not reject connection; just log the error. Subsequent sudo calls
              // will either use the su shell if available or provide sudo password.
            });
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

  private async ensureElevated(): Promise<void> {
    if (this.isElevated && this.suShell) return;
    if (!this.sshConfig.suPassword) return;

    if (this.suPromise) return this.suPromise;

    this.suPromise = new Promise((resolve, reject) => {
      const conn = this.getConnection();
      // Open an interactive shell and run `su -` inside it, responding to the password prompt.
  // Request a PTY so that su/sudo can prompt for a password interactively.
  conn.shell({ term: 'xterm', cols: 80, rows: 24 }, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          this.suPromise = null;
          reject(new McpError(ErrorCode.InternalError, `Failed to start interactive shell for su: ${err.message}`));
          return;
        }

        let buffer = '';
        const cleanup = () => {
          try { stream.removeAllListeners('data'); } catch (e) { /* ignore */ }
        };

        const onData = (data: Buffer) => {
          buffer += data.toString();

          // Detect password prompt from su
          if (/password[: ]*$/i.test(buffer)) {
            // Send the su password
            stream.write(this.sshConfig.suPassword + '\n');
            buffer = '';
            return;
          }

          // Detect common root prompt (ends with #) or explicit root indicator
          if (/\n[^\n]*# $/.test(buffer) || /root[@:]/i.test(buffer)) {
            // We appear to be elevated; keep the interactive shell as suShell
            cleanup();
            this.suShell = stream;
            this.isElevated = true;
            this.suPromise = null;
            resolve();
            return;
          }

          // Detect authentication failure
          if (/authentication failure|incorrect password|su: .*failed/i.test(buffer)) {
            cleanup();
            this.suPromise = null;
            reject(new McpError(ErrorCode.InternalError, `su authentication failed: ${buffer}`));
            return;
          }
        };

        stream.on('data', onData);

        stream.on('close', () => {
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
  version: '1.3.0',
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
  },
  async ({ command }) => {
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

      const result = await execSshCommandWithConnection(connectionManager, sanitizedCommand);
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
    },
    async ({ command }) => {
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

        let wrapped: string;
        const sudoPassword = connectionManager.getSudoPassword();

        if (!sudoPassword) {
          // No password provided, use -n to fail if sudo requires a password
          wrapped = `sudo -n sh -c '${sanitizedCommand.replace(/'/g, "'\\''")}'`;
        } else {
          // Password provided — pipe it into sudo using printf. This avoids complex
          // PTY/stdin handling on the SSH channel and is simpler and more reliable.
          const pwdEscaped = sudoPassword.replace(/'/g, "'\\''");
          wrapped = `printf '%s\\n' '${pwdEscaped}' | sudo -p "" -S sh -c '${sanitizedCommand.replace(/'/g, "'\\''")}'`;
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
        // Try to abort the running command
        const abortTimeout = setTimeout(() => {
          // If abort command itself times out, we'll just reject
        }, 5000);
        
        conn.exec('timeout 3s pkill -f \'' + escapeCommandForShell(command) + '\' 2>/dev/null || true', (err: Error | undefined, abortStream: ClientChannel | undefined) => {
          if (abortStream) {
            abortStream.on('close', () => {
              clearTimeout(abortTimeout);
            });
          } else {
            clearTimeout(abortTimeout);
          }
        });
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);
    
    let execCommand = command;

    const execFn = shell ? 
      (cb: any) => {
        shell.write(execCommand + '\n');
        cb(null, shell);
      } :
      (cb: any) => {
        // If we have stdin to send (e.g., sudo -S), request a PTY so sudo can read the
        // password reliably in environments that require a TTY.
        if (stdin && stdin.length > 0) {
          conn.exec(execCommand, { pty: true }, cb);
        } else {
          conn.exec(execCommand, cb);
        }
      };

    execFn((err: Error | undefined, stream: ClientChannel) => {
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

      // Setup data handlers before sending any input
      stream.on('data', (data: Buffer) => {
        stdout += data.toString();
      });
      stream.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      // If stdin provided, write it to the stream
      if (stdin && stdin.length > 0 && !shell) {
        try {
          // Write to the exec channel (send to remote stdin)
          stream.write(stdin);
          stream.end(); // End stdin after writing password
        } catch (e) {
          console.error('Error writing to stdin:', e);
        }
      } else {
        // No stdin, just end the stream (guard in case stream.end is not available)
        try { stream.end(); } catch (e) { /* ignore */ }
      }

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