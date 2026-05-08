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

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function shellBase64Decode(value: string): string {
  const encoded = Buffer.from(value, 'utf8').toString('base64');
  return `printf '%s' ${shellQuote(encoded)} | base64 -d`;
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

  async ensureElevated(): Promise<void> {
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
        const readyMarker = `__SSH_MCP_SU_READY_${Date.now()}_${Math.random().toString(36).slice(2)}__`;
        const cleanup = () => {
          try { stream.removeAllListeners('data'); } catch (e) { /* ignore */ }
        };

        const onData = (data: Buffer) => {
          const text = data.toString();
          buffer += text;

          // If we haven't sent the password yet, look for the password prompt
          if (!passwordSent && /password[: ]/i.test(buffer)) {
            passwordSent = true;
            stream.write(`${this.sshConfig.suPassword}\nstty -echo\n${shellBase64Decode(readyMarker)}; printf '\\n'\n`);
          }

          if (passwordSent && buffer.replace(/\r/g, '').includes(readyMarker)) {
            clearTimeout(timeoutId);
            cleanup();
            this.suShell = stream;
            this.isElevated = true;
            this.suPromise = null;
            resolve();
            return;
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

  getSuShell(): ClientChannel {
    if (!this.suShell || !this.isElevated) {
      throw new McpError(ErrorCode.InternalError, 'su shell not established');
    }
    return this.suShell;
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

async function createSshConfig(): Promise<SSHConfig> {
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

  const suPassword = sanitizePassword(SUPASSWORD ?? undefined);
  if (suPassword) {
    sshConfig.suPassword = suPassword;
  }

  const sudoPassword = sanitizePassword(SUDOPASSWORD ?? undefined);
  if (sudoPassword) {
    sshConfig.sudoPassword = sudoPassword;
  }

  return sshConfig;
}

async function getConnectionManager(): Promise<SSHConnectionManager> {
  if (!connectionManager) {
    connectionManager = new SSHConnectionManager(await createSshConfig());
  }
  return connectionManager;
}

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
    description: z.string().optional().describe("Optional client-side description; not sent to the remote shell"),
  },
  async ({ command }) => {
    const sanitizedCommand = sanitizeCommand(command);

    try {
      const connectionManager = await getConnectionManager();
      await connectionManager.ensureConnected();
      return await execSshCommandWithConnection(connectionManager, sanitizedCommand);
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

if (sanitizePassword(SUPASSWORD ?? undefined)) {
  server.tool(
    "su-exec",
    "Execute a shell command on the remote SSH server through an elevated su shell.",
    {
      command: z.string().describe("Shell command to execute with su on the remote SSH server"),
      description: z.string().optional().describe("Optional client-side description; not sent to the remote shell"),
    },
    async ({ command }) => {
      const sanitizedCommand = sanitizeCommand(command);

      try {
        const connectionManager = await getConnectionManager();
        await connectionManager.ensureConnected();
        return await execSshCommandWithSuConnection(connectionManager, sanitizedCommand);
      } catch (err: any) {
        if (err instanceof McpError) throw err;
        throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
      }
    }
  );
}

if (!DISABLE_SUDO && sanitizePassword(SUDOPASSWORD ?? undefined)) {
  server.tool(
    "sudo-exec",
    "Execute a shell command on the remote SSH server using sudo and the configured sudo password.",
    {
      command: z.string().describe("Shell command to execute with sudo on the remote SSH server"),
      description: z.string().optional().describe("Optional client-side description; not sent to the remote shell"),
    },
    async ({ command }) => {
      const sanitizedCommand = sanitizeCommand(command);

      try {
        const connectionManager = await getConnectionManager();
        await connectionManager.ensureConnected();
        const sudoPassword = connectionManager.getSudoPassword();
        if (!sudoPassword) {
          throw new McpError(ErrorCode.InvalidParams, 'sudo-exec requires --sudoPassword');
        }

        const wrapped = `printf '%s\\n' ${shellQuote(sudoPassword)} | sudo -p "" -S sh -c ${shellQuote(sanitizedCommand)}`;
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

    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);

    // Always use a normal SSH exec channel here. Elevated execution is exposed
    // through explicit su-exec and sudo-exec tools.
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

export async function execSshCommandWithSuConnection(manager: SSHConnectionManager, command: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  await manager.ensureElevated();

  return new Promise((resolve, reject) => {
    const shell = manager.getSuShell();
    const marker = `SSH_MCP_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const startMarker = `__${marker}_START__`;
    const endMarker = `__${marker}_END__`;
    let buffer = '';
    let isResolved = false;

    const dataHandler = (data: Buffer) => {
      buffer += data.toString();
      const normalized = buffer.replace(/\r/g, '');
      const lines = normalized.split('\n');
      const startLineIndex = lines.findIndex(line => line.endsWith(startMarker));
      if (startLineIndex === -1) return;

      const endLineIndex = lines.findIndex((line, index) => index > startLineIndex && line.includes(`${endMarker}:`));
      if (endLineIndex === -1) return;

      let output = lines.slice(startLineIndex + 1, endLineIndex).join('\n');
      finish(output ? `${output}\n` : '');
    };

    const timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        shell.removeListener('data', dataHandler);
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);

    const finish = (output: string) => {
      if (isResolved) return;
      isResolved = true;
      clearTimeout(timeoutId);
      shell.removeListener('data', dataHandler);
      resolve({
        content: [{
          type: 'text',
          text: output,
        }],
      });
    };

    shell.on('data', dataHandler);
    shell.write(`${shellBase64Decode(startMarker)}; printf '\\n'; sh -c ${shellQuote(command)}; status=$?; printf '\\n'; ${shellBase64Decode(endMarker)}; printf ':%s\\n' "$status"\n`);
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
