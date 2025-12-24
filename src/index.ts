#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client, ClientChannel } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { spawn, ChildProcess } from 'child_process';
import express from 'express';
import cors from 'cors';

// Example usage:
// Static mode (legacy): node build/index.js --host=1.2.3.4 --user=root --password=pass
// IAP static mode: node build/index.js --iapInstance=vm-name --iapProject=project-id --user=root
// Dynamic mode (recommended): node build/index.js --timeout=60000 --maxChars=none
// HTTP/SSE mode: node build/index.js --port=3000
// Then specify connection details in each command via the tools
function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string | null> = {};
  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const equalIndex = arg.indexOf('=');
      if (equalIndex === -1) {
        // No "=" sign - check if next arg is the value
        const key = arg.slice(2);
        const nextArg = args[i + 1];
        if (nextArg && !nextArg.startsWith('--')) {
          // Next arg is the value
          config[key] = nextArg;
          i += 2; // Skip both this arg and the value
        } else {
          // Flag without value
          config[key] = null;
          i++;
        }
      } else {
        // Key=value pair
        config[arg.slice(2, equalIndex)] = arg.slice(equalIndex + 1);
        i++;
      }
    } else {
      i++;
    }
  }
  return config;
}
const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';
// Always parse arguments to support static mode
const argvConfig = parseArgv();

// Static mode configuration (legacy - connection params at startup)
const HOST = argvConfig.host;
const PORT = argvConfig.port ? parseInt(argvConfig.port) : 22;
const USER = argvConfig.user;
const PASSWORD = argvConfig.password;
const SUPASSWORD = argvConfig.suPassword;
const SUDOPASSWORD = argvConfig.sudoPassword;
const KEY = argvConfig.key;
const IAP_INSTANCE = argvConfig.iapInstance;
const IAP_PROJECT = argvConfig.iapProject;
const IAP_ZONE = argvConfig.iapZone;

// Detect if we're in static mode (connection params provided at startup)
const IS_STATIC_MODE = !!(HOST || IAP_INSTANCE);

// HTTP/SSE transport configuration
const HTTP_PORT = argvConfig.port ? parseInt(argvConfig.port) : undefined;

// Global configuration
const DISABLE_SUDO = argvConfig.disableSudo !== undefined;
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

// Default IAP local port
const DEFAULT_IAP_LOCAL_PORT = 2222;

function validateConfig(config: Record<string, string | null>) {
  const errors = [];

  // Validate global parameters
  if (config.timeout && isNaN(Number(config.timeout))) errors.push('Invalid --timeout');
  if (config.maxChars && config.maxChars !== 'none' && isNaN(Number(config.maxChars))) errors.push('Invalid --maxChars');
  if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');

  // Validate static mode configuration (if connection params provided)
  const isStaticMode = !!(config.host || config.iapInstance);
  if (isStaticMode) {
    // Either host or iapInstance+iapProject must be provided
    if (config.host) {
      if (!config.user) errors.push('Missing required --user for SSH mode');
    } else if (config.iapInstance) {
      if (!config.iapProject) errors.push('Missing required --iapProject for IAP mode');
      if (!config.user) errors.push('Missing required --user for IAP mode');
    }
  }

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
  // Google IAP tunnel configuration (optional)
  iap?: {
    enabled: boolean;
    instanceName: string;
    zone?: string;  // Optional: gcloud can auto-detect if instance name is unique
    project: string;
    localPort?: number;
  };
}

// Google IAP Tunnel Manager
// Connection parameters interface for dynamic connections
export interface ConnectionParams {
  // SSH direct mode
  host?: string;
  port?: number;
  // IAP mode
  iapInstance?: string;
  iapProject?: string;
  iapZone?: string;
  iapLocalPort?: number;
  // Authentication (common to both modes)
  user: string;
  password?: string;
  privateKey?: string;
  privateKeyPath?: string;
  sudoPassword?: string;
  suPassword?: string;
}

// Connection Pool for managing multiple dynamic connections
export class ConnectionPool {
  private connections: Map<string, SSHConnectionManager> = new Map();

  /**
   * Generate a unique key for a connection based on parameters
   */
  private getConnectionKey(params: ConnectionParams): string {
    if (params.iapInstance && params.iapProject) {
      return `iap:${params.iapProject}:${params.iapInstance}:${params.user}`;
    } else if (params.host) {
      return `ssh:${params.host}:${params.port || 22}:${params.user}`;
    }
    throw new Error('Either host or (iapInstance + iapProject) must be specified');
  }

  /**
   * Convert ConnectionParams to SSHConfig
   */
  private async paramsToConfig(params: ConnectionParams): Promise<SSHConfig> {
    // Validate connection parameters
    if (!params.user) {
      throw new McpError(ErrorCode.InvalidParams, 'Missing required parameter: user');
    }

    if (params.iapInstance && params.iapProject) {
      // IAP mode
      const config: SSHConfig = {
        host: 'localhost',  // Will be overridden by tunnel
        port: 22,           // Will be overridden by tunnel
        username: params.user,
        iap: {
          enabled: true,
          instanceName: params.iapInstance,
          zone: params.iapZone,
          project: params.iapProject,
          localPort: params.iapLocalPort || DEFAULT_IAP_LOCAL_PORT
        }
      };

      // Handle authentication
      if (params.password) {
        config.password = params.password;
      } else if (params.privateKey) {
        config.privateKey = params.privateKey;
      } else if (params.privateKeyPath) {
        const fs = await import('fs/promises');
        config.privateKey = await fs.readFile(params.privateKeyPath, 'utf8');
      }

      if (params.sudoPassword) {
        config.sudoPassword = sanitizePassword(params.sudoPassword);
      }
      if (params.suPassword) {
        config.suPassword = sanitizePassword(params.suPassword);
      }

      return config;
    } else if (params.host) {
      // Direct SSH mode
      const config: SSHConfig = {
        host: params.host,
        port: params.port || 22,
        username: params.user
      };

      // Handle authentication
      if (params.password) {
        config.password = params.password;
      } else if (params.privateKey) {
        config.privateKey = params.privateKey;
      } else if (params.privateKeyPath) {
        const fs = await import('fs/promises');
        config.privateKey = await fs.readFile(params.privateKeyPath, 'utf8');
      }

      if (params.sudoPassword) {
        config.sudoPassword = sanitizePassword(params.sudoPassword);
      }
      if (params.suPassword) {
        config.suPassword = sanitizePassword(params.suPassword);
      }

      return config;
    } else {
      throw new McpError(
        ErrorCode.InvalidParams,
        'Either host or (iapInstance + iapProject) must be specified'
      );
    }
  }

  /**
   * Get or create a connection for the given parameters
   */
  async getConnection(params: ConnectionParams): Promise<SSHConnectionManager> {
    const key = this.getConnectionKey(params);

    let manager = this.connections.get(key);

    if (!manager || !manager.isConnected()) {
      // Create new connection
      const config = await this.paramsToConfig(params);
      manager = new SSHConnectionManager(config);
      await manager.connect();
      this.connections.set(key, manager);
    }

    return manager;
  }

  /**
   * Close all connections
   */
  closeAll(): void {
    for (const manager of this.connections.values()) {
      manager.close();
    }
    this.connections.clear();
  }

  /**
   * Get connection count for debugging
   */
  getConnectionCount(): number {
    return this.connections.size;
  }
}

export class SSHConnectionManager {
  private conn: Client | null = null;
  private sshConfig: SSHConfig;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;
  private suShell: any = null;  // Store the elevated shell session
  private suPromise: Promise<void> | null = null;
  private isElevated = false;  // Track if we're in su mode
  private originalHost: string;
  private originalPort: number;

  constructor(config: SSHConfig) {
    this.sshConfig = config;
    this.originalHost = config.host;
    this.originalPort = config.port;
  }

  async connect(): Promise<void> {
    // For IAP mode using gcloud ssh, we don't need a persistent connection
    // Commands are executed directly via gcloud compute ssh
    if (this.sshConfig.iap?.enabled) {
      this.isConnecting = false;
      this.connectionPromise = null;
      return; // No connection needed for IAP mode
    }

    if (this.conn && this.isConnected()) {
      return; // Already connected
    }

    if (this.isConnecting && this.connectionPromise) {
      return this.connectionPromise; // Wait for ongoing connection
    }

    this.isConnecting = true;
    this.connectionPromise = new Promise(async (resolve, reject) => {
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
    // For IAP mode, we're always "connected" since we use gcloud ssh directly
    if (this.sshConfig.iap?.enabled) {
      return true;
    }
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

// Global connection pool for dynamic connections
const connectionPool = new ConnectionPool();

// Global static connection (for legacy static mode)
let staticConnection: SSHConnectionManager | null = null;

// Initialize static connection if in static mode
async function initializeStaticConnection() {
  if (!IS_STATIC_MODE) return;

  const staticConfig: SSHConfig = {
    host: HOST || 'localhost',
    port: PORT,
    username: USER!,
    password: PASSWORD || undefined,
    suPassword: SUPASSWORD || undefined,
    sudoPassword: SUDOPASSWORD || undefined,
  };

  // Read private key from file if path provided
  if (KEY) {
    const fs = await import('fs/promises');
    staticConfig.privateKey = await fs.readFile(KEY, 'utf8');
  }

  // Add IAP configuration if in IAP static mode
  if (IAP_INSTANCE && IAP_PROJECT) {
    staticConfig.iap = {
      enabled: true,
      instanceName: IAP_INSTANCE,
      project: IAP_PROJECT,
      zone: IAP_ZONE || undefined,
      localPort: DEFAULT_IAP_LOCAL_PORT,
    };
  }

  staticConnection = new SSHConnectionManager(staticConfig);
}

const server = new McpServer({
  name: 'SSH MCP Server',
  version: '2.0.0',
  capabilities: {
    resources: {},
    tools: {},
  },
});

server.tool(
  "exec",
  IS_STATIC_MODE
    ? "Execute a shell command on a remote server via SSH (direct) or Google IAP tunnel."
    : "Execute a shell command on a remote server via SSH (direct) or Google IAP tunnel. Specify either 'host' for direct SSH or 'iapInstance+iapProject' for IAP mode.",
  {
    command: z.string().describe("Shell command to execute on the remote server"),
    // SSH direct mode
    host: z.string().optional().describe("SSH hostname or IP address (for direct SSH mode)"),
    port: z.number().optional().describe("SSH port (default: 22)"),
    // Google IAP mode
    iapInstance: z.string().optional().describe("GCP VM instance name (for IAP tunnel mode)"),
    iapProject: z.string().optional().describe("GCP project ID (for IAP tunnel mode)"),
    iapZone: z.string().optional().describe("GCP zone (optional, gcloud can auto-detect if instance name is unique)"),
    iapLocalPort: z.number().optional().describe("Local port for IAP tunnel (default: 2222)"),
    // Authentication (common to both modes)
    user: z.string().optional().describe("SSH username"),
    password: z.string().optional().describe("SSH password"),
    privateKey: z.string().optional().describe("SSH private key content (direct string)"),
    privateKeyPath: z.string().optional().describe("Path to SSH private key file"),
    sudoPassword: z.string().optional().describe("Password for sudo commands"),
    suPassword: z.string().optional().describe("Password for persistent su elevation"),
  },
  async (params) => {
    const { command, ...connectionParams } = params;
    // Sanitize command input
    const sanitizedCommand = sanitizeCommand(command);

    try {
      let manager: SSHConnectionManager;

      // Use static connection in static mode, otherwise use dynamic connection pool
      if (IS_STATIC_MODE) {
        if (!staticConnection) {
          throw new McpError(ErrorCode.InternalError, 'Static connection not initialized');
        }
        manager = staticConnection;
        // Connect if not already connected
        await manager.connect();
      } else {
        // Dynamic mode: get or create connection from pool
        // In dynamic mode, user is required since connection is not pre-configured
        if (!connectionParams.user) {
          throw new McpError(
            ErrorCode.InvalidParams,
            'Missing required parameter: user (dynamic mode requires connection parameters with each command)'
          );
        }
        manager = await connectionPool.getConnection(connectionParams as ConnectionParams);
      }

      // If a suPassword was provided, explicitly wait for elevation before executing
      if ((manager as any).getSuPassword && (manager as any).getSuPassword()) {
        try {
          const elevationPromise = (manager as any).ensureElevated();
          await Promise.race([
            elevationPromise,
            new Promise((_, reject) => setTimeout(() => reject(new Error('Elevation timeout')), 5000))
          ]);
        } catch (err) {
          // Log but don't fail; fall back to non-elevated execution if elevation times out
        }
      }

      const result = await execSshCommandWithConnection(manager, sanitizedCommand);
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
    IS_STATIC_MODE
      ? "Execute a shell command with sudo elevation on a remote server via SSH (direct) or Google IAP tunnel."
      : "Execute a shell command with sudo elevation on a remote server via SSH (direct) or Google IAP tunnel. Specify either 'host' for direct SSH or 'iapInstance+iapProject' for IAP mode.",
    {
      command: z.string().describe("Shell command to execute with sudo elevation"),
      // SSH direct mode
      host: z.string().optional().describe("SSH hostname or IP address (for direct SSH mode)"),
      port: z.number().optional().describe("SSH port (default: 22)"),
      // Google IAP mode
      iapInstance: z.string().optional().describe("GCP VM instance name (for IAP tunnel mode)"),
      iapProject: z.string().optional().describe("GCP project ID (for IAP tunnel mode)"),
      iapZone: z.string().optional().describe("GCP zone (optional, gcloud can auto-detect if instance name is unique)"),
      iapLocalPort: z.number().optional().describe("Local port for IAP tunnel (default: 2222)"),
      // Authentication (common to both modes)
      user: z.string().optional().describe("SSH username"),
      password: z.string().optional().describe("SSH password"),
      privateKey: z.string().optional().describe("SSH private key content (direct string)"),
      privateKeyPath: z.string().optional().describe("Path to SSH private key file"),
      sudoPassword: z.string().optional().describe("Password for sudo commands"),
      suPassword: z.string().optional().describe("Password for persistent su elevation"),
    },
    async (params) => {
      const { command, ...connectionParams } = params;
      const sanitizedCommand = sanitizeCommand(command);

      try {
        let manager: SSHConnectionManager;

        // Use static connection in static mode, otherwise use dynamic connection pool
        if (IS_STATIC_MODE) {
          if (!staticConnection) {
            throw new McpError(ErrorCode.InternalError, 'Static connection not initialized');
          }
          manager = staticConnection;
          // Connect if not already connected
          await manager.connect();
        } else {
          // Dynamic mode: get or create connection from pool
          if (!connectionParams.user) {
            throw new McpError(ErrorCode.InvalidParams, 'Missing required parameter: user');
          }
          manager = await connectionPool.getConnection(connectionParams as ConnectionParams);
        }

        // Wrap command with sudo
        let wrapped: string;
        const sudoPassword = manager.getSudoPassword();

        if (!sudoPassword) {
          // No password provided, use -n to fail if sudo requires a password
          wrapped = `sudo -n sh -c '${sanitizedCommand.replace(/'/g, "'\\''")}'`;
        } else {
          // Password provided — pipe it into sudo using printf
          const pwdEscaped = sudoPassword.replace(/'/g, "'\\''");
          wrapped = `printf '%s\\n' '${pwdEscaped}' | sudo -p "" -S sh -c '${sanitizedCommand.replace(/'/g, "'\\''")}'`;
        }

        return await execSshCommandWithConnection(manager, wrapped);
      } catch (err: any) {
        if (err instanceof McpError) throw err;
        throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
      }
    }
  );
}

// Auto-detect zone for an instance if not provided
async function autoDetectZone(instance: string, project: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const listProcess = spawn('gcloud', [
      'compute',
      'instances',
      'list',
      `--project=${project}`,
      `--filter=name=${instance}`,
      '--format=value(zone)'
    ], {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    listProcess.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    listProcess.stderr?.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    listProcess.on('exit', (code) => {
      if (code === 0) {
        const zone = stdout.trim();
        if (zone) {
          resolve(zone);
        } else {
          reject(new Error(`Instance ${instance} not found in project ${project}`));
        }
      } else {
        reject(new Error(`Failed to list instances: ${stderr}`));
      }
    });

    listProcess.on('error', (err) => {
      reject(new Error(`Failed to execute gcloud instances list: ${err.message}`));
    });
  });
}

// Execute command via gcloud compute ssh (for IAP mode)
export async function execViaGcloudSSH(
  instance: string,
  project: string,
  zone: string | undefined,
  user: string,
  command: string
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise(async (resolve, reject) => {
    // Auto-detect zone if not provided
    let effectiveZone = zone;
    if (!effectiveZone) {
      try {
        effectiveZone = await autoDetectZone(instance, project);
      } catch (err: any) {
        reject(new McpError(ErrorCode.InternalError, `Failed to auto-detect zone: ${err.message}`));
        return;
      }
    }

    const args = [
      'compute',
      'ssh',
      `${user}@${instance}`,
      '--tunnel-through-iap',
      `--project=${project}`,
      `--zone=${effectiveZone}`,
      `--command=${command}`
    ];

    const gcloudProcess = spawn('gcloud', args, {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    gcloudProcess.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    gcloudProcess.stderr?.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    // Set up timeout
    const timeoutId = setTimeout(() => {
      gcloudProcess.kill('SIGTERM');
      reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
    }, DEFAULT_TIMEOUT);

    gcloudProcess.on('exit', (code) => {
      clearTimeout(timeoutId);

      if (code === 0) {
        resolve({
          content: [{
            type: 'text',
            text: stdout,
          }],
        });
      } else {
        reject(new McpError(
          ErrorCode.InternalError,
          `gcloud ssh command failed with exit code ${code}.\nStderr: ${stderr}`
        ));
      }
    });

    gcloudProcess.on('error', (err) => {
      clearTimeout(timeoutId);
      reject(new McpError(ErrorCode.InternalError, `Failed to execute gcloud ssh: ${err.message}`));
    });
  });
}

// New function that uses persistent connection
export async function execSshCommandWithConnection(manager: SSHConnectionManager, command: string, stdin?: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  // Check if this is IAP mode - if so, use gcloud ssh directly
  const iapConfig = (manager as any).sshConfig?.iap;
  if (iapConfig && iapConfig.enabled) {
    return execViaGcloudSSH(
      iapConfig.instanceName,
      iapConfig.project,
      iapConfig.zone,
      (manager as any).sshConfig.username,
      command
    );
  }

  // Otherwise use standard SSH connection
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
  // Initialize static connection if in static mode
  await initializeStaticConnection();

  // Handle graceful shutdown
  const cleanup = () => {
    console.error("Shutting down SSH MCP Server...");
    connectionPool.closeAll();
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => {
    connectionPool.closeAll();
  });

  // Choose transport based on --port parameter
  if (HTTP_PORT) {
    // HTTP/SSE mode
    const app = express();
    app.use(cors());
    app.use(express.json());

    // Health check endpoint
    app.get('/health', (_req, res) => {
      res.json({ status: 'ok', mode: IS_STATIC_MODE ? 'static' : 'dynamic' });
    });

    // SSE endpoint for MCP
    app.get('/sse', async (req, res) => {
      console.error('New SSE connection established');
      const transport = new SSEServerTransport('/message', res);
      await server.connect(transport);
    });

    // Message endpoint for client requests
    app.post('/message', async (req, res) => {
      // This will be handled by SSEServerTransport
      res.status(200).end();
    });

    app.listen(HTTP_PORT, () => {
      console.error(`SSH MCP Server running on http://localhost:${HTTP_PORT}`);
      console.error(`SSE endpoint: http://localhost:${HTTP_PORT}/sse`);
      console.error(`Health check: http://localhost:${HTTP_PORT}/health`);
    });
  } else {
    // Stdio mode (default)
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("SSH MCP Server running on stdio");
  }
}

// Initialize server in test mode for automated tests
if (isTestMode) {
  (async () => {
    await initializeStaticConnection();
    const transport = new StdioServerTransport();
    await server.connect(transport);
  })().catch(error => {
    console.error("Fatal error connecting server:", error);
    process.exit(1);
  });
}
// Start server in CLI mode
else if (isCliEnabled) {
  main().catch((error) => {
    console.error("Fatal error in main():", error);
    connectionPool.closeAll();
    process.exit(1);
  });
}

export { parseArgv, validateConfig };