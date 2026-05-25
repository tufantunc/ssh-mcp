#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { Client, ClientChannel } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { ISshTransport, TransportConfig, ServerConfig, ExecResult, AuthMode } from './transports/types.js';
import { SSHConnectionManager, SSHConfig } from './transports/ssh2.js';
import { createTransport } from './transports/factory.js';
import { TransportRegistry } from './transports/registry.js';
import { resolveConfig } from './config/resolver.js';
import type { ResolvedConfig } from './config/types.js';
import {
  sanitizeCommand as sanitizeCommandImpl,
  sanitizePassword,
  escapeCommandForShell,
} from './utils/shell.js';

// Re-exports for backward compatibility with existing tests.
export { SSHConnectionManager, escapeCommandForShell };
export type { SSHConfig };

// =============================================================================
// CLI parsing — two modes:
//   (A) Multi-host: repeated --ssh=<JSON> (each JSON must include "name")
//   (B) Legacy single-host: --host --user [--kerberos | --key | --password] ...
// =============================================================================

function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string | null> = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const equalIndex = arg.indexOf('=');
      if (equalIndex === -1) {
        config[arg.slice(2)] = null;
      } else {
        const key = arg.slice(2, equalIndex);
        // --ssh is handled separately below (repeatable); skip here so we
        // don't clobber with only the last value.
        if (key === 'ssh') continue;
        config[key] = arg.slice(equalIndex + 1);
      }
    }
  }
  return config;
}

function collectSshJsonArgs(): string[] {
  return process.argv.slice(2)
    .filter(a => a.startsWith('--ssh='))
    .map(a => a.slice('--ssh='.length));
}

function parseServerConfigJson(raw: string): ServerConfig {
  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch (e: any) {
    throw new Error(`--ssh JSON parse error: ${e?.message || e}`);
  }
  if (!obj.name) throw new Error('--ssh JSON missing required "name"');
  if (!obj.host) throw new Error(`--ssh "${obj.name}" missing required "host"`);
  const user = obj.user ?? obj.username;
  if (!user) throw new Error(`--ssh "${obj.name}" missing required "user" (or "username")`);
  const auth: AuthMode | undefined = obj.auth;
  if (!auth || !['kerberos', 'key', 'password'].includes(auth)) {
    throw new Error(`--ssh "${obj.name}" requires "auth": "kerberos" | "key" | "password"`);
  }

  const cfg: ServerConfig = {
    name: obj.name,
    host: obj.host,
    port: obj.port ?? 22,
    username: user,
    authMode: auth,
  };

  switch (auth) {
    case 'kerberos':
      cfg.kerberos = true;
      cfg.transport = 'openssh';
      if (obj.gssapiDelegateCredentials) cfg.gssapiDelegateCredentials = obj.gssapiDelegateCredentials;
      break;
    case 'key':
      cfg.transport = obj.transport ?? 'ssh2';
      if (obj.keyPath) cfg.keyPath = obj.keyPath;
      if (obj.privateKey) cfg.privateKey = obj.privateKey;
      break;
    case 'password':
      cfg.transport = obj.transport ?? 'ssh2';
      if (obj.password) cfg.password = obj.password;
      break;
  }

  if (obj.sudoPassword) cfg.sudoPassword = obj.sudoPassword;
  if (obj.suPassword) cfg.suPassword = obj.suPassword;
  if (obj.knownHostsFile) cfg.knownHostsFile = obj.knownHostsFile;
  if (obj.strictHostKeyChecking) cfg.strictHostKeyChecking = obj.strictHostKeyChecking;
  return cfg;
}

const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';
const argvConfig = (isCliEnabled || isTestMode) ? parseArgv() : {} as Record<string, string>;
const sshJsonArgs = (isCliEnabled || isTestMode) ? collectSshJsonArgs() : [];

// Legacy (single-host) flags
const HOST = argvConfig.host;
const PORT = argvConfig.port ? parseInt(argvConfig.port) : 22;
const USER = argvConfig.user;
const PASSWORD = argvConfig.password;
const SUPASSWORD = argvConfig.suPassword;
const SUDOPASSWORD = argvConfig.sudoPassword;
const DISABLE_SUDO = argvConfig.disableSudo !== undefined;
const KEY = argvConfig.key;
const DEFAULT_TIMEOUT = argvConfig.timeout ? parseInt(argvConfig.timeout) : 60000;
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

const TRANSPORT_FLAG = argvConfig.transport;
const KERBEROS_FLAG = argvConfig.kerberos !== undefined && argvConfig.kerberos !== 'false';
const GSSAPI_DELEGATE = argvConfig.gssapiDelegateCredentials;
const KNOWN_HOSTS_FILE = argvConfig.knownHostsFile;
const STRICT_HOST_KEY = argvConfig.strictHostKeyChecking;
const CONFIG_PATH = argvConfig.config;

const legacyFlagNames = [
  'host', 'user', 'password', 'key', 'kerberos', 'transport',
  'strictHostKeyChecking', 'knownHostsFile', 'gssapiDelegateCredentials',
  'suPassword', 'sudoPassword', 'disableSudo', 'port',
] as const;

function hasLegacyCliFlags(config: Record<string, string | null>): boolean {
  return legacyFlagNames.some(f => config[f] !== undefined);
}

function validateConfig(config: Record<string, string | null>, multiHost: boolean) {
  const errors: string[] = [];

  if (multiHost) {
    // Multi-host mode: legacy single-host flags are disallowed to avoid ambiguity
    const legacyFlags = ['host', 'user', 'password', 'key', 'kerberos', 'transport',
                         'strictHostKeyChecking', 'knownHostsFile', 'gssapiDelegateCredentials'];
    const set = legacyFlags.filter(f => config[f] !== undefined);
    if (set.length > 0) {
      errors.push(`Multi-host (--ssh) mode cannot be mixed with legacy single-host flags: ${set.map(s => '--' + s).join(', ')}`);
    }
  } else {
    // Legacy single-host validation
    if (!config.host) errors.push('Missing required --host (or use --ssh=<JSON> for multi-host mode)');
    if (!config.user) errors.push('Missing required --user');
    if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');

    const transportExplicit = config.transport;
    const kerberos = config.kerberos !== undefined && config.kerberos !== 'false';
    const transport = transportExplicit ?? (kerberos ? 'openssh' : 'ssh2');

    if (transport !== 'ssh2' && transport !== 'openssh') {
      errors.push(`Invalid --transport=${transport} (expected: ssh2 or openssh)`);
    }
    if (kerberos && transportExplicit === 'ssh2') {
      errors.push('--kerberos requires --transport=openssh (remove --transport=ssh2 or pass --kerberos alone)');
    }
    if (transport === 'ssh2' && (config.knownHostsFile || config.strictHostKeyChecking)) {
      errors.push('--knownHostsFile and --strictHostKeyChecking require --transport=openssh');
    }
    if (STRICT_HOST_KEY && !['yes', 'no', 'accept-new'].includes(config.strictHostKeyChecking!)) {
      errors.push('--strictHostKeyChecking must be one of: yes, no, accept-new');
    }
    if (GSSAPI_DELEGATE && !['yes', 'no'].includes(config.gssapiDelegateCredentials!)) {
      errors.push('--gssapiDelegateCredentials must be yes or no');
    }
  }

  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

const isMultiHost = sshJsonArgs.length > 0;
const hasLegacyCli = hasLegacyCliFlags(argvConfig);

function buildLegacyServerConfig(): ServerConfig | undefined {
  if (!HOST || !USER) return undefined;

  const authMode: AuthMode | undefined = KERBEROS_FLAG ? 'kerberos'
    : KEY ? 'key'
    : PASSWORD ? 'password'
    : undefined;
  const resolvedTransport: 'ssh2' | 'openssh' =
    (TRANSPORT_FLAG === 'openssh' || KERBEROS_FLAG) ? 'openssh' : 'ssh2';

  const cfg: ServerConfig = {
    name: 'default',
    host: HOST,
    port: PORT,
    username: USER,
    transport: resolvedTransport,
    authMode,
  };
  if (PASSWORD) cfg.password = PASSWORD;
  if (KEY) cfg.keyPath = KEY;
  if (SUPASSWORD !== null && SUPASSWORD !== undefined) cfg.suPassword = sanitizePassword(SUPASSWORD);
  if (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined) cfg.sudoPassword = sanitizePassword(SUDOPASSWORD);
  if (KERBEROS_FLAG) cfg.kerberos = true;
  if (GSSAPI_DELEGATE) cfg.gssapiDelegateCredentials = GSSAPI_DELEGATE as 'yes' | 'no';
  if (KNOWN_HOSTS_FILE) cfg.knownHostsFile = KNOWN_HOSTS_FILE;
  if (STRICT_HOST_KEY) cfg.strictHostKeyChecking = STRICT_HOST_KEY as 'yes' | 'no' | 'accept-new';
  return cfg;
}

const cliSourceConfigs: ServerConfig[] = (() => {
  if (isMultiHost) {
    return sshJsonArgs.map(raw => parseServerConfigJson(raw));
  }
  if (hasLegacyCli) {
    const legacy = buildLegacyServerConfig();
    return legacy ? [legacy] : [];
  }
  return [];
})();

const resolvedConfig: ResolvedConfig = (isCliEnabled || isTestMode)
  ? resolveConfig({
      cliSources: cliSourceConfigs,
      cliConfigPath: typeof CONFIG_PATH === 'string' ? CONFIG_PATH : undefined,
    })
  : { sources: [], perSourceApproval: {} };

if (isCliEnabled) {
  if (isMultiHost) {
    validateConfig(argvConfig, true);
  } else if (hasLegacyCli) {
    validateConfig(argvConfig, false);
  } else if (resolvedConfig.sources.length === 0) {
    throw new Error(
      'Configuration error:\nMissing required --host (or use --ssh=<JSON>, --config=<path>, SSH_MCP_CONFIG, or a default ssh-mcp config.toml)',
    );
  }
}

export function sanitizeCommand(command: string): string {
  return sanitizeCommandImpl(command, MAX_CHARS as number);
}

// =============================================================================
// Transport registry — lazy init, single entry for legacy single-host mode.
// =============================================================================

const registry = new TransportRegistry();

async function prepareKeyContents(cfg: ServerConfig): Promise<void> {
  // ssh2 transport reads key contents in memory; openssh uses -i path.
  if (cfg.transport === 'ssh2' && cfg.keyPath && !cfg.privateKey) {
    const fs = await import('fs/promises');
    cfg.privateKey = await fs.readFile(cfg.keyPath, 'utf8');
  }
}

async function bootstrapRegistry(): Promise<void> {
  for (const cfg of resolvedConfig.sources) {
    await prepareKeyContents(cfg);
    registry.register(cfg);
  }
  if (resolvedConfig.defaultName) {
    registry.setDefault(resolvedConfig.defaultName);
  }
}

export function resultToMcpContent(result: ExecResult) {
  if (result.category === 'timeout') {
    throw new McpError(ErrorCode.InternalError, result.stderr || `Command execution timed out after ${DEFAULT_TIMEOUT}ms`);
  }
  if (result.category === 'auth') {
    throw new McpError(ErrorCode.InternalError, `SSH authentication error: ${result.stderr}`);
  }
  if (result.category === 'host_key') {
    throw new McpError(ErrorCode.InternalError, `SSH host key error: ${result.stderr}`);
  }
  if (result.category === 'connect') {
    throw new McpError(ErrorCode.InternalError, `SSH connection error: ${result.stderr}`);
  }
  if (result.category === 'transport') {
    throw new McpError(ErrorCode.InternalError, result.stderr || 'SSH transport error');
  }
  // Only treat stderr as a hard failure when the command actually failed (non-zero exit).
  // Many tools (sudo with -S, curl, git, apt) write progress/info to stderr on success.
  const exitCode = result.exitCode ?? 0;
  if (exitCode !== 0 && result.stderr) {
    throw new McpError(ErrorCode.InternalError, `Error (code ${exitCode}):\n${result.stderr}`);
  }
  // Success path: include stderr alongside stdout when it has substantive content.
  const trimmedStderr = result.stderr.trim();
  const text = trimmedStderr
    ? (result.stdout
        ? `${result.stdout.replace(/\n+$/, '')}\n[stderr]\n${result.stderr}`
        : result.stderr)
    : result.stdout;
  return {
    content: [{
      type: 'text' as const,
      text,
    }],
  };
}

const server = new McpServer({
  name: 'SSH MCP Server',
  version: '2.1.0',
  capabilities: { resources: {}, tools: {} },
});

const connectionNameSchema = z.string().optional()
  .describe('Name of the SSH connection (from --ssh config). Optional when only one server is configured.');

server.tool(
  'exec',
  'Execute a shell command on a remote SSH server and return the output.',
  {
    command: z.string().describe('Shell command to execute on the remote SSH server'),
    description: z.string().optional().describe('Optional description of what this command will do'),
    connectionName: connectionNameSchema,
  },
  async ({ command, description, connectionName }) => {
    const sanitizedCommand = sanitizeCommand(command);
    try {
      const t = await registry.get(connectionName);
      const commandWithDescription = description
        ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
        : sanitizedCommand;
      const result = await t.exec(commandWithDescription, { timeoutMs: DEFAULT_TIMEOUT });
      return resultToMcpContent(result);
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

if (!DISABLE_SUDO) {
  server.tool(
    'sudo-exec',
    'Execute a shell command on a remote SSH server using sudo. Uses the configured sudoPassword if provided; otherwise assumes passwordless sudo.',
    {
      command: z.string().describe('Shell command to execute with sudo on the remote SSH server'),
      description: z.string().optional().describe('Optional description of what this command will do'),
      connectionName: connectionNameSchema,
    },
    async ({ command, description, connectionName }) => {
      const sanitizedCommand = sanitizeCommand(command);
      try {
        const t = await registry.get(connectionName);
        const commandWithDescription = description
          ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
          : sanitizedCommand;
        // Legacy single-host mode may still pass --sudoPassword on CLI; in
        // multi-host mode each ServerConfig carries its own sudoPassword.
        const legacySudo = (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined && !isMultiHost)
          ? sanitizePassword(SUDOPASSWORD)
          : undefined;
        const result = await t.execElevated(commandWithDescription, {
          timeoutMs: DEFAULT_TIMEOUT,
          mode: 'sudo',
          password: legacySudo,
        });
        return resultToMcpContent(result);
      } catch (err: any) {
        if (err instanceof McpError) throw err;
        throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
      }
    }
  );
}

server.tool(
  'list-servers',
  'List all configured SSH server connections, their auth mode, and current connection status.',
  {},
  async () => {
    const rows = registry.list();
    if (rows.length === 0) {
      return { content: [{ type: 'text', text: 'No SSH servers are configured.' }] };
    }
    const text = rows.map(r => {
      const tag = r.isDefault ? ' (default)' : '';
      const state = r.connected ? 'connected' : 'not yet connected';
      return `- ${r.name}${tag}: ${r.username}@${r.host}:${r.port} [transport=${r.transport}, auth=${r.authMode}, ${state}]`;
    }).join('\n');
    return { content: [{ type: 'text', text }] };
  }
);

// =============================================================================
// Legacy exports preserved for existing test files.
// =============================================================================

export async function execSshCommandWithConnection(
  manager: SSHConnectionManager,
  command: string,
  stdin?: string
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: 'text'; text: string; } | { [x: string]: unknown; type: 'image'; data: string; mimeType: string; } | { [x: string]: unknown; type: 'audio'; data: string; mimeType: string; } | { [x: string]: unknown; type: 'resource'; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;

    const conn = manager.getConnection();
    const shell = (manager as any).getSuShell ? (manager as any).getSuShell() : (manager as any).suShell;

    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);

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
              content: [{ type: 'text', text: output + (output ? '\n' : '') }],
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
          reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
        }
        return;
      }

      let stdout = '';
      let stderr = '';

      if (stdin && stdin.length > 0) {
        try { stream.write(stdin); } catch (e) { console.error('Error writing to stdin:', e); }
      }
      try { stream.end(); } catch (e) { /* ignore */ }

      stream.on('data', (data: Buffer) => { stdout += data.toString(); });
      stream.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });
      stream.on('close', (code: number, _signal: string) => {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timeoutId);
          if (stderr) {
            reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
          } else {
            resolve({ content: [{ type: 'text', text: stdout }] });
          }
        }
      });
    });
  });
}

export async function execSshCommand(
  sshConfig: any,
  command: string,
  stdin?: string
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: 'text'; text: string; } | { [x: string]: unknown; type: 'image'; data: string; mimeType: string; } | { [x: string]: unknown; type: 'audio'; data: string; mimeType: string; } | { [x: string]: unknown; type: 'resource'; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;

    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        const abortTimeout = setTimeout(() => { conn.end(); }, 5000);
        conn.exec(`timeout 3s pkill -f '${escapeCommandForShell(command)}' 2>/dev/null || true`, (err: Error | undefined, abortStream: ClientChannel | undefined) => {
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
        if (stdin && stdin.length > 0) {
          try { stream.write(stdin); } catch (e) { /* ignore */ }
        }
        try { stream.end(); } catch (e) { /* ignore */ }
        let stdout = '';
        let stderr = '';
        stream.on('close', (code: number, _signal: string) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            conn.end();
            if (stderr) {
              reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
            } else {
              resolve({ content: [{ type: 'text', text: stdout }] });
            }
          }
        });
        stream.on('data', (data: Buffer) => { stdout += data.toString(); });
        stream.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });
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

// =============================================================================
// Server lifecycle
// =============================================================================

async function main() {
  await bootstrapRegistry();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  const mode = isMultiHost ? `multi-host (${registry.names().length} servers: ${registry.names().join(', ')})` : 'single-host';
  console.error(`SSH MCP Server running on stdio — ${mode}`);

  const cleanup = () => {
    console.error('Shutting down SSH MCP Server...');
    void registry.closeAll();
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => { void registry.closeAll(); });
}

if (isTestMode) {
  (async () => {
    try {
      await bootstrapRegistry();
    } catch { /* tests may not configure hosts */ }
    const transport = new StdioServerTransport();
    server.connect(transport).catch(error => {
      console.error('Fatal error connecting server:', error);
      process.exit(1);
    });
  })();
} else if (isCliEnabled) {
  main().catch((error) => {
    console.error('Fatal error in main():', error);
    void registry.closeAll();
    process.exit(1);
  });
}

export { parseArgv, validateConfig };
