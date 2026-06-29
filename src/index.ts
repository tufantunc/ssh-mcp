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

export function parseServerConfigJson(raw: string): ServerConfig {
  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch (e: any) {
    throw new Error(`--ssh JSON parse error: ${e?.message || e}\nRaw: ${raw}`);
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
  // knownHostsFile / strictHostKeyChecking are openssh-transport-only. The ssh2
  // transport ignores both, so accepting them on an ssh2 config would silently
  // drop the requested host-key enforcement — a security downgrade. Mirror the
  // legacy single-host rule ("--knownHostsFile and --strictHostKeyChecking
  // require --transport=openssh") and reject the combination here.
  if ((obj.knownHostsFile || obj.strictHostKeyChecking) && cfg.transport !== 'openssh') {
    throw new Error(
      `--ssh "${obj.name}" knownHostsFile/strictHostKeyChecking require "transport": "openssh" (got ${cfg.transport})`
    );
  }
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

function validateConfig(config: Record<string, string | null>, multiHost: boolean) {
  const errors: string[] = [];

  if (multiHost) {
    // Multi-host mode: legacy single-host flags are disallowed to avoid ambiguity.
    // bootstrapRegistry reads connection details ONLY from each --ssh JSON in
    // this mode, so any legacy flag would be silently ignored — including
    // --port (wrong port), --sudoPassword and --suPassword (elevation would run
    // without the password). Reject the whole set rather than drop them quietly.
    const legacyFlags = ['host', 'user', 'port', 'password', 'key', 'kerberos', 'transport',
                         'sudoPassword', 'suPassword',
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

if (isCliEnabled) {
  validateConfig(argvConfig, isMultiHost);
}

export function sanitizeCommand(command: string): string {
  return sanitizeCommandImpl(command, MAX_CHARS as number);
}

function resolveTransport(opts: { transportFlag?: string | null; kerberos?: boolean }): 'ssh2' | 'openssh' {
  if (opts.transportFlag === 'openssh' || opts.kerberos) return 'openssh';
  return 'ssh2';
}

/**
 * Resolve the effective auth mode from the provided credential flags.
 *
 * Precedence: kerberos > password > key. Password is ranked above key to
 * preserve the legacy ssh2 behaviour (base `main`): when both a password and a
 * key path are supplied, the password wins and the key file is never read. This
 * avoids an ENOENT crash for password configs that still carry a stale/sample
 * `--key=path/to/key`.
 */
export function resolveAuthMode(opts: {
  kerberos?: boolean;
  key?: string | null;
  password?: string | null;
}): 'kerberos' | 'key' | 'password' | undefined {
  if (opts.kerberos) return 'kerberos';
  if (opts.password) return 'password';
  if (opts.key) return 'key';
  return undefined;
}

/**
 * Inputs for {@link buildTransportConfig}. Mirrors the legacy CLI flags but is
 * passed explicitly so the resolution logic is pure and unit-testable.
 */
export interface BuildTransportConfigInputs {
  host?: string | null;
  port: number;
  username?: string | null;
  password?: string | null;
  key?: string | null;
  suPassword?: string | null;
  sudoPassword?: string | null;
  kerberos?: boolean;
  transportFlag?: string | null;
  gssapiDelegateCredentials?: string | null;
  knownHostsFile?: string | null;
  strictHostKeyChecking?: string | null;
}

export async function buildTransportConfig(inputs: BuildTransportConfigInputs): Promise<TransportConfig> {
  const { host, username } = inputs;
  if (!host || !username) {
    throw new McpError(ErrorCode.InvalidParams, 'Missing required host or username');
  }

  const transport = resolveTransport({ transportFlag: inputs.transportFlag, kerberos: inputs.kerberos });
  const authMode = resolveAuthMode({
    kerberos: inputs.kerberos,
    password: inputs.password,
    key: inputs.key,
  });

  const cfg: TransportConfig = {
    host,
    port: inputs.port,
    username,
    transport,
    authMode,
  };

  if (inputs.password) cfg.password = inputs.password;
  if (inputs.key) {
    cfg.keyPath = inputs.key;
    // ssh2 transport needs the key contents, not the path — but only when the
    // key is the resolved auth mode. A password config that also carries a
    // stale/sample --key must NOT read the (possibly nonexistent) key file,
    // which would otherwise throw ENOENT before connecting (regression vs base
    // main, where password took precedence and the key was never read).
    if (transport === 'ssh2' && authMode === 'key') {
      const fs = await import('fs/promises');
      cfg.privateKey = await fs.readFile(inputs.key, 'utf8');
    }
  }
  if (inputs.suPassword !== null && inputs.suPassword !== undefined) cfg.suPassword = sanitizePassword(inputs.suPassword);
  if (inputs.sudoPassword !== null && inputs.sudoPassword !== undefined) cfg.sudoPassword = sanitizePassword(inputs.sudoPassword);
  if (inputs.kerberos) cfg.kerberos = true;
  if (inputs.gssapiDelegateCredentials) cfg.gssapiDelegateCredentials = inputs.gssapiDelegateCredentials as 'yes' | 'no';
  if (inputs.knownHostsFile) cfg.knownHostsFile = inputs.knownHostsFile;
  if (inputs.strictHostKeyChecking) cfg.strictHostKeyChecking = inputs.strictHostKeyChecking as 'yes' | 'no' | 'accept-new';

  return cfg;
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
  if (isMultiHost) {
    for (const raw of sshJsonArgs) {
      const cfg = parseServerConfigJson(raw);
      await prepareKeyContents(cfg);
      registry.register(cfg);
    }
  } else {
    if (!HOST || !USER) return; // Test mode with no CLI — tools will error if called
    // Route the legacy single-host path through buildTransportConfig so it
    // inherits the kerberos>password>key precedence and the gated key read
    // (a password config carrying a stale --key must not ENOENT on a missing
    // key file). buildTransportConfig already loads privateKey when key is the
    // resolved auth mode, so no separate prepareKeyContents call is needed here.
    const tcfg = await buildTransportConfig({
      host: HOST,
      port: PORT,
      username: USER,
      password: PASSWORD,
      key: KEY,
      suPassword: SUPASSWORD,
      sudoPassword: SUDOPASSWORD,
      kerberos: KERBEROS_FLAG,
      transportFlag: TRANSPORT_FLAG,
      gssapiDelegateCredentials: GSSAPI_DELEGATE,
      knownHostsFile: KNOWN_HOSTS_FILE,
      strictHostKeyChecking: STRICT_HOST_KEY,
    });
    registry.register({ ...tcfg, name: 'default' });
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
  .describe(
    'Name of the SSH connection to target (the id/name from your --ssh=<JSON> or TOML [[sources]] config). ' +
    'REQUIRED when multiple SSH connections are configured: omitting or blanking it fails fast with the list ' +
    'of valid names instead of silently routing to the default source. Omission is allowed only for a true ' +
    'single-source deployment (the lone source is used), or when the operator has explicitly set ' +
    '[server].require_connection = false to restore the legacy silent-default fallback.',
  );

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
