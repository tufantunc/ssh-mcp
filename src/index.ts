#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { Client, ClientChannel } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { ISshTransport, TransportConfig, ExecResult } from './transports/types.js';
import { SSHConnectionManager, SSHConfig } from './transports/ssh2.js';
import { createTransport } from './transports/factory.js';
import {
  sanitizeCommand as sanitizeCommandImpl,
  sanitizePassword,
  escapeCommandForShell,
} from './utils/shell.js';

// Re-exports for backward compatibility with existing tests (smoke.ssh.test.ts,
// persistent-connection.test.ts, etc.).
export { SSHConnectionManager, escapeCommandForShell };
export type { SSHConfig };

// Example usage: node build/index.js --host=1.2.3.4 --port=22 --user=root --password=pass --key=path/to/key --timeout=5000 --disableSudo
// Kerberos SSO:   node build/index.js --host=host --user=user@REALM --kerberos
function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string | null> = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const equalIndex = arg.indexOf('=');
      if (equalIndex === -1) {
        config[arg.slice(2)] = null;
      } else {
        config[arg.slice(2, equalIndex)] = arg.slice(equalIndex + 1);
      }
    }
  }
  return config;
}

const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';
const argvConfig = (isCliEnabled || isTestMode) ? parseArgv() : {} as Record<string, string>;

// Connection config (legacy flags)
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

// Transport config (new flags)
const TRANSPORT_FLAG = argvConfig.transport;
const KERBEROS_FLAG = argvConfig.kerberos !== undefined && argvConfig.kerberos !== 'false';
const GSSAPI_DELEGATE = argvConfig.gssapiDelegateCredentials;
const KNOWN_HOSTS_FILE = argvConfig.knownHostsFile;
const STRICT_HOST_KEY = argvConfig.strictHostKeyChecking;

function validateConfig(config: Record<string, string | null>) {
  const errors: string[] = [];
  if (!config.host) errors.push('Missing required --host');
  if (!config.user) errors.push('Missing required --user');
  if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');

  const transportExplicit = config.transport;
  const kerberos = config.kerberos !== undefined && config.kerberos !== 'false';
  // --kerberos alone implies --transport=openssh
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
  // OpenSSH options that require an explicit value. A value-less flag (e.g.
  // `--strictHostKeyChecking` with no `=value`) is recorded as `null` by
  // parseArgv; guarding on truthiness would silently skip validation and let
  // buildTransportConfig drop the option, falling back to the default and (for
  // strictHostKeyChecking) weakening the requested host-key policy. Detect the
  // flag by property presence so a missing value is rejected with a clear error.
  if ('strictHostKeyChecking' in config && !['yes', 'no', 'accept-new'].includes(config.strictHostKeyChecking!)) {
    errors.push('--strictHostKeyChecking must be one of: yes, no, accept-new');
  }
  if ('gssapiDelegateCredentials' in config && !['yes', 'no'].includes(config.gssapiDelegateCredentials!)) {
    errors.push('--gssapiDelegateCredentials must be yes or no');
  }
  if ('knownHostsFile' in config && !config.knownHostsFile) {
    errors.push('--knownHostsFile requires a file path');
  }

  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

if (isCliEnabled) {
  validateConfig(argvConfig);
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

export interface TransportInitCache {
  activeTransport: ISshTransport | null;
  initPromise: Promise<ISshTransport> | null;
}

const activeTransportCache: TransportInitCache = {
  activeTransport: null,
  initPromise: null,
};

/**
 * Return the active transport, or share one in-flight initialization.
 *
 * The transport must not be published before init() completes: OpenSSH password
 * auth prepares SSH_ASKPASS asynchronously, and a concurrent tool call that sees
 * a half-initialized transport can enter runSsh before the helper/env is ready.
 */
export function getOrCreateInitializedTransport(
  cache: TransportInitCache,
  createInitializedTransport: () => Promise<ISshTransport>,
): Promise<ISshTransport> {
  if (cache.activeTransport) return Promise.resolve(cache.activeTransport);
  if (cache.initPromise) return cache.initPromise;

  const initPromise = createInitializedTransport()
    .then((transport) => {
      cache.activeTransport = transport;
      if (cache.initPromise === initPromise) cache.initPromise = null;
      return transport;
    })
    .catch((err) => {
      if (cache.initPromise === initPromise) cache.initPromise = null;
      throw err;
    });
  cache.initPromise = initPromise;
  return initPromise;
}

async function getOrCreateTransport(): Promise<ISshTransport> {
  return getOrCreateInitializedTransport(activeTransportCache, async () => {
    const cfg = await buildTransportConfig({
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
    const transport = createTransport(cfg);
    await transport.init();
    return transport;
  });
}

/**
 * Map ExecResult to MCP tool response. Preserves upstream semantics:
 *   - auth/host_key/connect/transport categories → reject with descriptive error
 *   - timeout → reject with timeout error
 *   - non-zero exit → reject (wraps as "Error (code N):\n<stderr>"), even when
 *     stderr is empty (e.g. `false`, `test -f missing`): the synthetic detail
 *     "Command exited with status N" is used so a failed command never looks
 *     like a success just because it printed nothing to stderr.
 *   - exit 0 → success, even if stderr is non-empty
 *
 * Exit 0 is treated as success regardless of stderr: the OpenSSH transport
 * surfaces benign diagnostics on stderr (e.g. with the default
 * StrictHostKeyChecking=accept-new, the first connection to a host prints
 * "Warning: Permanently added '<host>' ... to the list of known hosts." while
 * exiting 0). Throwing on any stderr would turn every first-connect into an
 * error. On success the benign OpenSSH host-key warning is filtered out, but
 * any remaining stderr is appended to the text response so callers do not lose
 * useful command diagnostics/progress from tools (git clone, curl, build
 * tools) that write to stderr while succeeding.
 */
/**
 * Strip the benign OpenSSH first-connect host-key notice from a stderr stream,
 * leaving genuine command diagnostics intact. With StrictHostKeyChecking=
 * accept-new the client prints
 *   "Warning: Permanently added '<host>' (<keytype>) to the list of known hosts."
 * on the first connection to a host while still exiting 0; that line is noise,
 * not output the caller asked for.
 */
function stripBenignSshWarnings(stderr: string): string {
  return stderr
    .split('\n')
    .filter(line => !/^Warning: Permanently added .*to the list of known hosts\.?\s*$/.test(line))
    .join('\n')
    .trim();
}
export function resultToMcpContent(result: ExecResult) {
  if (result.category === 'timeout') {
    // Always surface that the command timed out, even when the process wrote to
    // stderr before the deadline. A build/tool that prints progress or
    // diagnostics to stderr and then hangs would otherwise be reported as an
    // ordinary error, hiding the timeout. Keep any captured stderr as trailing
    // context so its diagnostics are not lost.
    const timeoutMsg = `Command execution timed out after ${DEFAULT_TIMEOUT}ms`;
    const detail = result.stderr ? `${timeoutMsg}\n${result.stderr}` : timeoutMsg;
    throw new McpError(ErrorCode.InternalError, detail);
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
  if (result.exitCode !== null && result.exitCode !== 0) {
    const detail = result.stderr || `Command exited with status ${result.exitCode}`;
    throw new McpError(ErrorCode.InternalError, `Error (code ${result.exitCode}):\n${detail}`);
  }
  const diagnostics = stripBenignSshWarnings(result.stderr);
  const text = diagnostics
    ? `${result.stdout}${result.stdout && !result.stdout.endsWith('\n') ? '\n' : ''}${diagnostics}`
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
  version: '2.0.0',
  capabilities: {
    resources: {},
    tools: {},
  },
});

server.tool(
  'exec',
  'Execute a shell command on the remote SSH server and return the output.',
  {
    command: z.string().describe('Shell command to execute on the remote SSH server'),
    description: z.string().optional().describe('Optional description of what this command will do'),
  },
  async ({ command, description }) => {
    const sanitizedCommand = sanitizeCommand(command);
    try {
      const t = await getOrCreateTransport();
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
    'Execute a shell command on the remote SSH server using sudo. Will use sudo password if provided, otherwise assumes passwordless sudo.',
    {
      command: z.string().describe('Shell command to execute with sudo on the remote SSH server'),
      description: z.string().optional().describe('Optional description of what this command will do'),
    },
    async ({ command, description }) => {
      const sanitizedCommand = sanitizeCommand(command);
      try {
        const t = await getOrCreateTransport();
        const commandWithDescription = description
          ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
          : sanitizedCommand;
        const sudoPwd = (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined)
          ? sanitizePassword(SUDOPASSWORD)
          : undefined;
        const result = await t.execElevated(commandWithDescription, {
          timeoutMs: DEFAULT_TIMEOUT,
          mode: 'sudo',
          password: sudoPwd,
        });
        return resultToMcpContent(result);
      } catch (err: any) {
        if (err instanceof McpError) throw err;
        throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
      }
    }
  );
}

// ===========================================================================
// Legacy exports: preserved so existing tests (which import SSHConnectionManager,
// execSshCommandWithConnection, execSshCommand) keep working without modification.
// These call through to Ssh2Transport-equivalent logic or directly to ssh2.
// ===========================================================================

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

// ===========================================================================
// Server lifecycle
// ===========================================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('SSH MCP Server running on stdio');

  const cleanup = () => {
    console.error('Shutting down SSH MCP Server...');
    if (activeTransportCache.activeTransport) {
      void activeTransportCache.activeTransport.close();
      activeTransportCache.activeTransport = null;
      activeTransportCache.initPromise = null;
    }
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => {
    if (activeTransportCache.activeTransport) {
      void activeTransportCache.activeTransport.close();
    }
  });
}

if (isTestMode) {
  const transport = new StdioServerTransport();
  server.connect(transport).catch(error => {
    console.error('Fatal error connecting server:', error);
    process.exit(1);
  });
} else if (isCliEnabled) {
  main().catch((error) => {
    console.error('Fatal error in main():', error);
    if (activeTransportCache.activeTransport) {
      void activeTransportCache.activeTransport.close();
    }
    process.exit(1);
  });
}

export { parseArgv, validateConfig };
