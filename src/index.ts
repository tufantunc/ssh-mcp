#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig } from './config/loader.js';
import { resolveCredentials } from './config/credential-resolver.js';
import { ConnectionRegistry } from './ssh/connection-registry.js';
import { PolicyEngine, DEFAULT_RULES } from './policy/engine.js';
import { AuditStore } from './audit/store.js';
import { registerTools, registerResources, getToolHashes } from './tools/registry.js';
import { initKeychain } from './config/credential-resolver.js';
import { SERVER_VERSION } from './version.js';
import type { HostKeyMode } from './ssh/host-key.js';
import type { AppConfig, Profile, Defaults } from './types.js';

function parseArgv(): Record<string, string | null> {
  const args = process.argv.slice(2);
  const config: Record<string, string | null> = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq === -1) {
        config[arg.slice(2)] = null;
      } else {
        config[arg.slice(2, eq)] = arg.slice(eq + 1);
      }
    }
  }
  return config;
}

/**
 * v1 flags that v2 removed. Silently ignoring them means the user only finds
 * out at the first command, as an auth failure with no hint about the cause.
 */
const REMOVED_V1_FLAGS: Record<string, string> = {
  password: 'Use the SSH_MCP_PASSWORD env var (or a per-profile SSH_MCP_<PROFILE>_PASSWORD).',
  suPassword: 'Use the SSH_MCP_SUDO_PASSWORD env var.',
  sudoPassword: 'Use the SSH_MCP_SUDO_PASSWORD env var.',
  disableSudo: 'Sudo is now a separate tool; restrict it with a role/policy that disallows the "privileged" class.',
};

function checkRemovedFlags(argv: Record<string, string | null>): void {
  const found = Object.keys(REMOVED_V1_FLAGS).filter((f) => f in argv);
  if (found.length === 0) return;
  throw new Error(
    'These flags were removed in v2:\n' +
    found.map((f) => `  --${f}: ${REMOVED_V1_FLAGS[f]}`).join('\n') +
    '\nSee the "Migrating from v1" section of the README.',
  );
}

/**
 * v1 documented `--maxChars=none` (and 0/negative) as "no limit". Parsing it
 * with `parseInt(...) || 5000` silently turned that into a 5000-char cap.
 */
function parseMaxChars(raw: string | null | undefined): number {
  if (typeof raw !== 'string' || raw === '') return 5_000;
  if (raw.toLowerCase() === 'none') return Number.MAX_SAFE_INTEGER;
  const parsed = parseInt(raw);
  if (isNaN(parsed)) return 5_000;
  return parsed <= 0 ? Number.MAX_SAFE_INTEGER : parsed;
}

/**
 * `strict` was previously unreachable: nothing but test code could select it,
 * yet host-key.ts pointed users at a `--acceptNewHostKey` flag that never
 * existed. `--insecureHostKey` is kept as an alias for the documented flag.
 */
function resolveHostKeyMode(argv: Record<string, string | null>): HostKeyMode {
  if (argv.insecureHostKey !== undefined) return 'insecure';
  const mode = argv.hostKeyMode;
  if (mode === null || mode === undefined) return 'tofu';
  if (mode === 'tofu' || mode === 'strict' || mode === 'insecure') return mode;
  throw new Error(`Invalid --hostKeyMode=${mode}. Expected one of: tofu, strict, insecure.`);
}

async function buildAppConfig(argv: Record<string, string | null>): Promise<AppConfig> {
  if (argv.config) {
    return loadConfig(argv.config);
  }

  try {
    return await loadConfig();
  } catch {
    // No config file — fall through to CLI args
  }

  if (!argv.host || !argv.user) {
    throw new Error(
      'No config file found and missing required --host/--user.\n' +
      'Either create a config file at ~/.config/ssh-mcp/config.toml or pass --config <path>.\n' +
      'For quick start: --host=<host> --user=<user> (credentials via env vars).',
    );
  }

  const defaults: Defaults = {
    sessionMaxPerConnection: parseInt(argv.sessionMax as string) || 5,
    sessionIdleTimeoutMs: parseInt(argv.sessionTtl as string) || 600_000,
    sessionBackgroundMaxMs: 3_600_000,
    commandTimeoutMs: parseInt(argv.timeout as string) || 60_000,
    commandMaxChars: parseMaxChars(argv.maxChars),
    commandMaxOutputBytes: 1_048_576,
    connectionIdleReapMs: 900_000,
    approvalMode: 'ask-destructive',
  };

  const profile: Profile = {
    name: 'default',
    host: argv.host,
    port: parseInt(argv.port as string) || 22,
    user: argv.user,
    auth: argv.key ? 'key' : 'password',
    keyRef: argv.key || undefined,
    workdir: argv.workdir || undefined,
    tty: false,
    timeout: defaults.commandTimeoutMs,
    maxChars: defaults.commandMaxChars,
    maxOutputBytes: defaults.commandMaxOutputBytes,
    role: 'admin',
    readOnly: false,
    approvalPolicy: argv.disableApproval ? 'auto' : defaults.approvalMode,
    cert: false,
    sessionMaxPerConnection: defaults.sessionMaxPerConnection,
    sessionIdleTimeoutMs: defaults.sessionIdleTimeoutMs,
    sessionBackgroundMaxMs: defaults.sessionBackgroundMaxMs,
  };

  return { defaults, profiles: [profile] };
}

async function main() {
  const argv = parseArgv();
  checkRemovedFlags(argv);

  if (argv.dumpToolHashes !== undefined) {
    console.log(JSON.stringify(getToolHashes(), null, 2));
    return;
  }

  const config = await buildAppConfig(argv);
  const hostKeyMode = resolveHostKeyMode(argv);
  const entropyScan = !!argv.auditEntropyScan;
  const tamperEvident = !!argv.auditTamperEvident;

  await initKeychain();

  if (argv.otelEndpoint) {
    const { initTracing } = await import('./observability/tracer.js');
    await initTracing(argv.otelEndpoint as string, (argv.otelServiceName as string) || 'ssh-mcp');
  }

  const registry = new ConnectionRegistry(config, hostKeyMode);
  const policy = new PolicyEngine(DEFAULT_RULES);
  const audit = new AuditStore(undefined, entropyScan, tamperEvident);

  if (argv.opaUrl) {
    policy.setOpaUrl(argv.opaUrl);
    console.error(`OPA sidecar enabled: ${argv.opaUrl}`);
  }

  // An McpServer binds to a single transport, so HTTP needs one per session.
  const createMcpServer = (): McpServer => {
    const server = new McpServer({
      name: 'SSH MCP Server',
      version: SERVER_VERSION,
      capabilities: {
        tools: {},
        resources: {},
      },
    });
    registerTools(server, registry, policy, audit);
    registerResources(server, registry);
    return server;
  };

  const transportMode = argv.transport || 'stdio';

  if (transportMode === 'http') {
    const { startHttpServer } = await import('./transport/http.js');
    await startHttpServer(createMcpServer, {
      port: parseInt(argv.httpPort as string) || 3000,
      host: (argv.httpHost as string) || '127.0.0.1',
      bearerToken: argv.bearerToken as string | undefined,
      rateLimit: parseInt(argv.rateLimit as string) || 0,
      registry,
    });
  } else {
    const transport = new StdioServerTransport();
    await createMcpServer().connect(transport);
    console.error('SSH MCP Server v2 running on stdio');
  }

  const reaperInterval = setInterval(() => {
    for (const info of registry.listConnections()) {
      const conn = registry.get(info.profile);
      if (conn) {
        conn.reapExpiredSessions();
      }
    }
    registry.reapIdleConnections();
  }, 60_000);

  let isShuttingDown = false;
  const cleanup = async () => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.error('Shutting down SSH MCP Server...');
    clearInterval(reaperInterval);
    try { await audit.close(); } catch (e) { console.error('audit.close failed:', e); }
    try { await registry.closeAll(); } catch (e) { console.error('closeAll failed:', e); }
    process.exit(0);
  };

  if (transportMode !== 'http') {
    // The SDK's stdio transport listens only for 'data' and 'error', so a
    // client that exits without signalling leaves this process running with
    // its SSH connections open. Treat EOF on stdin as the client going away.
    const onStdinClosed = () => { void cleanup(); };
    process.stdin.on('end', onStdinClosed);
    process.stdin.on('close', onStdinClosed);
  }

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';

if (isCliEnabled || isTestMode) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export { parseArgv, buildAppConfig, checkRemovedFlags, parseMaxChars };
