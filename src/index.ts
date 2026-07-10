#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig } from './config/loader.js';
import { resolveCredentials } from './config/credential-resolver.js';
import { ConnectionRegistry } from './ssh/connection-registry.js';
import { PolicyEngine, DEFAULT_RULES } from './policy/engine.js';
import { AuditStore } from './audit/store.js';
import { registerTools } from './tools/registry.js';
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
    commandMaxChars: parseInt(argv.maxChars as string) || 5_000,
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
    tty: false,
    timeout: defaults.commandTimeoutMs,
    maxChars: defaults.commandMaxChars,
    role: 'admin',
    readOnly: false,
    approvalPolicy: argv.disableApproval ? 'auto' : 'ask-destructive',
    cert: false,
    sessionMaxPerConnection: defaults.sessionMaxPerConnection,
    sessionIdleTimeoutMs: defaults.sessionIdleTimeoutMs,
  };

  return { defaults, profiles: [profile] };
}

async function main() {
  const argv = parseArgv();
  const config = await buildAppConfig(argv);
  const hostKeyMode: HostKeyMode = argv.insecureHostKey ? 'insecure' : 'tofu';
  const entropyScan = !!argv.auditEntropyScan;
  const tamperEvident = !!argv.auditTamperEvident;

  const { initKeychain } = await import('./config/credential-resolver.js');
  await initKeychain();

  const registry = new ConnectionRegistry(config, hostKeyMode);
  const policy = new PolicyEngine(DEFAULT_RULES);
  const audit = new AuditStore(undefined, entropyScan, tamperEvident);

  const server = new McpServer({
    name: 'SSH MCP Server',
    version: '2.0.0',
    capabilities: {
      tools: {},
      resources: {},
    },
  });

  registerTools(server, registry, policy, audit);

  if (argv.opaUrl) {
    policy.setOpaUrl(argv.opaUrl);
    console.error(`OPA sidecar enabled: ${argv.opaUrl}`);
  }

  const transportMode = argv.transport || 'stdio';

  if (transportMode === 'http') {
    const { startHttpServer } = await import('./transport/http.js');
    await startHttpServer(server, {
      port: parseInt(argv.httpPort as string) || 3000,
      host: (argv.httpHost as string) || '127.0.0.1',
      bearerToken: argv.bearerToken as string | undefined,
      registry,
      audit,
    });
  } else {
    const transport = new StdioServerTransport();
    await server.connect(transport);
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
    await registry.closeAll();
    process.exit(0);
  };

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

export { parseArgv, buildAppConfig };
