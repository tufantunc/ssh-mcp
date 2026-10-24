#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { reportFatal, OperatorError } from './errors.js';
import { ConnectionRegistry } from './ssh/connection-registry.js';
import { PolicyEngine, resolvePolicyRules } from './policy/engine.js';
import { AuditStore } from './audit/store.js';
import { registerTools, registerResources, getToolHashes } from './tools/registry.js';
import { transferForbiddenDirs } from './tools/forbidden-dirs.js';
import { initKeychain } from './config/credential-resolver.js';
import { getConfigPath } from './config/loader.js';
import { SERVER_VERSION } from './version.js';
import { reapOnce } from './ssh/reaper.js';
import { ConfigReloader, installSighupReload } from './config/reload.js';
import {
  parseArgv,
  loadAppConfig,
  aclOptionsFromArgv,
  checkRemovedFlags,
  flagEnabled,
  parseFailureLimit,
  parseHttpSessionTtl,
  parseOpaUrl,
  parseOpaTimeout,
  resolveHostKeyMode,
} from './cli.js';

async function main() {
  const argv = parseArgv();
  checkRemovedFlags(argv);

  if (argv.dumpToolHashes !== undefined) {
    console.log(JSON.stringify(getToolHashes(), null, 2));
    return;
  }

  // The whole of it, not just `config`: the reloader needs to know where the live config
  // came from, its hash and when it was loaded.
  // The ACL posture, once: startup's load and every reload check the file with it.
  const aclOptions = aclOptionsFromArgv(argv);
  const startup = await loadAppConfig(argv, aclOptions);
  const { config } = startup;
  const hostKeyMode = resolveHostKeyMode(argv);
  const entropyScan = flagEnabled(argv, 'auditEntropyScan');
  const tamperEvident = flagEnabled(argv, 'auditTamperEvident');

  await initKeychain();

  if (argv.otelEndpoint) {
    const { initTracing } = await import('./observability/tracer.js');
    await initTracing(argv.otelEndpoint as string, (argv.otelServiceName as string) || 'ssh-mcp');
  }

  // Everything the transfer-root gate needs that it must not reach for itself:
  // which config file was actually loaded, and which directories are off limits.
  const localPath = {
    transferRoot: config.defaults.transferRoot,
    configPath: getConfigPath(argv.config || undefined),
    forbidden: transferForbiddenDirs(),
  };

  const registry = new ConnectionRegistry(config, hostKeyMode);
  const policy = new PolicyEngine(resolvePolicyRules(config.profiles, config.policy));
  const audit = new AuditStore(undefined, entropyScan, tamperEvident);

  if ('opaUrl' in argv) {
    // Presence, not truthiness — the trap `flagEnabled` was written for. A
    // space-separated `--opaUrl http://…` stores null, so the old guard dropped it
    // silently, and dropped any `--opaFailClosed` the operator asked for with it.
    policy.setOpaUrl(
      parseOpaUrl(argv.opaUrl),
      flagEnabled(argv, 'opaFailClosed'),
      parseOpaTimeout(argv.opaTimeoutMs),
    );
    console.error(`OPA sidecar enabled: ${argv.opaUrl}`);
  } else if (flagEnabled(argv, 'opaFailClosed')) {
    throw new OperatorError('--opaFailClosed does nothing without --opaUrl.');
  }

  // One reloader for the process: every MCP server below (one under stdio, one per HTTP
  // session) reloads the same registry, policy and transfer root, and the reloader
  // serializes them.
  const reloader = new ConfigReloader({ aclOptions, registry, policy, audit, localPath, startup });

  // An McpServer binds to a single transport, so HTTP needs one per session.
  const createMcpServer = (): McpServer => {
    // capabilities moved from serverInfo to ServerOptions in SDK 1.30.
    const server = new McpServer(
      { name: 'SSH MCP Server', version: SERVER_VERSION },
      { capabilities: { tools: {}, resources: {} } },
    );
    registerTools(server, registry, policy, audit, { localPath, reloader });
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
      sessionIdleTtlMs: parseHttpSessionTtl(argv.httpSessionTtl),
      authFailureLimit: parseFailureLimit(argv.authFailureLimit),
      trustProxy: flagEnabled(argv, 'trustProxy'),
      trustedProxies: (argv.trustedProxies as string)?.split(',').map((h) => h.trim()).filter(Boolean),
      allowedHosts: (argv.allowedHosts as string)?.split(',').map((h) => h.trim()).filter(Boolean),
      registry,
    });
  } else {
    const transport = new StdioServerTransport();
    await createMcpServer().connect(transport);
    console.error('SSH MCP Server v2 running on stdio');
  }

  const reaperInterval = setInterval(() => {
    // Session-then-connection ordering (load-bearing) is documented in `reapOnce`.
    void reapOnce(registry).catch((err) => console.error('reaper failed:', err));
  }, 60_000);

  /**
   * How long teardown gets before the process exits regardless.
   *
   * One kill ladder (3s) plus slack. Sessions and connections close concurrently, so this
   * is the whole budget rather than a per-session one. Docker's default stop grace is 10s
   * and Kubernetes' is 30s, so this stays comfortably inside both — the point is that we
   * choose the moment we give up rather than being SIGKILLed in the middle of it.
   */
  const SHUTDOWN_BUDGET_MS = 5000;

  let isShuttingDown = false;
  const cleanup = async () => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.error('Shutting down SSH MCP Server...');
    clearInterval(reaperInterval);
    // Audit first. An earlier version of this comment claimed session teardown wrote audit
    // records that the old order dropped — it does not: nothing under src/ssh/ touches the
    // audit store, only the `close-session` tool does, and that record is written and
    // awaited during the tool call. So the reorder rescued nothing and put the final flush
    // behind a teardown that now waits for kill ladders. Flushing first cannot lose a record
    // that teardown does not write, and it survives a SIGKILL at the end of the grace period.
    try { await audit.close(); } catch (e) { console.error('audit.close failed:', e); }
    // Bounded, so `process.exit(0)` is reached deliberately rather than by the container
    // runtime's SIGKILL. Teardown is concurrent now, so the honest ceiling is one kill
    // ladder plus slack rather than one per session.
    try {
      await Promise.race([
        registry.closeAll(),
        new Promise((resolve) => setTimeout(resolve, SHUTDOWN_BUDGET_MS).unref()),
      ]);
    } catch (e) { console.error('closeAll failed:', e); }
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
  // Before this, SIGHUP's default action killed the process without flushing the audit
  // log. Now it reloads the config, except on Windows; see installSighupReload.
  installSighupReload(reloader);
}

const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';

if (isCliEnabled || isTestMode) {
  main().catch((error) => {
    process.exit(reportFatal(error));
  });
}
