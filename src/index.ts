#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig, getConfigPath } from './config/loader.js';
import { OperatorError, ConfigNotFoundError, reportFatal } from './errors.js';
import type { AclFinding } from './config/windows-acl.js';
import { ConnectionRegistry } from './ssh/connection-registry.js';
import { PolicyEngine, HOST_GROUPS, resolvePolicyRules } from './policy/engine.js';
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
 * Whether a boolean flag was passed at all.
 *
 * `parseArgv` stores `null` for a flag written without `=`, which is how every
 * documented boolean flag is written. Testing that value for truthiness makes
 * the flag a no-op: `--disableApproval`, `--auditEntropyScan` and
 * `--auditTamperEvident` all did nothing unless spelled `--flag=1`, which
 * nothing documents (#91). The two call sites that got it right already used
 * `!== undefined`; this gives the check a name so the next one cannot miss it.
 *
 * `--flag=false` and `--flag=0` turn it off, because a flag that cannot be
 * turned off once written into a wrapper script is its own annoyance.
 */
function flagEnabled(argv: Record<string, string | null>, name: string): boolean {
  if (!(name in argv)) return false;
  const value = argv[name];
  if (value === null || value === '') return true;
  return !['false', '0', 'no', 'off'].includes(value.toLowerCase());
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
  throw new OperatorError(
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
  if (flagEnabled(argv, 'insecureHostKey')) return 'insecure';
  const mode = argv.hostKeyMode;
  if (mode === null || mode === undefined) return 'tofu';
  if (mode === 'tofu' || mode === 'strict' || mode === 'insecure') return mode;
  throw new OperatorError(`Invalid --hostKeyMode=${mode}. Expected one of: tofu, strict, insecure.`);
}

/**
 * Which policy tier a CLI-configured host belongs to.
 *
 * Without this there was no way to say it from the command line at all. The
 * inline profile carries no group, so it fell to the strictest tier, where the
 * `admin` role has no `privileged` — meaning `sudo` could never run for anyone
 * who had not written a config file (#91).
 *
 * The default stays `prod`. Guessing an unknown host is production is the safe
 * direction; what was missing was a way to correct the guess.
 */
export function resolveHostGroup(argv: Record<string, string | null>): string {
  const group = argv.group;
  if (group === null || group === undefined) return 'prod';
  if ((HOST_GROUPS as readonly string[]).includes(group)) return group;
  // Falling through would silently apply the prod bindings to a typo, and the
  // operator would read the refusal as policy rather than as their own slip.
  throw new OperatorError(
    `Invalid --group=${group}. Expected one of: ${HOST_GROUPS.join(', ')}.`,
  );
}

/**
 * Every ACL finding, in the order it happened — both "readable beyond its owner" and
 * "could not be checked".
 *
 * Collected rather than only printed so `main()` can act on them once there is somewhere
 * durable to put them; see the note at the sink below.
 */
const aclFindings: AclFinding[] = [];

async function buildAppConfig(argv: Record<string, string | null>): Promise<AppConfig> {
  // The way past an ACL that could not be read, rather than an operator with no
  // exit. See assertPrivateOnWindows.
  // The sink is supplied here rather than left to the module's default, which is the
  // point of having one: "this security check did not run" is a decision about what the
  // operator must be told, and the loader is not the layer that owns that. Routing it to
  // the audit store as well needs an AuditRecord variant for a startup event — that type
  // is hash-chained and tamper-evident, so it is its own change, and it is queued.
  const aclOpts = {
    enforce: flagEnabled(argv, 'strictConfigAcl'),
    allowUnchecked: flagEnabled(argv, 'allowUncheckedConfigAcl'),
    onFinding: (f: AclFinding) => {
      aclFindings.push(f);
      console.error(`Warning: ${f.message}`);
    },
  };

  if (argv.config !== undefined) {
    // `parseArgv` stores null for a flag written without `=`, so a bare `--config` used to
    // be falsy here and fall into the default-path branch — which now refuses rather than
    // silently ignoring an unusable file, so the operator got a refusal naming a path they
    // never asked for.
    if (argv.config === null || argv.config === '') {
      throw new OperatorError('--config needs a path: --config=<path>');
    }
    return loadConfig(argv.config, aclOpts);
  }

  try {
    const fromFile = await loadConfig(undefined, aclOpts);
    // Before #138 every Windows config was rejected by the mode-bit check and
    // the rejection was swallowed, so an operator who also passed --host/--user
    // was silently running off the flags. Now that the file loads, it takes
    // precedence — a flip worth one line rather than a surprise about which host
    // a command reached.
    if (argv.host || argv.user) {
      console.error(
        `Note: ${getConfigPath()} was loaded, so --host/--user are ignored. ` +
        'Pass --config <path> to choose a different file.',
      );
    }
    return fromFile;
  } catch (err) {
    // Only "there is no file" means fall through. A file that exists and is
    // unusable — malformed TOML, a schema violation, a permission failure —
    // used to be swallowed here too and reported as a missing config, which is
    // how #138 stayed unfindable: the operator's file was in the right place,
    // and the real error was discarded before anyone could read it.
    //
    // Falling through would also be wrong on its own terms whenever
    // --host/--user happen to be present: the server would start, silently
    // ignoring every profile, policy and role binding the operator wrote.
    if (!(err instanceof ConfigNotFoundError)) throw err;
  }

  if (!argv.host || !argv.user) {
    throw new OperatorError(
      'No config file found and missing required --host/--user.\n' +
      // Was hardcoded to ~/.config/ssh-mcp/config.toml on every platform, so on
      // Windows and macOS it named a path this code never reads.
      `Either create a config file at ${getConfigPath()} or pass --config <path>.\n` +
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
    commandQuotaPerDay: parseInt(argv.commandQuota as string) || 0,
    approvalGrantTtlMs: parseInt(argv.approvalGrantTtl as string) || 0,
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
    group: resolveHostGroup(argv),
    readOnly: false,
    approvalPolicy: flagEnabled(argv, 'disableApproval') ? 'auto' : defaults.approvalMode,
    cert: false,
    sessionMaxPerConnection: defaults.sessionMaxPerConnection,
    sessionIdleTimeoutMs: defaults.sessionIdleTimeoutMs,
    sessionBackgroundMaxMs: defaults.sessionBackgroundMaxMs,
    commandQuotaPerDay: defaults.commandQuotaPerDay,
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
  const entropyScan = flagEnabled(argv, 'auditEntropyScan');
  const tamperEvident = flagEnabled(argv, 'auditTamperEvident');

  await initKeychain();

  if (argv.otelEndpoint) {
    const { initTracing } = await import('./observability/tracer.js');
    await initTracing(argv.otelEndpoint as string, (argv.otelServiceName as string) || 'ssh-mcp');
  }

  const registry = new ConnectionRegistry(config, hostKeyMode);
  const policy = new PolicyEngine(resolvePolicyRules(config.profiles, config.policy));
  const audit = new AuditStore(undefined, entropyScan, tamperEvident);

  if (argv.opaUrl) {
    policy.setOpaUrl(argv.opaUrl);
    console.error(`OPA sidecar enabled: ${argv.opaUrl}`);
  }

  // An McpServer binds to a single transport, so HTTP needs one per session.
  const createMcpServer = (): McpServer => {
    // capabilities moved from serverInfo to ServerOptions in SDK 1.30.
    const server = new McpServer(
      { name: 'SSH MCP Server', version: SERVER_VERSION },
      { capabilities: { tools: {}, resources: {} } },
    );
    registerTools(server, registry, policy, audit, {
      approvalGrantTtlMs: config.defaults.approvalGrantTtlMs,
    });
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
      allowedHosts: (argv.allowedHosts as string)?.split(',').map((h) => h.trim()).filter(Boolean),
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
    process.exit(reportFatal(error));
  });
}

export { parseArgv, buildAppConfig, checkRemovedFlags, parseMaxChars, flagEnabled, resolveHostKeyMode };
