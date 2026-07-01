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
import type { ResolvedConfig, ApprovalMode } from './config/types.js';
import {
  sanitizeCommand as sanitizeCommandImpl,
  sanitizePassword,
  escapeCommandForShell,
} from './utils/shell.js';
import {
  gateApproval,
  getApprovalDecisionFromError,
  setApprovalEngine,
  buildApprovalEngineFromConfig,
  type ApprovalDecision,
  type BuildEngineFromConfigInput,
  type ApprovalDispatcher,
  type ResolvedSource,
} from './approval/index.js';
import { loadAuditSink, type AuditSink } from './approval/audit-seam.js';

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
const CONFIG_PATH = argvConfig.config;

// Flags that signal intent to use the legacy single-host CLI mode. NOTE:
// `disableSudo` is deliberately excluded — it only controls whether the sudo
// tool is registered and is valid across ALL modes (multi-host --ssh and TOML
// --config included). Treating it as a legacy trigger made
// `--config cfg.toml --disableSudo` route through validateConfig(false) and
// wrongly demand --host/--user. `port` stays here because it is only
// meaningful as part of a single-host source.
const legacyFlagNames = [
  'host', 'user', 'password', 'key', 'kerberos', 'transport',
  'strictHostKeyChecking', 'knownHostsFile', 'gssapiDelegateCredentials',
  'suPassword', 'sudoPassword', 'port',
] as const;

export function hasLegacyCliFlags(config: Record<string, string | null>): boolean {
  return legacyFlagNames.some(f => config[f] !== undefined);
}

function validateConfig(config: Record<string, string | null>, multiHost = false) {
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
    // A value-less `--transport` is recorded as `null` by parseArgv; the nullish
    // fallback below would treat it as absent and silently run the default ssh2
    // transport, so a mistyped OpenSSH selection would run the wrong transport.
    // Reject a present-but-value-less --transport like the other value-requiring
    // flags.
    if ('transport' in config && transportExplicit == null) {
      errors.push('--transport requires a value (ssh2 or openssh)');
    }
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
    // GSSAPIDelegateCredentials is only emitted by the OpenSSH transport in the
    // Kerberos auth branch (see OpenSshTransport.buildArgs). Accepting the flag
    // without --kerberos would let a user request credential delegation while the
    // server silently omits it, breaking second-hop SSO with no error. Require
    // Kerberos auth so the requested delegation is actually honored.
    if ('gssapiDelegateCredentials' in config && !kerberos) {
      errors.push('--gssapiDelegateCredentials requires --kerberos');
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
  : { sources: [], perSourceApproval: {}, defaultExplicit: false };

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
  // Unified bootstrap (toml-config design): resolvedConfig.sources already
  // carries every registered host — multi-host --ssh JSON, the legacy
  // single-host config, and any [[sources]] from a TOML — built by
  // resolveConfig(). Iterate it as the single source of truth. The
  // kerberos>password>key precedence and gated key read from PR #2/#3 are
  // preserved here via buildLegacyServerConfig (uses resolveAuthMode) plus the
  // authMode-gated prepareKeyContents below.
  for (const cfg of resolvedConfig.sources) {
    await prepareKeyContents(cfg);
    registry.register(cfg);
  }
  applyRegistryConnectionPolicy(registry, resolvedConfig);
}

/**
 * Wire the resolved connection policy onto a registry whose sources are already
 * registered. Split out (and exported) so the explicit-default / fallback /
 * require_connection opt-out matrix is unit-testable without booting the server.
 *
 * Two independent knobs:
 *  - defaultExplicit: call setDefault() ONLY when the user explicitly chose a
 *    default. Falling through to register()'s first-registered fallback leaves
 *    the registry's defaultExplicit=false, so a multi-source config with no
 *    explicit default still rejects an omitted connectionName (the headline
 *    security fix) instead of silently routing to the first host.
 *  - requireConnection: when false, opt out of that guard entirely. Absent the
 *    field (older ResolvedConfig shape / no [server].require_connection) it
 *    defaults to safe (guard ON).
 */
export function applyRegistryConnectionPolicy(
  reg: Pick<TransportRegistry, 'setDefault' | 'setRequireConnectionWhenMulti'>,
  config: ResolvedConfig,
): void {
  const requireConnection = config.requireConnection ?? true;
  reg.setRequireConnectionWhenMulti(requireConnection);
  if (config.defaultExplicit && config.defaultName) {
    reg.setDefault(config.defaultName);
  }
}

export function buildApprovalProfile(
  id: string,
  perSourceApproval: Record<string, ApprovalMode> = {},
  source?: { description?: string },
): ResolvedSource {
  const mode = perSourceApproval[id];
  return {
    id,
    ...(source?.description ? { description: source.description } : {}),
    ...(mode ? { approval: { mode } } : {}),
  };
}

export function appendDescriptionComment(command: string, description?: string): string {
  if (!description) return command;
  const safeDescription = description
    .replace(/[\r\n]+/g, ' ')
    .replace(/[\t\f\v ]+/g, ' ')
    .trim();
  return safeDescription ? `${command} # ${safeDescription}` : command;
}

// =============================================================================
// Approval engine + OPTIONAL audit-truth seam (Decision D2).
//
// The approval engine is the source of truth for whether a command runs. The
// audit seam is OPTIONAL: when `src/audit/` is part of the build it logs the
// real decision; when absent (e.g. on `pr/toml-config`, this lane's base) it
// no-ops. `auditSink` starts as a no-op so the exec/sudo-exec handlers can call
// it unconditionally; `wireApprovalAndAudit()` upgrades it at boot.
// =============================================================================

let auditSink: AuditSink = { record() { /* no-op until wired (or audit absent) */ } };

/**
 * Build the production approval engine from resolvedConfig. Returns null for
 * the legacy CLI path (no [approval] section and no per-source overrides) so
 * the gate keeps its backward-compatible `legacy:no-engine` allow.
 *
 * Throws (fatal at boot):
 *   - manual mode requested but WebUI disabled (gate-12 invariant)
 *   - smart mode requested but [approval.llm] missing endpoint or model
 */
function buildProductionApprovalEngine(webuiActive: boolean): ApprovalDispatcher | null {
  const approvalCfg = resolvedConfig.approval;
  const perSourceModes: ApprovalMode[] = Object.values(resolvedConfig.perSourceApproval ?? {});
  if (approvalCfg === undefined && perSourceModes.length === 0) {
    return null;
  }
  const input: BuildEngineFromConfigInput = {
    // Resolve the GLOBAL default mode:
    //  - explicit [approval].mode set        -> honor it.
    //  - no global mode, per-source overrides -> the [approval] block (when
    //    present at all) exists only to host [approval.llm] for a per-source
    //    smart override; keep the global default 'yolo' (unrestricted) so only
    //    the overridden sources are gated. Defining [approval.llm] for a
    //    per-source `mode = "smart"` makes resolvedConfig.approval non-undefined
    //    even though no global mode was requested, so keying solely on
    //    `approvalCfg === undefined` would wrongly fall through to manual here
    //    and gate every ungated host (or throw at boot with WebUI off). This
    //    also covers the no-[approval]-block case (per-source overrides only).
    //  - no global mode and no per-source overrides -> a bare [approval] block
    //    (e.g. `fail_closed = true`, or `[approval.llm]` alone) was added
    //    deliberately to enable approval; leave defaultMode undefined so
    //    buildApprovalEngineFromConfig applies the documented 'manual' default.
    defaultMode:
      approvalCfg?.mode !== undefined
        ? approvalCfg.mode
        : perSourceModes.length > 0
          ? 'yolo'
          : undefined,
    fail_closed: approvalCfg?.fail_closed,
    llm: approvalCfg?.llm,
    perSourceModes,
  };
  return buildApprovalEngineFromConfig(input, {
    manualOpts: { webuiEnabled: webuiActive },
  });
}

/** Decide whether the WebUI will be active at boot (TOML or --webui). */
function isWebUIActive(): boolean {
  // `--webui` (bare flag) parses to a key present in argvConfig. The WebUI
  // server itself lands in a later lane; here we only need the boot-time
  // decision so manual-mode's gate-12 invariant resolves correctly.
  const cliWebui = 'webui' in argvConfig;
  return cliWebui || resolvedConfig.webui?.enabled === true;
}

/**
 * Wire the approval engine into the gate and load the optional audit sink.
 * Safe to call before the MCP transport connects so the first exec is gated.
 */
async function wireApprovalAndAudit(): Promise<void> {
  const engine = buildProductionApprovalEngine(isWebUIActive());
  setApprovalEngine(engine);
  auditSink = await loadAuditSink({
    auditDir: resolvedConfig.server?.audit_dir,
    auditMaxBytes: resolvedConfig.server?.audit_max_bytes,
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
    const commandWithDescription = appendDescriptionComment(sanitizedCommand, description);
    // Audit attribution starts as unresolved and is pinned to the canonical
    // host name via registry.profile() — a pure name resolution that does NOT
    // connect. Pinning it BEFORE registry.get() (which lazily inits the
    // transport and can reject on bad credentials, host-key rejection, or an
    // unreachable host) keeps pre-command init failures audited under the real
    // host identity when the target is unambiguous. When the name is genuinely
    // ambiguous/unknown (omitted connectionName in multi-host mode without an
    // explicit default, or an unregistered name) registry.profile() throws and
    // the audit keeps the raw '(unresolved)'/bad-name attribution. A
    // blank/whitespace name is treated as omitted, mirroring
    // TransportRegistry.resolveName().
    let profile = connectionName && connectionName.trim() !== '' ? connectionName : '(unresolved)';
    // Fallback timestamp for errors raised before the transport call (registry
    // init failure, approval deny). Re-captured immediately before t.exec below
    // so a SUCCESSFUL command's audit durationMs measures command runtime only,
    // not SSH init + approval wait time.
    let startedAt = Date.now();
    let audited = false;
    let approvalDecision: ApprovalDecision | undefined;
    try {
      const resolvedProfile = registry.profile(connectionName);
      profile = resolvedProfile.id;
      const t = await registry.get(connectionName);
      approvalDecision = await gateApproval({
        profile: resolvedProfile,
        tool: 'exec',
        command: commandWithDescription,
        description,
      });
      startedAt = Date.now();
      const result = await t.exec(commandWithDescription, { timeoutMs: DEFAULT_TIMEOUT });
      auditSink.record({
        tool: 'exec',
        profile,
        command: commandWithDescription,
        description,
        startedAt,
        result,
        approval: approvalDecision,
      });
      audited = true;
      return resultToMcpContent(result);
    } catch (err: any) {
      approvalDecision = approvalDecision ?? getApprovalDecisionFromError(err);
      if (!audited) auditSink.record({
        tool: 'exec',
        profile,
        command: commandWithDescription,
        description,
        startedAt,
        error: err,
        approval: approvalDecision,
      });
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
      const commandWithDescription = appendDescriptionComment(sanitizedCommand, description);
      // Audit attribution starts as unresolved and is pinned to the canonical
      // host name via registry.profile() — a pure name resolution that does NOT
      // connect. Pinning it BEFORE registry.get() (which lazily inits the
      // transport and can reject on bad credentials, host-key rejection, or an
      // unreachable host) keeps pre-command init failures audited under the real
      // host identity when the target is unambiguous. When the name is genuinely
      // ambiguous/unknown (omitted connectionName in multi-host mode without an
      // explicit default, or an unregistered name) registry.profile() throws and
      // the audit keeps the raw '(unresolved)'/bad-name attribution. A
      // blank/whitespace name is treated as omitted, mirroring
      // TransportRegistry.resolveName().
      let profile = connectionName && connectionName.trim() !== '' ? connectionName : '(unresolved)';
      // Fallback timestamp for errors raised before the transport call (registry
      // init failure, approval deny). Re-captured immediately before
      // t.execElevated below so a SUCCESSFUL command's audit durationMs measures
      // command runtime only, not SSH init + approval wait time.
      let startedAt = Date.now();
      let audited = false;
      let approvalDecision: ApprovalDecision | undefined;
      try {
        const resolvedProfile = registry.profile(connectionName);
        profile = resolvedProfile.id;
        const t = await registry.get(connectionName);
        approvalDecision = await gateApproval({
          profile: resolvedProfile,
          tool: 'sudo-exec',
          command: commandWithDescription,
          description,
        });
        // Legacy single-host mode may still pass --sudoPassword on CLI; in
        // multi-host mode each ServerConfig carries its own sudoPassword.
        const legacySudo = (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined && !isMultiHost)
          ? sanitizePassword(SUDOPASSWORD)
          : undefined;
        startedAt = Date.now();
        const result = await t.execElevated(commandWithDescription, {
          timeoutMs: DEFAULT_TIMEOUT,
          mode: 'sudo',
          password: legacySudo,
        });
        auditSink.record({
          tool: 'sudo-exec',
          profile,
          command: commandWithDescription,
          description,
          startedAt,
          result,
          approval: approvalDecision,
        });
        audited = true;
        return resultToMcpContent(result);
      } catch (err: any) {
        approvalDecision = approvalDecision ?? getApprovalDecisionFromError(err);
        if (!audited) auditSink.record({
          tool: 'sudo-exec',
          profile,
          command: commandWithDescription,
          description,
          startedAt,
          error: err,
          approval: approvalDecision,
        });
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
  // Boot the approval engine + optional audit seam BEFORE the MCP transport so
  // the very first exec / sudo-exec call is gated and (optionally) audited.
  await wireApprovalAndAudit();
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
    try {
      await wireApprovalAndAudit();
    } catch { /* tests may not configure an approval engine */ }
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
