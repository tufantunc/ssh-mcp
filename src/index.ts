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
import { startConfigWatcher } from './config/config-watcher.js';
import { ConfigReloader } from './config/reloader.js';
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
import { startWebUI } from './webui/server.js';
import type {
  ManualApprovalQueue,
  PendingApproval as WebUIPendingApproval,
  ApprovalDecision as WebUIApprovalDecision,
  AuditTail as WebUIAuditTail,
  ModeController as WebUIModeController,
  SourceController as WebUISourceController,
  SourceUpdatedEvent as WebUISourceUpdatedEvent,
  ConfigReloadController as WebUIConfigReloadController,
} from './webui/types.js';

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
  if (typeof obj.description === 'string') cfg.description = obj.description;

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
  if (resolvedConfig.defaultName) {
    registry.setDefault(resolvedConfig.defaultName);
  }
}

/** Effective profile/connection name for gating + audit attribution. */
function resolvedProfileName(connectionName?: string): string {
  return connectionName ?? registry.getDefaultName() ?? 'default';
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

let approvalEngine: ApprovalDispatcher | null = null;
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
  const perSourceApproval = resolvedConfig.perSourceApproval ?? {};
  const perSourceModes: ApprovalMode[] = Object.values(perSourceApproval);
  // When the WebUI is active we still want a live-switchable engine even if no
  // [approval] section and no per-source overrides exist — otherwise the gate
  // keeps the legacy no-engine allow and there's nothing to switch. A bare
  // yolo-default engine is the right baseline in that case.
  if (approvalCfg === undefined && perSourceModes.length === 0 && !webuiActive) {
    return null;
  }
  const input: BuildEngineFromConfigInput = {
    defaultMode: approvalCfg?.mode,
    fail_closed: approvalCfg?.fail_closed,
    llm: approvalCfg?.llm,
    perSourceModes,
    staticOverrides: perSourceApproval,
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
  approvalEngine = buildProductionApprovalEngine(isWebUIActive());
  setApprovalEngine(approvalEngine);
  auditSink = await loadAuditSink({
    auditDir: resolvedConfig.server?.audit_dir,
    auditMaxBytes: resolvedConfig.server?.audit_max_bytes,
  });
}

/** Bridge the in-process approval dispatcher to the read-only WebUI queue shape. */
function buildWebUIApprovalQueueAdapter(engine: ApprovalDispatcher | null): ManualApprovalQueue | undefined {
  if (!engine) return undefined;

  const enqWrappers = new Map<Function, (p: any) => void>();
  const resWrappers = new Map<Function, (p: any, d: any) => void>();
  const toWebUI = (p: any): WebUIPendingApproval => ({
    id: p.id,
    profile: p.context?.profile?.id ?? 'default',
    tool: p.context?.tool ?? 'exec',
    command: p.context?.command ?? '',
    description: p.context?.description,
    enqueuedAt: p.enqueued_at,
  });

  return {
    list: () => engine.listPending().map(toWebUI),
    resolve: (id, decision: WebUIApprovalDecision) =>
      engine.resolvePending(id, decision.decision, decision.reason, decision.decided_by),
    on(event, listener) {
      if (event === 'enqueue') {
        const wrap = (p: any) => (listener as (p: WebUIPendingApproval) => void)(toWebUI(p));
        enqWrappers.set(listener, wrap);
        engine.on('enqueue', wrap);
      } else if (event === 'resolve') {
        const wrap = (p: any, d: WebUIApprovalDecision) =>
          (listener as (p: WebUIPendingApproval, d: WebUIApprovalDecision) => void)(toWebUI(p), d);
        resWrappers.set(listener, wrap);
        engine.on('resolve', wrap);
      }
    },
    off(event, listener) {
      if (event === 'enqueue') {
        const wrap = enqWrappers.get(listener);
        if (wrap) {
          engine.off('enqueue', wrap);
          enqWrappers.delete(listener);
        }
      } else if (event === 'resolve') {
        const wrap = resWrappers.get(listener);
        if (wrap) {
          engine.off('resolve', wrap);
          resWrappers.delete(listener);
        }
      }
    },
  };
}

/** Bridge the optional audit seam to the read-only WebUI audit tail shape. */
function buildWebUIAuditTailAdapter(sink: AuditSink): WebUIAuditTail | undefined {
  if (typeof sink.tail !== 'function' || typeof sink.on !== 'function') return undefined;

  const toWebUI = (r: any) => ({
    ts: r.ts,
    id: r.id,
    profile: r.profile,
    tool: r.tool,
    command: r.command,
    description: r.description,
    approval: r.approval,
    exec: r.exec
      ? {
          exit_code: r.exec.exit_code ?? undefined,
          duration_ms: r.exec.duration_ms,
          stdout_truncated: r.exec.stdout_truncated,
          stderr_truncated: r.exec.stderr_truncated,
          stdout: r.exec.stdout,
          stderr: r.exec.stderr,
        }
      : undefined,
  });
  const listenerMap = new Map<Function, (r: unknown) => void>();

  return {
    tail: async opts => {
      const records = await sink.tail!(opts);
      return records.map(toWebUI);
    },
    on: (event, listener) => {
      const wrap = (r: unknown) => listener(toWebUI(r));
      listenerMap.set(listener, wrap);
      sink.on!(event, wrap);
    },
    off: (event, listener) => {
      const wrap = listenerMap.get(listener);
      if (wrap && typeof sink.off === 'function') {
        sink.off(event, wrap);
        listenerMap.delete(listener);
      }
    },
  };
}

function makeApprovalModeLookup(): (profileName: string) => string {
  const staticDefaultMode: ApprovalMode = resolvedConfig.approval?.mode ?? 'yolo';
  const staticPerSource = resolvedConfig.perSourceApproval ?? {};
  return (name: string) => {
    // Prefer the live engine so the WebUI reflects runtime switches; fall back
    // to the static TOML resolution when no engine is wired (legacy path).
    if (approvalEngine) return approvalEngine.getEffectiveMode(name);
    return staticPerSource[name] ?? staticDefaultMode;
  };
}

/**
 * Bridge the in-process dispatcher to the WebUI's ModeController contract
 * (PR-7). All mutation is in-memory only (Decision D3): this adapter calls the
 * dispatcher's mode store, which never touches disk. Returns undefined when no
 * engine is wired (mode switching disabled).
 */
function buildWebUIModeController(engine: ApprovalDispatcher | null): WebUIModeController | undefined {
  if (!engine) return undefined;
  const wrappers = new Map<Function, (e: any) => void>();
  return {
    availableModes: () => engine.availableModes(),
    getGlobalMode: () => engine.getGlobalMode(),
    getEffectiveMode: (profileId: string) => engine.getEffectiveMode(profileId),
    setProfileMode: (profileId: string, mode: string | null) =>
      engine.setProfileMode(profileId, mode as ApprovalMode | null),
    setGlobalMode: (mode: string) => engine.setGlobalMode(mode as ApprovalMode),
    on(event, listener) {
      const wrap = (e: any) => listener(e);
      wrappers.set(listener, wrap);
      engine.on(event, wrap);
    },
    off(event, listener) {
      const wrap = wrappers.get(listener);
      if (wrap) {
        engine.off(event, wrap);
        wrappers.delete(listener);
      }
    },
  };
}

/**
 * Bridge the TransportRegistry's in-memory description override to the WebUI's
 * SourceController contract (PR-8). All mutation is in-memory only (Decision
 * D3): `registry.setDescription()` updates a Map and NEVER writes the TOML
 * config. The approval engine re-reads the effective description on its next
 * decision because `registry.profile()` applies the override on every call —
 * so an edit takes effect live without a restart. This adapter owns the
 * `source-updated` fan-out (the registry is a pure state-holder, like the
 * ApprovalModeStore beneath the mode controller).
 */
function buildWebUISourceController(reg: TransportRegistry): WebUISourceController {
  const listeners = new Set<(e: WebUISourceUpdatedEvent) => void>();
  return {
    hasSource: (id: string) => reg.names().includes(id),
    getEffectiveDescription: (id: string) => reg.getEffectiveDescription(id),
    setDescription(id: string, description: string | null): WebUISourceUpdatedEvent {
      const effective = reg.setDescription(id, description);
      const event: WebUISourceUpdatedEvent = {
        id,
        description: effective,
        at: new Date().toISOString(),
      };
      for (const l of listeners) {
        try { l(event); } catch { /* a bad listener must not break the edit */ }
      }
      return event;
    },
    on(_event, listener) {
      listeners.add(listener);
    },
    off(_event, listener) {
      listeners.delete(listener);
    },
  };
}

// =============================================================================
// Config hot-reload (PR-9). The reloader owns the parse→validate→swap→rollback
// transaction; the watcher debounces fs.watch and drives it. Reload scope =
// connections + per-source description + approval policy. The MCP tool list is
// NEVER reloaded (Decision D4) — it is static and registered once at startup,
// so STDIO clients need no reconnect. All mutation is in-memory (D3): a reload
// reseeds from the file but writes nothing back, so it can't loop the watcher.
// =============================================================================

let configReloader: ConfigReloader | null = null;
let stopConfigWatcher: (() => void) | null = null;

/**
 * Re-resolve the boot config from disk using the same precedence chain as
 * startup. Only ever called on the TOML-driven path (the watcher isn't started
 * for `--ssh`/legacy CLI), so `cliSources` is empty and TOML wins. Throws on any
 * parse/validation error — the reloader treats a throw as "keep the old config".
 */
function reloadResolveConfig(): ResolvedConfig {
  return resolveConfig({
    cliSources: cliSourceConfigs,
    cliConfigPath: typeof CONFIG_PATH === 'string' ? CONFIG_PATH : undefined,
  });
}

/**
 * Build the ConfigReloader bound to the live registry + approval engine. Only
 * meaningful when a TOML config path exists (TOML-driven boot); returns null
 * otherwise so the watcher is never started for CLI/`--ssh` mode.
 */
function buildConfigReloader(): ConfigReloader | null {
  if (!resolvedConfig.configPath) return null;
  return new ConfigReloader({
    registry,
    loadConfig: reloadResolveConfig,
    engine: approvalEngine ?? undefined,
    prepareSources: async (sources) => {
      for (const cfg of sources) await prepareKeyContents(cfg);
    },
  });
}

/** Adapt the ConfigReloader (an EventEmitter) to the WebUI's read-only controller. */
function buildWebUIReloadController(reloader: ConfigReloader | null): WebUIConfigReloadController | undefined {
  if (!reloader) return undefined;
  const wrappers = new Map<Function, (e: any) => void>();
  return {
    on(event, listener) {
      const wrap = (e: any) => listener(e);
      wrappers.set(listener, wrap);
      reloader.on(event, wrap);
    },
    off(event, listener) {
      const wrap = wrappers.get(listener);
      if (wrap) {
        reloader.off(event, wrap);
        wrappers.delete(listener);
      }
    },
  };
}

async function maybeStartWebUI(): Promise<{ close(): Promise<void> } | undefined> {
  if (!isWebUIActive()) return undefined;

  const tomlWebui = resolvedConfig.webui;
  const host = tomlWebui?.host ?? '127.0.0.1';
  const port = tomlWebui?.port ?? 8088;
  const authToken = tomlWebui?.auth_token;

  const handle = await startWebUI({
    host,
    port,
    authToken,
    registry: { list: () => registry.list() },
    queue: buildWebUIApprovalQueueAdapter(approvalEngine),
    audit: buildWebUIAuditTailAdapter(auditSink),
    getApprovalMode: makeApprovalModeLookup(),
    modeController: buildWebUIModeController(approvalEngine),
    sourceController: buildWebUISourceController(registry),
    reloadController: buildWebUIReloadController(configReloader),
  });
  const tokenStatus = authToken ? 'token required' : 'anonymous loopback';
  console.error(`SSH MCP WebUI running on http://${handle.address.host}:${handle.address.port}/ — ${tokenStatus}`);
  return handle;
}


export async function executeAuditedTransportCommand(input: {
  transport: Pick<ISshTransport, 'exec' | 'execElevated'>;
  tool: 'exec' | 'sudo-exec';
  command: string;
  description?: string;
  profile?: string;
  timeoutMs?: number;
  sudoPassword?: string;
  store: { append(record: unknown): unknown };
}) {
  const sanitizedCommand = sanitizeCommand(input.command);
  const commandWithDescription = input.description
    ? `${sanitizedCommand} # ${input.description.replace(/#/g, '\\#')}`
    : sanitizedCommand;
  const startedAt = Date.now();
  const result = input.tool === 'sudo-exec'
    ? await input.transport.execElevated(commandWithDescription, {
        timeoutMs: input.timeoutMs ?? DEFAULT_TIMEOUT,
        mode: 'sudo',
        password: input.sudoPassword,
      })
    : await input.transport.exec(commandWithDescription, { timeoutMs: input.timeoutMs ?? DEFAULT_TIMEOUT });

  const now = new Date();
  const durationMs = Math.max(0, Date.now() - startedAt);
  try {
    input.store.append({
      profile: input.profile ?? 'stub',
      tool: input.tool,
      command: commandWithDescription,
      description: input.description,
      approval: {
        mode: 'yolo',
        decision: 'allow',
        reason: 'approval engine not yet wired (yolo placeholder)',
        decided_at: now.toISOString(),
        decided_by: 'yolo',
      },
      exec: {
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
        exitCode: result.exitCode ?? null,
        durationMs,
      },
      now,
    });
  } catch (auditErr: any) {
    console.error(`audit log append failed: ${auditErr?.message || auditErr}`);
  }

  return resultToMcpContent(result);
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
    const commandWithDescription = appendDescriptionComment(sanitizedCommand, description);
    const profile = resolvedProfileName(connectionName);
    const startedAt = Date.now();
    let audited = false;
    let approvalDecision: ApprovalDecision | undefined;
    try {
      const t = await registry.get(connectionName);
      approvalDecision = await gateApproval({
        profile: registry.profile(connectionName),
        tool: 'exec',
        command: commandWithDescription,
        description,
      });
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
      const profile = resolvedProfileName(connectionName);
      const startedAt = Date.now();
      let audited = false;
      let approvalDecision: ApprovalDecision | undefined;
      try {
        const t = await registry.get(connectionName);
        approvalDecision = await gateApproval({
          profile: registry.profile(connectionName),
          tool: 'sudo-exec',
          command: commandWithDescription,
          description,
        });
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
  // Build the config reloader AFTER the approval engine exists so a hot reload
  // reseeds policy in lockstep with connections. Null for CLI/`--ssh` boots.
  configReloader = buildConfigReloader();
  const webuiHandle = await maybeStartWebUI();
  // Start the debounced TOML watcher LAST so the WebUI's reloadController is
  // already subscribed before any file change can fire `config-reloaded`.
  if (configReloader && resolvedConfig.configPath) {
    stopConfigWatcher = startConfigWatcher({
      configPath: resolvedConfig.configPath,
      onChange: async () => { await configReloader!.reload(); },
    });
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
  const mode = isMultiHost ? `multi-host (${registry.names().length} servers: ${registry.names().join(', ')})` : 'single-host';
  console.error(`SSH MCP Server running on stdio — ${mode}`);

  const cleanup = () => {
    console.error('Shutting down SSH MCP Server...');
    if (stopConfigWatcher) { try { stopConfigWatcher(); } catch { /* ignore */ } }
    if (webuiHandle) void webuiHandle.close().catch(() => { /* ignore */ });
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
