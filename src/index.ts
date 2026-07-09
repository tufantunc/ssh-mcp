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
  manualWithoutResolverWarning,
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

/**
 * Resolve and validate the transport for a multi-host --ssh JSON config.
 * Defaults to 'ssh2'; rejects any value that is not exactly 'ssh2' or 'openssh'
 * so a typo like "opnssh" fails at parse time instead of silently running the
 * default ssh2 transport. (createTransport treats any non-'openssh' value as
 * ssh2, while prepareKeyContents only loads a key when transport === 'ssh2',
 * so an unchecked typo would connect over ssh2 without the configured key.)
 * Mirrors the legacy CLI's `Invalid --transport` rejection.
 */
function resolveJsonTransport(obj: any): 'ssh2' | 'openssh' {
  const t = obj.transport ?? 'ssh2';
  if (t !== 'ssh2' && t !== 'openssh') {
    throw new Error(`--ssh "${obj.name}" invalid "transport": ${JSON.stringify(obj.transport)} (expected "ssh2" or "openssh")`);
  }
  return t;
}

export function parseServerConfigJson(raw: string): ServerConfig {
  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch (e: any) {
    // Do NOT echo the raw argument: a malformed --ssh config can still carry a
    // password or private key alongside the syntax error, and main() prints the
    // thrown error to stderr. Surface only the parser message, never the config.
    throw new Error(`--ssh JSON parse error: ${e?.message || e}`);
  }
  // name must be a non-empty string: a numeric key (e.g. `"name": 1`) registers
  // under a Map key the MCP tools' string connectionName can never resolve.
  if (typeof obj.name !== 'string' || obj.name.length === 0) {
    throw new Error('--ssh JSON requires a non-empty string "name"');
  }
  if (!obj.host) throw new Error(`--ssh "${obj.name}" missing required "host"`);
  const user = obj.user ?? obj.username;
  if (!user) throw new Error(`--ssh "${obj.name}" missing required "user" (or "username")`);
  const auth: AuthMode | undefined = obj.auth;
  if (!auth || !['kerberos', 'key', 'password'].includes(auth)) {
    throw new Error(`--ssh "${obj.name}" requires "auth": "kerberos" | "key" | "password"`);
  }

  // port: mirror the legacy --port numeric validation. An unchecked value fails
  // only at first use (openssh `ssh -G -p abc` -> "Bad port", exit 255; ssh2
  // receives a non-numeric port), advertised by list-servers as if healthy.
  // Reject a non-integer / out-of-range port at parse time.
  let port = 22;
  if (obj.port !== undefined) {
    const p = typeof obj.port === 'number' ? obj.port : Number(obj.port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      throw new Error(`--ssh "${obj.name}" invalid "port": ${JSON.stringify(obj.port)} (expected integer 1-65535)`);
    }
    port = p;
  }

  const cfg: ServerConfig = {
    name: obj.name,
    host: obj.host,
    port,
    username: user,
    authMode: auth,
  };
  if (typeof obj.description === 'string') cfg.description = obj.description;

  switch (auth) {
    case 'kerberos':
      cfg.kerberos = true;
      cfg.transport = 'openssh';
      // Kerberos implies openssh; reject an explicit conflicting transport
      // rather than silently overriding it (mirrors the legacy --kerberos rule).
      if (obj.transport !== undefined && obj.transport !== 'openssh') {
        throw new Error(`--ssh "${obj.name}" auth "kerberos" implies transport "openssh" (got ${JSON.stringify(obj.transport)})`);
      }
      break;
    case 'key':
      cfg.transport = resolveJsonTransport(obj);
      // The legacy single-host CLI used `--key=<path>`; the multi-host JSON
      // schema uses `keyPath` (openssh -i / ssh2 read from disk) or
      // `privateKey` (ssh2 inline contents). A legacy-shaped top-level `key`
      // field is read by neither transport, so a config that supplies only
      // `key` has NO key material and would silently fall back to ambient
      // agent/default identities. Reject it with guidance instead of accepting
      // a credential-less key config (Codex 3541767246).
      if (obj.key !== undefined) {
        throw new Error(`--ssh "${obj.name}" auth "key" uses "keyPath" (or "privateKey" for ssh2), not "key"`);
      }
      // OpenSshTransport.buildArgs only passes cfg.keyPath via `-i`; an inline
      // privateKey would be silently ignored and ssh would fall back to
      // agent/default identities. Reject the combination so the configured
      // credential is actually used (or the user switches to keyPath).
      if (cfg.transport === 'openssh' && obj.privateKey) {
        throw new Error(`--ssh "${obj.name}" inline "privateKey" is not supported for transport "openssh"; use "keyPath"`);
      }
      if (obj.keyPath) cfg.keyPath = obj.keyPath;
      if (obj.privateKey) cfg.privateKey = obj.privateKey;
      // Require actual key material. Without keyPath (openssh -i / ssh2 read)
      // or an inline privateKey (ssh2), buildArgs() omits `-i` and
      // `IdentitiesOnly=yes`, and the ssh2 transport has no key, so the
      // connection silently falls back to whatever default or agent identity is
      // offered instead of the intended key. Fail at parse time rather than
      // let a key-auth config connect with an ambient identity (Codex 3541767246).
      if (!cfg.keyPath && !cfg.privateKey) {
        throw new Error(
          `--ssh "${obj.name}" auth "key" requires "keyPath"${cfg.transport === 'ssh2' ? ' or inline "privateKey"' : ''}`,
        );
      }
      break;
    case 'password':
      cfg.transport = resolveJsonTransport(obj);
      if (obj.password) cfg.password = obj.password;
      break;
  }

  if (obj.sudoPassword) cfg.sudoPassword = obj.sudoPassword;
  if (obj.suPassword) cfg.suPassword = obj.suPassword;

  // gssapiDelegateCredentials: enum-validate and require kerberos auth (the only
  // path that emits GSSAPIDelegateCredentials). An unchecked typo like "maybe"
  // registers but fails every command (openssh `ssh -G -o
  // GSSAPIDelegateCredentials=maybe` -> "unsupported option", exit 255).
  // Mirrors the legacy rules "must be yes or no" + "requires --kerberos".
  if (obj.gssapiDelegateCredentials !== undefined) {
    if (!['yes', 'no'].includes(obj.gssapiDelegateCredentials)) {
      throw new Error(`--ssh "${obj.name}" gssapiDelegateCredentials must be "yes" or "no" (got ${JSON.stringify(obj.gssapiDelegateCredentials)})`);
    }
    if (auth !== 'kerberos') {
      throw new Error(`--ssh "${obj.name}" gssapiDelegateCredentials requires auth "kerberos"`);
    }
    cfg.gssapiDelegateCredentials = obj.gssapiDelegateCredentials;
  }

  // strictHostKeyChecking: enum-validate. An unchecked value fails every command
  // (openssh `ssh -G -o StrictHostKeyChecking=maybe` -> "unsupported option",
  // exit 255). Mirrors the legacy enum check.
  if (obj.strictHostKeyChecking !== undefined &&
      !['yes', 'no', 'accept-new'].includes(obj.strictHostKeyChecking)) {
    throw new Error(`--ssh "${obj.name}" strictHostKeyChecking must be one of: yes, no, accept-new (got ${JSON.stringify(obj.strictHostKeyChecking)})`);
  }

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
// The explicit `--config` path is resolved (and value-less `--config` rejected)
// via resolveCliConfigPath at the resolveConfig call site below.

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

  // Precedence must match resolveAuthMode (kerberos > password > key), NOT a
  // key-before-password order. When a legacy invocation supplies both
  // --password and --key, password wins: classifying it as key auth would make
  // prepareKeyContents read the (possibly stale/sample) key file → ENOENT, and
  // could let the ssh2 transport prefer the key over the intended password
  // (regression vs base `main`). See resolveAuthMode's doc-comment.
  const authMode: AuthMode | undefined = resolveAuthMode({
    kerberos: KERBEROS_FLAG,
    password: PASSWORD,
    key: KEY,
  });
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
  // Only attach the key path when key auth actually wins. Attaching a stale
  // --key on a password/kerberos source would make prepareKeyContents (ssh2)
  // read the possibly-nonexistent file, and openssh's password/kerberos
  // branches never use keyPath anyway.
  if (KEY && authMode === 'key') cfg.keyPath = KEY;
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

/**
 * Resolve the explicit `--config` path from parsed argv.
 *
 * `parseArgv` records a value-less `--config` (no `=path`) as `null`. Silently
 * coercing that to `undefined` would drop the explicit flag and fall back to
 * `SSH_MCP_CONFIG`/default discovery, so a mistyped `--config` could start the
 * process against the wrong configured source instead of failing fast. Reject a
 * present-but-value-less `--config` like the other value-requiring flags.
 * Returns the path when supplied, or `undefined` when the flag is absent.
 */
export function resolveCliConfigPath(
  config: Record<string, string | null>,
): string | undefined {
  if (!('config' in config)) return undefined;
  const value = config.config;
  if (typeof value !== 'string') {
    throw new Error('Configuration error:\n--config requires a value (--config=<path>)');
  }
  // `--config=` parses as an empty string. resolveConfig treats a truthy
  // explicit path as the config to load but skips loadTomlFile for a falsy one,
  // so an empty value would start the process while silently dropping the
  // intended TOML top-level settings/discovery. Treat '' like the value-less
  // `--config` case and fail fast (Codex 3541772406).
  if (value === '') {
    throw new Error('Configuration error:\n--config requires a value (--config=<path>)');
  }
  return value;
}

const resolvedConfig: ResolvedConfig = (isCliEnabled || isTestMode)
  ? resolveConfig({
      cliSources: cliSourceConfigs,
      cliConfigPath: resolveCliConfigPath(argvConfig),
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

export interface BuildTransportConfigOptions {
  /**
   * When true, an ssh2 key config records `keyPath` but does NOT read the key
   * file contents into `privateKey`. The read is deferred to the registry's
   * lazy `prepareKeyContents` hook on the first tool call. Used by the legacy
   * single-host bootstrap so a key mounted after process launch still works —
   * matching the pre-registry behavior where the key was only read inside
   * getOrCreateTransport() on first use, not at startup.
   */
  deferKeyRead?: boolean;
}

export async function buildTransportConfig(
  inputs: BuildTransportConfigInputs,
  opts: BuildTransportConfigOptions = {},
): Promise<TransportConfig> {
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
    //
    // deferKeyRead skips the eager read entirely so the registry's lazy
    // prepareKeyContents hook reads it on first tool call instead. The legacy
    // single-host bootstrap uses this so a key mounted after process launch is
    // still honored — startup must not read the key file (Codex 3541767256).
    if (transport === 'ssh2' && authMode === 'key' && !opts.deferKeyRead) {
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

const registry = new TransportRegistry(prepareKeyContents);

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
  // preserved via buildLegacyServerConfig (uses resolveAuthMode).
  //
  // Key reads are DEFERRED: prepareKeyContents is passed as the registry's
  // lazy prepareConfig hook (see `new TransportRegistry(prepareKeyContents)`)
  // and runs inside get(name), not here — so one host with a missing/unmounted
  // key path can't break startup or list-servers for the other healthy hosts
  // (multi-host R2 hardening carried forward from pr/multi-host).
  for (const cfg of resolvedConfig.sources) {
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

/** Effective profile/connection name for gating + audit attribution. */
function resolvedProfileName(connectionName?: string): string {
  // Treat an empty/blank connectionName as "omitted", mirroring
  // TransportRegistry.resolveName() (which routes `''` to the default host).
  // Otherwise gating + audit attribution would be computed for the literal
  // profile id '' while the command actually ran against the default host,
  // silently bypassing that host's per-source approval policy.
  const name = connectionName && connectionName.trim() !== '' ? connectionName : undefined;
  if (name) return name;
  // An omitted/blank name that the registry would REJECT (multi-source, no
  // explicit default, guard on) never lands on a host: resolveName() throws
  // before selection. Attributing that rejected call to getDefaultName() (the
  // first-registered host) would corrupt audit profile for exactly the guard
  // case. Mirror the guard and label it unresolved instead of a real host.
  if (registry.wouldRejectOmittedName()) return '(unresolved)';
  return registry.getDefaultName() ?? 'default';
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

function auditExecution(params: {
  tool: 'exec' | 'sudo-exec';
  profile: string;
  command: string;
  description?: string;
  startedAt: number;
  result?: ExecResult;
  error?: unknown;
  store: { append(record: unknown): unknown };
}): void {
  const now = new Date();
  const durationMs = Math.max(0, Date.now() - params.startedAt);
  try {
    // Append inside the try: audit logging is best-effort — a store failure
    // must be visible but should not hide the real SSH result.
    params.store.append({
      profile: params.profile,
      tool: params.tool,
      command: params.command,
      description: params.description,
      approval: {
        mode: 'yolo',
        decision: 'allow',
        reason: 'approval engine not yet wired (yolo placeholder)',
        decided_at: now.toISOString(),
        decided_by: 'yolo',
      },
      exec: params.result
        ? {
            stdout: params.result.stdout ?? '',
            stderr: params.result.stderr ?? '',
            exitCode: params.result.exitCode ?? null,
            durationMs,
          }
        : {
            stdout: '',
            stderr: params.error instanceof Error ? params.error.message : String(params.error ?? 'unknown error'),
            exitCode: null,
            durationMs,
          },
      now,
    });
  } catch (auditErr: any) {
    // Audit failure must be visible but should not hide the real SSH result.
    console.error(`audit log append failed: ${auditErr?.message || auditErr}`);
  }
}

function approvalProfileForConnection(connectionName?: string): ResolvedSource {
  const id = resolvedProfileName(connectionName);
  const source = resolvedConfig.sources.find(s => s.name === id);
  return buildApprovalProfile(id, resolvedConfig.perSourceApproval ?? {}, source);
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
 * Resolve the [approval]/per-source config into the concrete engine input.
 * Returns null for the legacy CLI path (no [approval] section and no per-source
 * overrides). Shared by buildProductionApprovalEngine (which builds the engine)
 * and wireApprovalAndAudit (which reuses the SAME resolved defaultMode +
 * perSourceModes for the manual-without-resolver boot warning) so the warning
 * can never disagree with the mode the engine actually runs.
 */
export function resolveApprovalEngineInput(
  config: ResolvedConfig = resolvedConfig,
): BuildEngineFromConfigInput | null {
  const approvalCfg = config.approval;
  const perSourceModes: ApprovalMode[] = Object.values(config.perSourceApproval ?? {});
  if (approvalCfg === undefined && perSourceModes.length === 0) {
    return null;
  }
  const approvalLlmOnly = approvalCfg !== undefined
    && approvalCfg.mode === undefined
    && approvalCfg.fail_closed === undefined
    && approvalCfg.llm !== undefined;
  const perSourceOnlyDefault = perSourceModes.length > 0
    && (approvalCfg === undefined || approvalLlmOnly);
  return {
    // Resolve the GLOBAL default mode:
    //  - explicit [approval].mode set        -> honor it.
    //  - no global mode, per-source overrides, and either no [approval] block
    //    or an [approval.llm]-only block -> keep the global default 'yolo'
    //    (unrestricted) so only the overridden sources are gated. Defining
    //    [approval.llm] for a per-source `mode = "smart"` makes
    //    resolvedConfig.approval non-undefined even though no global mode was
    //    requested, so keying solely on `approvalCfg === undefined` would
    //    wrongly fall through to manual here and gate every ungated host (or
    //    throw at boot with WebUI off).
    //  - no global mode but a real top-level approval knob (e.g.
    //    `fail_closed = true`, or a bare [approval] block) was added
    //    deliberately to enable approval; leave defaultMode undefined so
    //    buildApprovalEngineFromConfig applies the documented 'manual' default.
    defaultMode:
      approvalCfg?.mode !== undefined
        ? approvalCfg.mode
        : perSourceOnlyDefault
          ? 'yolo'
          : undefined,
    fail_closed: approvalCfg?.fail_closed,
    llm: approvalCfg?.llm,
    perSourceModes,
  };
}

export function approvalResolverWarningFromInput(
  input: BuildEngineFromConfigInput | null,
  params: { webuiEnabled: boolean; resolverWired: boolean },
): string | null {
  if (input === null) return null;
  return manualWithoutResolverWarning({
    webuiEnabled: params.webuiEnabled,
    defaultMode: input.defaultMode,
    perSourceModes: input.perSourceModes,
    resolverWired: params.resolverWired,
  });
}

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
  const input = resolveApprovalEngineInput();
  if (input === null) {
    return null;
  }
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
 * True when a driver that settles the manual-approval queue is wired into this
 * build. The queue resolver — the WebUI manual-approval server — lands in the
 * child lane `pr/webui-manual-approval`; the approval-engine lane ships only the
 * queue primitive, so no resolver is wired here. Kept as an explicit predicate
 * (rather than inlining `false`) so the child lane can flip it to a real
 * detection — e.g. `return isWebUIServerWired();` — without touching the warning
 * call site.
 */
function isApprovalResolverWired(): boolean {
  return false;
}

/**
 * Wire the approval engine into the gate and load the optional audit sink.
 * Safe to call before the MCP transport connects so the first exec is gated.
 */
async function wireApprovalAndAudit(): Promise<void> {
  // Keep the module-level `approvalEngine` binding: the read-only WebUI wiring
  // downstream (makeApprovalModeLookup + buildWebUIApprovalQueueAdapter) reads
  // it to surface the live engine to the dashboard.
  const webuiActive = isWebUIActive();
  approvalEngine = buildProductionApprovalEngine(webuiActive);

  // Non-fatal boot advisory: manual mode boots a queue with no driver when the
  // approval-engine lane runs standalone, ahead of its child WebUI lane. Boot
  // still succeeds (the queue exists, it just times out until a resolver lands);
  // warn so the operator is not left wondering why every command hangs.
  const input = resolveApprovalEngineInput();
  const warning = approvalResolverWarningFromInput(input, {
    webuiEnabled: webuiActive,
    resolverWired: isApprovalResolverWired(),
  });
  if (warning) {
    console.error(`WARN: ${warning}`);
  }
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
  const perSource = resolvedConfig.perSourceApproval ?? {};
  // Mirror exactly what ApprovalDispatcher.decide() enforces so the WebUI
  // never advertises a gate that is not actually applied:
  //   - no engine wired        -> gateApproval() takes the legacy no-engine
  //                               allow path (yolo-equivalent);
  //   - per-source override set -> decide() honors ctx.profile.approval.mode,
  //                               which the handlers thread in via
  //                               approvalProfileForConnection();
  //   - otherwise               -> decide() falls back to the engine's own
  //                               resolved default mode.
  return (name: string): string => {
    if (!approvalEngine) return 'yolo';
    return perSource[name] ?? approvalEngine.defaultMode;
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
  const startedAt = Date.now();
  const profile = input.profile ?? 'default';
  let audited = false;
  // Record the raw attempted command if sanitization rejects it below. A
  // command rejected by validation (empty / over --maxChars) still leaves an
  // audit record — the contract covers failures, and sanitizeCommand throws.
  let auditCommand = String(input.command ?? '');
  try {
    const sanitizedCommand = sanitizeCommand(input.command);
    const commandWithDescription = appendDescriptionComment(sanitizedCommand, input.description);
    auditCommand = commandWithDescription;
    const result = input.tool === 'sudo-exec'
      ? await input.transport.execElevated(commandWithDescription, {
          timeoutMs: input.timeoutMs ?? DEFAULT_TIMEOUT,
          mode: 'sudo',
          password: input.sudoPassword,
        })
      : await input.transport.exec(commandWithDescription, { timeoutMs: input.timeoutMs ?? DEFAULT_TIMEOUT });
    auditExecution({
      tool: input.tool,
      profile,
      command: commandWithDescription,
      description: input.description,
      startedAt,
      result,
      store: input.store,
    });
    audited = true;
    return resultToMcpContent(result);
  } catch (err) {
    // Transport rejection (spawn failure, unexpected exception) OR a
    // sanitization rejection (empty/too-long command) still gets an audit
    // record — the contract is "audit success AND failure", matching the
    // exec/sudo-exec MCP handlers. `audited` guards the resultToMcpContent
    // throw path (result already audited above) from double-writing.
    if (!audited) {
      auditExecution({
        tool: input.tool,
        profile,
        command: auditCommand,
        description: input.description,
        startedAt,
        error: err,
        store: input.store,
      });
    }
    throw err;
  }
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
    const profile = resolvedProfileName(connectionName);
    // Fallback timestamp for errors raised before the transport call (registry
    // init failure, approval deny). Re-captured immediately before t.exec below
    // so a SUCCESSFUL command's audit durationMs measures command runtime only,
    // not SSH init + approval wait time.
    let startedAt = Date.now();
    let audited = false;
    let approvalDecision: ApprovalDecision | undefined;
    try {
      const t = await registry.get(connectionName);
      approvalDecision = await gateApproval({
        profile: approvalProfileForConnection(connectionName),
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
      const profile = resolvedProfileName(connectionName);
      // Fallback timestamp for errors raised before the transport call (registry
      // init failure, approval deny). Re-captured immediately before
      // t.execElevated below so a SUCCESSFUL command's audit durationMs measures
      // command runtime only, not SSH init + approval wait time.
      let startedAt = Date.now();
      let audited = false;
      let approvalDecision: ApprovalDecision | undefined;
      try {
        const t = await registry.get(connectionName);
        approvalDecision = await gateApproval({
          profile: approvalProfileForConnection(connectionName),
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
  const webuiHandle = await maybeStartWebUI();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  const mode = isMultiHost ? `multi-host (${registry.names().length} servers: ${registry.names().join(', ')})` : 'single-host';
  console.error(`SSH MCP Server running on stdio — ${mode}`);

  const cleanup = () => {
    console.error('Shutting down SSH MCP Server...');
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
