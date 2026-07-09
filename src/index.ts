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
import { AuditStore, resolveAuditDir, yoloApproval } from './audit/store.js';
import { AuditTool } from './audit/types.js';

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
      // Require actual password material. An empty/missing password still
      // registers the server as password-authenticated but fails on first use:
      // OpenSshTransport.init() throws "authMode=password requires --password",
      // and the default ssh2 path attempts to connect without the credential the
      // selected auth mode promises. Fail at parse time like the key-auth branch
      // already does for missing key material (Codex 3549295040).
      if (typeof obj.password !== 'string' || obj.password.length === 0) {
        throw new Error(`--ssh "${obj.name}" auth "password" requires a non-empty "password"`);
      }
      cfg.password = obj.password;
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
// TODO(toml-config): read [server].audit_dir / [server].audit_max_bytes from
// the resolved TOML config once the toml-config card lands. For now, keep the
// documented default and support env overrides for tests/operators.
const AUDIT_DIR = resolveAuditDir(process.env.SSH_MCP_AUDIT_DIR);
const AUDIT_MAX_BYTES = (() => {
  const raw = process.env.SSH_MCP_AUDIT_MAX_BYTES;
  if (!raw) return 10_000;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 10_000;
})();
// Audit store is constructed lazily (see getAuditStore) so that merely
// importing this module — e.g. under SSH_MCP_DISABLE_MAIN=1 for library use
// or unit tests — never performs audit-directory filesystem I/O. The store
// is materialized on first actual audit write (CLI/tool execution).
let _auditStore: AuditStore | null = null;
function getAuditStore(): AuditStore {
  if (_auditStore === null) {
    _auditStore = new AuditStore({ auditDir: AUDIT_DIR, auditMaxBytes: AUDIT_MAX_BYTES });
  }
  return _auditStore;
}
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

export async function prepareKeyContents(cfg: ServerConfig): Promise<void> {
  // ssh2 transport reads key contents in memory; openssh uses -i path.
  // Gate on authMode === 'key': buildTransportConfig() still records keyPath
  // even when password auth takes precedence over a stale/sample --key, so a
  // config such as `--password=... --key=/stale` must NOT read the (possibly
  // nonexistent) key file here — otherwise the first tool call fails with
  // ENOENT instead of using the password (Codex 3549295046). Mirrors the eager
  // read's `authMode === 'key'` guard in buildTransportConfig().
  if (
    cfg.authMode === 'key' &&
    cfg.transport === 'ssh2' &&
    cfg.keyPath &&
    !cfg.privateKey
  ) {
    const fs = await import('fs/promises');
    cfg.privateKey = await fs.readFile(cfg.keyPath, 'utf8');
  }
}

async function bootstrapRegistry(): Promise<void> {
  if (isMultiHost) {
    for (const raw of sshJsonArgs) {
      const cfg = parseServerConfigJson(raw);
      // Do NOT read key files here — prepareKeyContents is deferred to the
      // registry's lazy get(name) path (passed as the registry's prepareConfig
      // hook), so one host with a missing/unmounted key path can't break
      // startup or list-servers for the other, healthy hosts.
      registry.register(cfg);
    }
  } else {
    if (!HOST || !USER) return; // Test mode with no CLI — tools will error if called
    // Route the legacy single-host path through buildTransportConfig so it
    // inherits the kerberos>password>key precedence. Pass deferKeyRead so the
    // ssh2 key file is NOT read at startup: prepareKeyContents (the registry's
    // lazy prepareConfig hook) reads it on the first tool call instead, exactly
    // like the multi-host path. This preserves the pre-registry behavior where
    // the key was read only inside getOrCreateTransport(), so a key-based
    // deployment whose secret mount appears after process launch still starts
    // (Codex 3541767256).
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
    }, { deferKeyRead: true });
    registry.register({ ...tcfg, name: 'default' });
  }
}

function resolvedProfileName(connectionName?: string): string {
  // Delegate to the registry's non-throwing resolver so an ambiguous
  // multi-host call (name omitted, >1 server, no explicit default) is recorded
  // as '(unresolved)' instead of being misattributed to the first server on the
  // failure-audit path.
  return registry.resolveProfileName(connectionName);
}

function auditExecution(params: {
  tool: AuditTool;
  profile: string;
  command: string;
  description?: string;
  startedAt: number;
  result?: ExecResult;
  error?: unknown;
  store?: AuditStore;
}): void {
  const now = new Date();
  const durationMs = Math.max(0, Date.now() - params.startedAt);
  try {
    // Resolve the store inside the try: lazily constructing it can throw when
    // the audit directory is unwritable, and audit logging is best-effort —
    // a store-construction failure must not surface to the caller either.
    const store = params.store ?? getAuditStore();
    store.append({
      profile: params.profile,
      tool: params.tool,
      command: params.command,
      description: params.description,
      approval: yoloApproval(now),
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

export async function executeAuditedTransportCommand(input: {
  transport: Pick<ISshTransport, 'exec' | 'execElevated'>;
  tool: AuditTool;
  command: string;
  description?: string;
  profile?: string;
  timeoutMs?: number;
  sudoPassword?: string;
  store: AuditStore;
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
    const commandWithDescription = input.description
      ? `${sanitizedCommand} # ${input.description.replace(/#/g, '\\#')}`
      : sanitizedCommand;
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
    const profile = resolvedProfileName(connectionName);
    const startedAt = Date.now();
    let audited = false;
    // Record the raw attempted command if sanitization rejects it below. A
    // command rejected by validation (empty / over --maxChars) still leaves an
    // audit record — the contract covers failures, and sanitizeCommand throws.
    let auditCommand = String(command ?? '');
    try {
      const sanitizedCommand = sanitizeCommand(command);
      const t = await registry.get(connectionName);
      const commandWithDescription = description
        ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
        : sanitizedCommand;
      auditCommand = commandWithDescription;
      const result = await t.exec(commandWithDescription, { timeoutMs: DEFAULT_TIMEOUT });
      auditExecution({
        tool: 'exec',
        profile,
        command: commandWithDescription,
        description,
        startedAt,
        result,
      });
      audited = true;
      return resultToMcpContent(result);
    } catch (err: any) {
      if (!audited) auditExecution({ tool: 'exec', profile, command: auditCommand, description, startedAt, error: err });
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
      const profile = resolvedProfileName(connectionName);
      const startedAt = Date.now();
      let audited = false;
      // Record the raw attempted command if sanitization rejects it below. A
      // command rejected by validation (empty / over --maxChars) still leaves
      // an audit record — the contract covers failures, and sanitizeCommand
      // throws.
      let auditCommand = String(command ?? '');
      try {
        const sanitizedCommand = sanitizeCommand(command);
        const t = await registry.get(connectionName);
        const commandWithDescription = description
          ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
          : sanitizedCommand;
        auditCommand = commandWithDescription;
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
        auditExecution({
          tool: 'sudo-exec',
          profile,
          command: commandWithDescription,
          description,
          startedAt,
          result,
        });
        audited = true;
        return resultToMcpContent(result);
      } catch (err: any) {
        if (!audited) auditExecution({ tool: 'sudo-exec', profile, command: auditCommand, description, startedAt, error: err });
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
