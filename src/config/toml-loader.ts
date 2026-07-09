/**
 * TOML config loader for ssh-mcp-kerberos.
 *
 * Responsibilities:
 *  - Read file from disk.
 *  - Parse via @iarna/toml.
 *  - Resolve `env:NAME` strings against process.env (missing -> validation error).
 *  - Expand leading `~` and `~/` to the user's home directory.
 *  - Validate required fields and known enum values.
 *  - Project the validated TOML into the runtime shape (`ResolvedConfig`)
 *    that wires straight into TransportRegistry.register().
 *  - Never echo secret material in error messages.
 *
 * Discovery (when no explicit path is provided):
 *   1. $SSH_MCP_CONFIG
 *   2. $XDG_CONFIG_HOME/ssh-mcp/config.toml  (or ~/.config/ssh-mcp/config.toml when XDG unset)
 *   3. ~/.ssh-mcp/config.toml
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import TOML from '@iarna/toml';

import type { AuthMode, ServerConfig } from '../transports/types.js';
import type {
  ApprovalMode,
  ApprovalSection,
  ResolvedConfig,
  TomlConfig,
  TomlSource,
} from './types.js';

const VALID_AUTH: AuthMode[] = ['kerberos', 'key', 'password'];
const VALID_APPROVAL_MODE: ApprovalMode[] = ['yolo', 'smart', 'manual'];
const SECRET_TOML_KEYS = [
  'password',
  'sudo_password',
  'su_password',
  'private_key',
  'auth_token',
  'api_key',
];

function redactTomlParseMessage(message: string): string {
  const secretAssignment = new RegExp(
    `(\\b(?:${SECRET_TOML_KEYS.join('|')})\\s*=\\s*).*$`,
    'i',
  );
  return message
    .split(/\r?\n/)
    .map(line => line.replace(secretAssignment, '$1[REDACTED]'))
    .join('\n');
}

function isMissingPathError(e: any): boolean {
  return e?.code === 'ENOENT' || e?.code === 'ENOTDIR';
}

/** Replace a leading `~` with $HOME (POSIX + Windows). No-op for non-string. */
export function expandHome(p: string | undefined): string | undefined {
  if (!p) return p;
  if (p === '~') return os.homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) {
    return path.join(os.homedir(), p.slice(2));
  }
  return p;
}

/**
 * Resolve `env:NAME` references against process.env. Returns the value
 * unchanged when the prefix is absent. Throws a redact-safe error when
 * the referenced env var is missing or empty so secrets are never logged.
 */
export function resolveEnvRef(
  value: string | undefined,
  fieldLabel: string,
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') return value;
  if (!value.startsWith('env:')) return value;
  const name = value.slice(4).trim();
  if (!name) {
    throw new Error(`Config: ${fieldLabel} uses "env:" but no variable name was provided`);
  }
  const resolved = env[name];
  if (resolved === undefined || resolved === '') {
    throw new Error(
      `Config: ${fieldLabel} references env var ${name}, but it is not set or empty`,
    );
  }
  return resolved;
}

/**
 * Default discovery paths (in precedence order, highest first). Path is
 * returned even when the file does not exist; the caller decides whether
 * to require the discovered path.
 */
export function defaultDiscoveryPaths(env: NodeJS.ProcessEnv = process.env): string[] {
  const paths: string[] = [];
  if (env.SSH_MCP_CONFIG) paths.push(env.SSH_MCP_CONFIG);
  const xdg = env.XDG_CONFIG_HOME && env.XDG_CONFIG_HOME.trim()
    ? env.XDG_CONFIG_HOME
    : path.join(os.homedir(), '.config');
  paths.push(path.join(xdg, 'ssh-mcp', 'config.toml'));
  paths.push(path.join(os.homedir(), '.ssh-mcp', 'config.toml'));
  return paths;
}

/** Locate the first existing discovery path, if any. */
export function discoverConfigPath(env: NodeJS.ProcessEnv = process.env): string | undefined {
  for (const candidate of defaultDiscoveryPaths(env)) {
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch (e: any) {
      // SSH_MCP_CONFIG is an explicit user/env selection. A missing env path
      // still falls through to XDG/home discovery for compatibility, but an
      // unreadable/inaccessible env path must fail closed rather than silently
      // booting from a lower-precedence config.
      if (candidate === env.SSH_MCP_CONFIG && !isMissingPathError(e)) {
        throw new Error(`Config: cannot access ${candidate}: ${e?.message || e}`);
      }
      // not found — fall through
    }
  }
  return undefined;
}

interface LoadOptions {
  env?: NodeJS.ProcessEnv;
  /**
   * Tolerate a TOML with zero [[sources]] entries. Used by the resolver when
   * CLI sources are present and suppress the TOML source list, so a TOML that
   * only supplies top-level sections (e.g. just [webui]) is a valid, supported
   * combination instead of a hard error.
   */
  allowEmptySources?: boolean;
  /**
   * Skip [[sources]] parsing, validation, and secret env-ref resolution
   * entirely, projecting only the top-level sections. Used by the resolver
   * when CLI sources are present and SUPPRESS the TOML source list: the
   * suppressed [[sources]] are discarded downstream, so validating them here
   * (and resolving their `env:` secrets) would abort startup on a source-only
   * error even though only the top-level sections are meant to survive.
   * Implies allowEmptySources.
   */
  ignoreSources?: boolean;
}

/**
 * Parse a raw TOML string into the runtime `ResolvedConfig` shape.
 * Used directly by tests; the file-system entry point `loadTomlFile`
 * delegates here after reading the file.
 */
export function parseTomlConfig(raw: string, opts: LoadOptions = {}): ResolvedConfig {
  const env = opts.env ?? process.env;

  let parsed: any;
  try {
    parsed = TOML.parse(raw);
  } catch (e: any) {
    const message = redactTomlParseMessage(e?.message || String(e));
    throw new Error(`Config: TOML parse failed: ${message}`);
  }

  const rawSources = Array.isArray(parsed?.sources) ? parsed.sources : [];
  // When ignoreSources is set the CLI sources win and suppress the entire TOML
  // source list downstream, so skip parsing/validating them here (an env: ref
  // or other source-only error in a suppressed source must not abort startup).
  const sources = opts.ignoreSources ? [] : rawSources;
  if (sources.length === 0 && !opts.allowEmptySources && !opts.ignoreSources) {
    throw new Error('Config: at least one [[sources]] entry is required');
  }

  const resolvedSources: ServerConfig[] = [];
  const perSourceApproval: Record<string, ApprovalMode> = {};
  const seenNames = new Set<string>();
  let defaultName: string | undefined;

  for (let i = 0; i < sources.length; i++) {
    const src = sources[i] as TomlSource;
    const label = `[[sources]][${i}]`;

    if (!src || typeof src !== 'object') {
      throw new Error(`Config: ${label} must be a TOML table`);
    }
    if (!src.id || typeof src.id !== 'string') {
      throw new Error(`Config: ${label} missing required string "id"`);
    }
    if (seenNames.has(src.id)) {
      throw new Error(`Config: duplicate source id "${src.id}"`);
    }
    seenNames.add(src.id);

    if (!src.host || typeof src.host !== 'string') {
      throw new Error(`Config: sources.${src.id} missing required "host"`);
    }
    if (!src.user || typeof src.user !== 'string') {
      throw new Error(`Config: sources.${src.id} missing required "user"`);
    }
    if (!src.auth || !VALID_AUTH.includes(src.auth)) {
      throw new Error(
        `Config: sources.${src.id}.auth must be one of: ${VALID_AUTH.join(', ')}`,
      );
    }
    if (src.port !== undefined) {
      // This loader is the validation boundary for TOML sources, so reject a
      // port that is not a usable TCP port here rather than letting a value
      // like 22.5 / -1 / 70000 register and fail later with an opaque
      // transport-level error from ssh2/OpenSSH.
      if (
        typeof src.port !== 'number' ||
        !Number.isInteger(src.port) ||
        src.port < 1 ||
        src.port > 65535
      ) {
        throw new Error(
          `Config: sources.${src.id}.port must be an integer between 1 and 65535`,
        );
      }
    }
    if (
      src.transport !== undefined &&
      src.transport !== 'ssh2' &&
      src.transport !== 'openssh'
    ) {
      throw new Error(
        `Config: sources.${src.id}.transport must be "ssh2" or "openssh"`,
      );
    }
    if (
      src.strict_host_key_checking !== undefined &&
      !['yes', 'no', 'accept-new'].includes(src.strict_host_key_checking)
    ) {
      throw new Error(
        `Config: sources.${src.id}.strict_host_key_checking must be yes|no|accept-new`,
      );
    }
    if (
      src.gssapi_delegate_credentials !== undefined &&
      !['yes', 'no'].includes(src.gssapi_delegate_credentials)
    ) {
      throw new Error(
        `Config: sources.${src.id}.gssapi_delegate_credentials must be yes|no`,
      );
    }
    // GSSAPIDelegateCredentials is only wired in the Kerberos auth branch (see
    // the `case 'kerberos'` below and OpenSshTransport.buildArgs); for key or
    // password auth the option is silently dropped, so a user requesting
    // credential delegation would get none with no error. Mirror the legacy CLI
    // rule ("--gssapiDelegateCredentials requires --kerberos") and reject the
    // combination at parse time.
    if (src.gssapi_delegate_credentials !== undefined && src.auth !== 'kerberos') {
      throw new Error(
        `Config: sources.${src.id}.gssapi_delegate_credentials requires auth="kerberos"`,
      );
    }

    // Default transport mirrors index.ts logic: kerberos -> openssh, else explicit, else ssh2.
    const resolvedTransport: 'ssh2' | 'openssh' = src.transport
      ?? (src.auth === 'kerberos' ? 'openssh' : 'ssh2');

    // Kerberos requires the openssh transport (GSSAPI is only wired there).
    // An explicit transport="ssh2" on a kerberos source would start up and then
    // fail authentication at runtime — mirror the legacy CLI rule and reject it
    // at parse time. (index.ts validateConfig: "--kerberos requires
    // --transport=openssh".)
    if (src.auth === 'kerberos' && src.transport === 'ssh2') {
      throw new Error(
        `Config: sources.${src.id} auth="kerberos" requires transport="openssh" (remove transport="ssh2")`,
      );
    }

    // Secret fields must be quoted strings. An unquoted numeric value (e.g.
    // `password = 123456`) parses as a TOML number; resolveEnvRef returns
    // non-strings unchanged, so a number would reach the SSH/sudo password
    // paths and fail with an opaque runtime type error. Reject it here with a
    // clear, redact-safe config error that names the field but not the value.
    const requireConfigString = (
      value: unknown,
      field: string,
    ): string | undefined => {
      if (value === undefined) return undefined;
      if (typeof value !== 'string') {
        throw new Error(`Config: sources.${src.id}.${field} must be a quoted string`);
      }
      return value;
    };

    const password = resolveEnvRef(
      requireConfigString(src.password, 'password'),
      `sources.${src.id}.password`,
      env,
    );
    const sudoPassword = resolveEnvRef(
      requireConfigString(src.sudo_password, 'sudo_password'),
      `sources.${src.id}.sudo_password`,
      env,
    );
    const suPassword = resolveEnvRef(
      requireConfigString(src.su_password, 'su_password'),
      `sources.${src.id}.su_password`,
      env,
    );
    const keyPath = requireConfigString(src.key_path, 'key_path');
    const privateKey = requireConfigString(src.private_key, 'private_key');

    const out: ServerConfig = {
      name: src.id,
      host: src.host,
      port: src.port ?? 22,
      username: src.user,
      authMode: src.auth,
      transport: resolvedTransport,
    };

    switch (src.auth) {
      case 'kerberos':
        out.kerberos = true;
        if (src.gssapi_delegate_credentials) {
          out.gssapiDelegateCredentials = src.gssapi_delegate_credentials;
        }
        break;
      case 'key':
        if (keyPath) out.keyPath = expandHome(keyPath);
        // Resolve `env:NAME` for inline private_key the same way password/
        // sudo_password/su_password are resolved. Without this the literal
        // "env:SSH_KEY" placeholder would be copied into ServerConfig.privateKey
        // and the ssh2 transport would try to parse it as key material, failing
        // auth even when the env var is set (Codex 3541772408).
        if (privateKey !== undefined) {
          out.privateKey = resolveEnvRef(
            privateKey,
            `sources.${src.id}.private_key`,
            env,
          );
        }
        if (!out.keyPath && !out.privateKey) {
          throw new Error(
            `Config: sources.${src.id} auth="key" requires key_path or private_key`,
          );
        }
        // The openssh transport authenticates with `-i <keyPath>` and never
        // materializes an inline private_key — supplying only private_key on
        // openssh silently falls back to default-identity pubkey auth. Require
        // an on-disk key_path for openssh key sources so the configured key is
        // actually used. (ssh2 reads inline key contents in memory, so inline
        // private_key remains valid there.)
        if (resolvedTransport === 'openssh' && !out.keyPath) {
          throw new Error(
            `Config: sources.${src.id} auth="key" with transport="openssh" requires key_path ` +
            `(inline private_key is not supported on the openssh transport)`,
          );
        }
        break;
      case 'password':
        if (!password) {
          throw new Error(
            `Config: sources.${src.id} auth="password" requires "password"`,
          );
        }
        out.password = password;
        break;
    }

    if (sudoPassword !== undefined) out.sudoPassword = sudoPassword;
    if (suPassword !== undefined) out.suPassword = suPassword;
    // known_hosts_file / strict_host_key_checking are honored only by the
    // openssh transport (openssh.ts). On ssh2 they are silently dropped, which
    // would disable the requested host-key enforcement — a security downgrade.
    // Mirror the legacy CLI rule ("--knownHostsFile and --strictHostKeyChecking
    // require --transport=openssh") and reject the combination at parse time.
    if (
      resolvedTransport === 'ssh2' &&
      (src.known_hosts_file || src.strict_host_key_checking)
    ) {
      throw new Error(
        `Config: sources.${src.id} known_hosts_file/strict_host_key_checking require transport="openssh" ` +
        `(the ssh2 transport does not enforce host keys)`,
      );
    }
    if (src.known_hosts_file) out.knownHostsFile = expandHome(src.known_hosts_file);
    if (src.strict_host_key_checking) out.strictHostKeyChecking = src.strict_host_key_checking;

    resolvedSources.push(out);

    // `default` controls omit-name routing under the multi-source guard, so a
    // non-boolean value (e.g. the quoted `default = "true"`) must be rejected
    // rather than silently ignored — otherwise the intended default is never
    // applied and omitted connectionName calls start failing (Codex 3541772419).
    if (src.default !== undefined && typeof src.default !== 'boolean') {
      throw new Error(
        `Config: sources.${src.id}.default must be a boolean (got ${JSON.stringify(src.default)})`,
      );
    }
    if (src.default === true) {
      if (defaultName && defaultName !== src.id) {
        throw new Error(
          `Config: multiple sources marked default ("${defaultName}" and "${src.id}")`,
        );
      }
      defaultName = src.id;
    }

    if (src.approval?.mode !== undefined) {
      const mode = src.approval.mode;
      if (typeof mode !== 'string' || !VALID_APPROVAL_MODE.includes(mode as ApprovalMode)) {
        throw new Error(
          `Config: sources.${src.id}.approval.mode must be one of: ${VALID_APPROVAL_MODE.join(', ')}`,
        );
      }
      perSourceApproval[src.id] = mode as ApprovalMode;
    }
  }

  const server = parsed.server ? validateServerSection(parsed.server) : undefined;
  const webui = parsed.webui ? validateWebUI(parsed.webui, env) : undefined;
  const approval = parsed.approval ? validateApproval(parsed.approval, env) : undefined;

  return {
    sources: resolvedSources,
    defaultName,
    // In a TOML, defaultName is set ONLY by an explicit `default = true` on a
    // source (see the loop above) — never a positional fallback. So a defined
    // defaultName here is, by construction, a user-chosen explicit default.
    defaultExplicit: defaultName !== undefined,
    perSourceApproval,
    // Safe default: require an explicit connectionName when multi-source.
    // Opt out only via [server].require_connection = false.
    requireConnection: server?.require_connection ?? true,
    server,
    webui,
    approval,
  };
}

function validateServerSection(raw: any) {
  const out: TomlConfig['server'] = {};
  if (raw.audit_dir !== undefined) {
    if (typeof raw.audit_dir !== 'string') throw new Error('Config: [server].audit_dir must be a string');
    out.audit_dir = expandHome(raw.audit_dir);
  }
  if (raw.audit_max_bytes !== undefined) {
    if (typeof raw.audit_max_bytes !== 'number' || raw.audit_max_bytes <= 0) {
      throw new Error('Config: [server].audit_max_bytes must be a positive number');
    }
    out.audit_max_bytes = raw.audit_max_bytes;
  }
  if (raw.require_connection !== undefined) {
    if (typeof raw.require_connection !== 'boolean') {
      throw new Error('Config: [server].require_connection must be a boolean');
    }
    out.require_connection = raw.require_connection;
  }
  return out;
}

function validateWebUI(raw: any, env: NodeJS.ProcessEnv) {
  const out: TomlConfig['webui'] = {};
  if (raw.enabled !== undefined) {
    if (typeof raw.enabled !== 'boolean') throw new Error('Config: [webui].enabled must be a boolean');
    out.enabled = raw.enabled;
  }
  if (raw.host !== undefined) {
    if (typeof raw.host !== 'string') throw new Error('Config: [webui].host must be a string');
    out.host = raw.host;
  }
  if (raw.port !== undefined) {
    if (typeof raw.port !== 'number') throw new Error('Config: [webui].port must be a number');
    out.port = raw.port;
  }
  if (raw.auth_token !== undefined) {
    out.auth_token = resolveEnvRef(String(raw.auth_token), '[webui].auth_token', env);
  }
  // Cross-field check: a non-loopback bind requires a token — but ONLY when the
  // web UI is actually enabled. With `[webui] enabled = false` the section is
  // inert (parsed/reserved, never served), so demanding a token for a disabled
  // section would let an otherwise-off optional block fail SSH startup (Codex
  // 3541772404). When the eventual CLI enable path turns it on, the same check
  // applies against the resolved enabled=true state.
  if (out.enabled && out.host && out.host !== '127.0.0.1' && out.host !== 'localhost' && out.host !== '::1') {
    if (!out.auth_token) {
      throw new Error(
        `Config: [webui].host="${out.host}" is non-loopback; auth_token is required when [webui].enabled = true`,
      );
    }
  }
  return out;
}

function validateApproval(raw: any, env: NodeJS.ProcessEnv): ApprovalSection {
  const out: ApprovalSection = {};
  if (raw.mode !== undefined) {
    if (!VALID_APPROVAL_MODE.includes(raw.mode)) {
      throw new Error(`Config: [approval].mode must be one of: ${VALID_APPROVAL_MODE.join(', ')}`);
    }
    out.mode = raw.mode;
  }
  if (raw.fail_closed !== undefined) {
    if (typeof raw.fail_closed !== 'boolean') {
      throw new Error('Config: [approval].fail_closed must be a boolean');
    }
    out.fail_closed = raw.fail_closed;
  }
  if (raw.llm !== undefined) {
    if (typeof raw.llm !== 'object' || raw.llm === null) {
      throw new Error('Config: [approval.llm] must be a table');
    }
    const llm = raw.llm;
    const resolved: ApprovalSection['llm'] = {};
    if (llm.endpoint !== undefined) {
      if (typeof llm.endpoint !== 'string') throw new Error('Config: [approval.llm].endpoint must be a string');
      resolved.endpoint = llm.endpoint;
    }
    if (llm.api_key !== undefined) {
      // Only resolve the api_key env ref when smart approval is actually
      // enabled. [approval.llm] settings are irrelevant in the default/manual
      // mode, so resolving here would fail startup on a missing OPENAI_API_KEY
      // for a user who copied the example config without enabling smart mode.
      // Defer resolution to smart mode; leave api_key unresolved otherwise.
      if (out.mode === 'smart') {
        resolved.api_key = resolveEnvRef(String(llm.api_key), '[approval.llm].api_key', env);
      }
    }
    if (llm.model !== undefined) {
      if (typeof llm.model !== 'string') throw new Error('Config: [approval.llm].model must be a string');
      resolved.model = llm.model;
    }
    if (llm.timeout_ms !== undefined) {
      if (typeof llm.timeout_ms !== 'number' || llm.timeout_ms <= 0) {
        throw new Error('Config: [approval.llm].timeout_ms must be a positive number');
      }
      resolved.timeout_ms = llm.timeout_ms;
    }
    if (llm.provider !== undefined) {
      if (typeof llm.provider !== 'string') throw new Error('Config: [approval.llm].provider must be a string');
      resolved.provider = llm.provider;
    }
    out.llm = resolved;
  }
  return out;
}

/** Load + parse a TOML file from disk. Throws on missing file or any validation error. */
export function loadTomlFile(filePath: string, opts: LoadOptions = {}): ResolvedConfig {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (e: any) {
    throw new Error(`Config: cannot read ${filePath}: ${e?.message || e}`);
  }
  const parsed = parseTomlConfig(raw, opts);
  parsed.configPath = filePath;
  return parsed;
}
