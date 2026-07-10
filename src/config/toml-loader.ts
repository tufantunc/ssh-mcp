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
      const st = fs.statSync(candidate);
      if (st.isFile()) return candidate;
      if (candidate === env.SSH_MCP_CONFIG) {
        throw new Error(`Config: cannot access ${candidate}: not a regular file`);
      }
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
   * Treat [webui] as enabled while validating top-level WebUI settings. The
   * boot resolver sets this for the CLI `--webui` override so deferred secrets
   * and cross-field checks use the effective enabled state, not only the TOML
   * `enabled` key.
   */
  webuiEnabled?: boolean;
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
    if (src.default !== undefined && typeof src.default !== 'boolean') {
      throw new Error(`Config: sources.${src.id}.default must be a boolean`);
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

    const passwordValue = src.auth === 'password'
      ? requireConfigString(src.password, 'password')
      : undefined;
    const resolveOptionalElevationPassword = (
      value: unknown,
      field: 'sudo_password' | 'su_password',
    ): string | undefined => {
      const resolved = resolveEnvRef(
        requireConfigString(value, field),
        `sources.${src.id}.${field}`,
        env,
      );
      // Treat an explicitly empty TOML elevation password as unset. Leaving it
      // as '' makes the OpenSSH sudo path feed a blank line via sudo -S, which
      // blocks the intended passwordless-sudo / suPassword fallback behavior.
      return resolved === '' ? undefined : resolved;
    };
    const sudoPassword = resolveOptionalElevationPassword(src.sudo_password, 'sudo_password');
    const suPassword = resolveOptionalElevationPassword(src.su_password, 'su_password');
    const keyPath = requireConfigString(src.key_path, 'key_path');
    const privateKey = src.auth === 'key'
      ? requireConfigString(src.private_key, 'private_key')
      : undefined;
    const knownHostsFile = requireConfigString(src.known_hosts_file, 'known_hosts_file');
    const description = requireConfigString(src.description, 'description');

    const out: ServerConfig = {
      name: src.id,
      description: src.description,
      host: src.host,
      port: src.port ?? 22,
      username: src.user,
      authMode: src.auth,
      transport: resolvedTransport,
    };
    if (description && description.length > 0) {
      out.description = description;
    }

    switch (src.auth) {
      case 'kerberos':
        out.kerberos = true;
        if (src.gssapi_delegate_credentials) {
          out.gssapiDelegateCredentials = src.gssapi_delegate_credentials;
        }
        break;
      case 'key':
        if (keyPath) out.keyPath = expandHome(keyPath);
        // The openssh transport authenticates with `-i <keyPath>` and never
        // materializes an inline private_key — supplying only private_key on
        // openssh silently falls back to default-identity pubkey auth. Treat
        // inline private_key as unsupported on openssh: require key_path and do
        // not resolve an unused private_key env ref that could fail startup.
        // (ssh2 reads inline key contents in memory, so inline private_key
        // remains valid there.)
        if (resolvedTransport === 'openssh') {
          if (!out.keyPath) {
            throw new Error(
              `Config: sources.${src.id} auth="key" with transport="openssh" requires key_path ` +
              `(inline private_key is not supported on the openssh transport)`,
            );
          }
          break;
        }
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
        break;
      case 'password': {
        const password = resolveEnvRef(
          passwordValue,
          `sources.${src.id}.password`,
          env,
        );
        if (!password) {
          throw new Error(
            `Config: sources.${src.id} auth="password" requires "password"`,
          );
        }
        out.password = password;
        break;
      }
    }

    if (sudoPassword !== undefined) out.sudoPassword = sudoPassword;
    if (suPassword !== undefined) out.suPassword = suPassword;
    if (src.description !== undefined) out.description = src.description;
    // known_hosts_file / strict_host_key_checking are honored only by the
    // openssh transport (openssh.ts). On ssh2 they are silently dropped, which
    // would disable the requested host-key enforcement — a security downgrade.
    // Mirror the legacy CLI rule ("--knownHostsFile and --strictHostKeyChecking
    // require --transport=openssh") and reject the combination at parse time.
    if (
      resolvedTransport === 'ssh2' &&
      (knownHostsFile !== undefined || src.strict_host_key_checking !== undefined)
    ) {
      throw new Error(
        `Config: sources.${src.id} known_hosts_file/strict_host_key_checking require transport="openssh" ` +
        `(the ssh2 transport does not enforce host keys)`,
      );
    }
    if (knownHostsFile !== undefined) out.knownHostsFile = expandHome(knownHostsFile);
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
      out.approval = { mode: mode as ApprovalMode };
      perSourceApproval[src.id] = mode as ApprovalMode;
    }
  }

  const server = parsed.server ? validateServerSection(parsed.server) : undefined;
  const webui = parsed.webui
    ? validateWebUI(parsed.webui, env, opts.webuiEnabled === true)
    : undefined;
  const approval = parsed.approval
    ? validateApproval(parsed.approval, env, Object.values(perSourceApproval).includes('smart'))
    : undefined;

  return {
    sources: resolvedSources,
    defaultName,
    // In a TOML, defaultName is set ONLY by an explicit `default = true` on a
    // source (see the loop above) — never a positional fallback. So a defined
    // defaultName here is, by construction, a user-chosen explicit default.
    defaultExplicit: defaultName !== undefined,
    perSourceApproval,
    // Surface [server].require_connection so the boot path can wire the
    // omit-name guard opt-out. Undefined (field absent) keeps the guard ON.
    requireConnection: server?.require_connection,
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
    // Byte counts are integer-only: a fractional cap below 1 would floor to 0
    // downstream and silently empty every stdout/stderr capture, so reject
    // non-integers at the config entry point (Codex 3556038524).
    if (
      typeof raw.audit_max_bytes !== 'number' ||
      !Number.isInteger(raw.audit_max_bytes) ||
      raw.audit_max_bytes <= 0
    ) {
      throw new Error('Config: [server].audit_max_bytes must be a positive integer');
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

function validateWebUI(raw: any, env: NodeJS.ProcessEnv, enabledByCli = false) {
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
    if (!Number.isInteger(raw.port) || raw.port < 0 || raw.port > 65535) {
      throw new Error('Config: [webui].port must be an integer between 0 and 65535');
    }
    out.port = raw.port;
  }
  if (raw.cors !== undefined) {
    if (typeof raw.cors !== 'boolean') throw new Error('Config: [webui].cors must be a boolean');
    out.cors = raw.cors;
  }
  const webuiEnabled = out.enabled === true || enabledByCli;
  if (raw.auth_token !== undefined) {
    if (typeof raw.auth_token !== 'string') throw new Error('Config: [webui].auth_token must be a string');
    if (webuiEnabled) {
      out.auth_token = resolveEnvRef(raw.auth_token, '[webui].auth_token', env);
    }
  }
  // Cross-field check: a non-loopback bind requires a token — but ONLY when the
  // web UI is actually enabled. With `[webui] enabled = false` the section is
  // inert (parsed/reserved, never served), so demanding a token for a disabled
  // section would let an otherwise-off optional block fail SSH startup (Codex
  // 3541772404). When the eventual CLI enable path turns it on, the same check
  // applies against the resolved enabled=true state.
  if (webuiEnabled && out.host && out.host !== '127.0.0.1' && out.host !== 'localhost' && out.host !== '::1') {
    if (!out.auth_token) {
      throw new Error(
        `Config: [webui].host="${out.host}" is non-loopback; auth_token is required when WebUI is enabled`,
      );
    }
  }
  return out;
}

function validateApproval(
  raw: any,
  env: NodeJS.ProcessEnv,
  resolveLlmApiKeyForPerSourceSmart = false,
): ApprovalSection {
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
      // Resolve the api_key env ref when smart approval is ACTIVELY used —
      // either by the top-level [approval].mode or by a per-source override.
      // In that case a missing/empty OPENAI_API_KEY is fatal (smart cannot
      // authenticate), so the resolution throws. Type validation is never
      // deferred: a present api_key must be a string in every mode.
      if (typeof llm.api_key !== 'string') {
        throw new Error('Config: [approval.llm].api_key must be a string');
      }
      const smartActive = out.mode === 'smart' || resolveLlmApiKeyForPerSourceSmart;
      // The LLM block is "fully configured" once it carries endpoint + model.
      // buildApprovalEngineFromConfig pre-arms smart in that case (so the WebUI
      // can live-switch into smart without a restart), and SmartApproval needs
      // the configured api_key to authenticate that live switch. Preserve the
      // resolved key when the block is fully configured. A missing env remains
      // non-fatal while smart is inactive, matching deferred resolution.
      const fullyConfigured =
        typeof llm.endpoint === 'string' && typeof llm.model === 'string';
      if (smartActive) {
        const apiKey = resolveEnvRef(llm.api_key, '[approval.llm].api_key', env);
        if (!apiKey) {
          throw new Error('Config: [approval.llm].api_key must not be empty when smart mode is active');
        }
        resolved.api_key = apiKey;
      } else if (fullyConfigured) {
        try {
          const apiKey = resolveEnvRef(llm.api_key, '[approval.llm].api_key', env);
          if (apiKey) {
            resolved.api_key = apiKey;
          } else {
            resolved.api_key_unresolved = true;
          }
        } catch {
          // Missing env remains non-fatal while smart is inactive, but retain a
          // marker so the engine builder does not advertise/pre-arm an
          // unauthenticated smart mode.
          resolved.api_key_unresolved = true;
        }
      }
      // else: incomplete block and smart unused — defer entirely (unchanged).
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
