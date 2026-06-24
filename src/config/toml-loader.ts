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
    } catch {
      // not found / permission denied — fall through
    }
  }
  return undefined;
}

interface LoadOptions {
  env?: NodeJS.ProcessEnv;
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
    throw new Error(`Config: TOML parse failed: ${e?.message || e}`);
  }

  const sources = Array.isArray(parsed?.sources) ? parsed.sources : [];
  if (sources.length === 0) {
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
    if (src.port !== undefined && (typeof src.port !== 'number' || !Number.isFinite(src.port))) {
      throw new Error(`Config: sources.${src.id}.port must be a number`);
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
    if (src.description !== undefined && typeof src.description !== 'string') {
      throw new Error(`Config: sources.${src.id}.description must be a string`);
    }

    // Default transport mirrors index.ts logic: kerberos -> openssh, else explicit, else ssh2.
    const resolvedTransport: 'ssh2' | 'openssh' = src.transport
      ?? (src.auth === 'kerberos' ? 'openssh' : 'ssh2');

    const password = resolveEnvRef(src.password, `sources.${src.id}.password`, env);
    const sudoPassword = resolveEnvRef(src.sudo_password, `sources.${src.id}.sudo_password`, env);
    const suPassword = resolveEnvRef(src.su_password, `sources.${src.id}.su_password`, env);

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
        if (src.key_path) out.keyPath = expandHome(src.key_path);
        if (src.private_key) out.privateKey = src.private_key;
        if (!out.keyPath && !out.privateKey) {
          throw new Error(
            `Config: sources.${src.id} auth="key" requires key_path or private_key`,
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
    if (src.description !== undefined) out.description = src.description;
    if (src.known_hosts_file) out.knownHostsFile = expandHome(src.known_hosts_file);
    if (src.strict_host_key_checking) out.strictHostKeyChecking = src.strict_host_key_checking;

    resolvedSources.push(out);

    if (src.default === true) {
      if (defaultName && defaultName !== src.id) {
        throw new Error(
          `Config: multiple sources marked default ("${defaultName}" and "${src.id}")`,
        );
      }
      defaultName = src.id;
    }

    if (src.approval?.mode) {
      if (!VALID_APPROVAL_MODE.includes(src.approval.mode)) {
        throw new Error(
          `Config: sources.${src.id}.approval.mode must be one of: ${VALID_APPROVAL_MODE.join(', ')}`,
        );
      }
      out.approval = { mode: src.approval.mode };
      perSourceApproval[src.id] = src.approval.mode;
    }
  }

  const server = parsed.server ? validateServerSection(parsed.server) : undefined;
  const webui = parsed.webui ? validateWebUI(parsed.webui, env) : undefined;
  const approval = parsed.approval ? validateApproval(parsed.approval, env) : undefined;

  return {
    sources: resolvedSources,
    defaultName,
    perSourceApproval,
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
  // Cross-field check: non-loopback bind requires a token.
  if (out.host && out.host !== '127.0.0.1' && out.host !== 'localhost' && out.host !== '::1') {
    if (!out.auth_token) {
      throw new Error(
        `Config: [webui].host="${out.host}" is non-loopback; auth_token is required`,
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
      resolved.api_key = resolveEnvRef(String(llm.api_key), '[approval.llm].api_key', env);
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
