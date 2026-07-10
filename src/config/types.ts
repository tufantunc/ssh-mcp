/**
 * TOML config schema for ssh-mcp-kerberos.
 *
 * Mirrors dbhub's [[sources]]/[server]/[webui]/[approval] layout. The parsed
 * representation is intentionally a superset: only `sources` is required.
 * Other sections are reserved for the audit-log, approval-engine, and
 * webui-status tasks downstream — this task implements parsing + validation
 * for the whole shape so later tasks need only consume it.
 */

import type { AuthMode, ServerConfig } from '../transports/types.js';

export type ApprovalMode = 'yolo' | 'smart' | 'manual';

/** Top-level [server] block — optional. */
export interface ServerSection {
  /** Audit dir; defaults to ~/.ssh-mcp. Expanded ~ at parse time. */
  audit_dir?: string;
  /** Per-record stdout/stderr cap. Default 10000. */
  audit_max_bytes?: number;
  /**
   * Opt out of the multi-source omit-name connection guard (restore the legacy
   * silent first-source default). Absent or `true` keeps the guard ON (safe);
   * `false` disables it. Projected onto ResolvedConfig.requireConnection and
   * consumed by applyRegistryConnectionPolicy at boot.
   */
  require_connection?: boolean;
}

/** Top-level [webui] block — optional. WebUI is OFF unless enabled or --webui passed. */
export interface WebUISection {
  enabled?: boolean;
  host?: string;        // default 127.0.0.1
  port?: number;        // default 8088
  auth_token?: string;  // required when host != 127.0.0.1; supports env:NAME
}

/** [approval.llm] block — used in smart mode. */
export interface ApprovalLLMSection {
  endpoint?: string;
  api_key?: string;     // supports env:NAME
  /** Internal resolved-config marker: a configured key was unavailable. */
  api_key_unresolved?: true;
  model?: string;
  timeout_ms?: number;
  provider?: 'openai' | string;
}

/** Top-level [approval] block — optional. */
export interface ApprovalSection {
  mode?: ApprovalMode;       // default 'manual'
  fail_closed?: boolean;     // default true
  llm?: ApprovalLLMSection;
}

/** A single [[sources]] entry from the TOML. */
export interface TomlSource {
  id: string;
  /**
   * Human-readable label for the source. RESERVED: parsed and type-checked
   * here but not yet projected into ServerConfig — a downstream task
   * (webui-description-edit) consumes it. Documented in ssh-mcp.toml.example so
   * configs can declare it ahead of that consumer landing.
   */
  description?: string;
  host: string;
  port?: number;
  user: string;
  auth: AuthMode;
  key_path?: string;
  private_key?: string;
  password?: string;        // supports env:NAME
  sudo_password?: string;   // supports env:NAME
  su_password?: string;     // supports env:NAME
  transport?: 'ssh2' | 'openssh';
  kerberos?: boolean;
  gssapi_delegate_credentials?: 'yes' | 'no';
  known_hosts_file?: string;
  strict_host_key_checking?: 'yes' | 'no' | 'accept-new';
  default?: boolean;
  /** Per-source approval override (just `mode` for v1). */
  approval?: { mode?: ApprovalMode };
}

/** The raw, parsed TOML document (post-validation). */
export interface TomlConfig {
  server?: ServerSection;
  webui?: WebUISection;
  approval?: ApprovalSection;
  sources: TomlSource[];
}

/**
 * The shape consumed by `src/index.ts` and the TransportRegistry. Mirrors
 * the existing `ServerConfig` array (one per registered host) plus a few
 * top-level sections future tasks (audit/approval/webui) will read.
 */
export interface ResolvedConfig {
  /** ServerConfig values fed to TransportRegistry.register, in order. */
  sources: ServerConfig[];
  /** Name of the source TransportRegistry should treat as default, if any. */
  defaultName?: string;
  /**
   * True ONLY when the user explicitly chose a default (a TOML source with
   * `default = true`). False when `defaultName` is merely the first-registered
   * fallback. The boot path keys the multi-source omit-name guard on this:
   * `setDefault()` (which re-enables the omit-name shortcut) is called only for
   * an explicit default, so a multi-source config with no explicit default
   * still rejects an omitted connectionName instead of silently routing to the
   * first host. Required (not optional) so every construction site states its
   * intent and the compiler catches omissions.
   */
  defaultExplicit: boolean;
  /** Per-source approval override, keyed by source name. */
  perSourceApproval: Record<string, ApprovalMode>;
  /**
   * Boot-time value of [server].require_connection. When `false` the
   * multi-source omit-name guard is disabled (legacy first-source default);
   * `undefined`/`true` keeps it ON. applyRegistryConnectionPolicy applies the
   * safe default, so a config that predates this field stays guarded.
   */
  requireConnection?: boolean;
  server?: ServerSection;
  webui?: WebUISection;
  approval?: ApprovalSection;
  /** Path the TOML was loaded from (for diagnostics). Undefined when no TOML used. */
  configPath?: string;
}
