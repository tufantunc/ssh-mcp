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
  /** Per-source approval override, keyed by source name. */
  perSourceApproval: Record<string, ApprovalMode>;
  server?: ServerSection;
  webui?: WebUISection;
  approval?: ApprovalSection;
  /** Path the TOML was loaded from (for diagnostics). Undefined when no TOML used. */
  configPath?: string;
}
