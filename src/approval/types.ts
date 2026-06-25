/**
 * Approval engine types — mode dispatch, decisions, and per-source overrides.
 *
 * This module is intentionally self-contained so the approval-engine card can
 * land before toml-config / audit-log. The reviewer will reconcile
 * ResolvedSource / AuditRecord shapes once those cards merge.
 */

export type ApprovalMode = 'yolo' | 'smart' | 'manual';

/**
 * The closed set of recognized approval modes, in stable display order.
 * Single source of truth for runtime validation of a requested mode switch.
 */
export const APPROVAL_MODES = ['yolo', 'smart', 'manual'] as const;

/** Runtime type-guard: is `value` a recognized ApprovalMode string? */
export function isApprovalMode(value: unknown): value is ApprovalMode {
  return typeof value === 'string' && (APPROVAL_MODES as readonly string[]).includes(value);
}

/**
 * Payload broadcast (SSE `mode-changed`) whenever a live approval-mode switch
 * is applied. `scope` distinguishes a global-default change from a per-profile
 * override. `mode` is the value that was set; `effective` is what the named
 * profile now resolves to (override > global) so the UI never has to recompute
 * precedence. `at` is an ISO timestamp. In-memory only — never persisted.
 */
export interface ModeChangedPayload {
  scope: 'global' | 'profile';
  /** Present iff scope === 'profile'. */
  profileId?: string;
  mode: ApprovalMode;
  effective: ApprovalMode;
  at: string;
}

export type ApprovalDecision =
  | { decision: 'allow'; reason: string; decided_by: string; decided_at: string; mode: ApprovalMode }
  | { decision: 'deny'; reason: string; decided_by: string; decided_at: string; mode: ApprovalMode };

/**
 * Minimal shape of a resolved SSH source/profile used by the approval engine.
 * Once toml-config lands, this should be re-exported from src/config/types.ts.
 */
export interface ResolvedSource {
  id: string;
  description?: string;
  approval?: {
    mode?: ApprovalMode;
  };
}

/**
 * Context handed to ApprovalEngine.decide() for every exec / sudo-exec call.
 */
export interface ApprovalContext {
  profile: ResolvedSource;
  tool: 'exec' | 'sudo-exec';
  command: string;       // sanitized, post-redact for visible value
  description?: string;  // verbatim from MCP arg
}

/**
 * LLM endpoint configuration for `smart` mode.
 * Defaults to the OpenAI chat-completions schema; provider is reserved for
 * future Anthropic / Azure shapes.
 */
export interface SmartLlmConfig {
  provider?: 'openai' | 'anthropic' | 'azure';
  endpoint: string;
  api_key?: string;
  model: string;
  timeout_ms?: number;   // default 8000
}

export interface SmartApprovalOptions {
  llm: SmartLlmConfig;
  fail_closed?: boolean;  // default true
  /**
   * Test seam: dependency-injectable fetch implementation. Defaults to the
   * global `fetch`. The signature is intentionally narrowed to the bits we use
   * so test stubs don't need to satisfy the full DOM Fetch type.
   */
  fetchImpl?: (input: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{
    ok: boolean;
    status: number;
    text: () => Promise<string>;
  }>;
}

export interface ManualApprovalOptions {
  timeout_ms?: number;   // default 5 minutes
  webuiEnabled: boolean; // when false, manual mode throws at construction time
}

/**
 * A pending manual approval request. WebUI surface (separate card) lists these
 * and posts allow/deny back via `resolve()`.
 */
export interface PendingApproval {
  id: string;
  enqueued_at: string;
  context: ApprovalContext;
  /** Resolve from outside (for example a future WebUI mutation handler). Returns true if the resolve
   * was applied; false if the request had already timed out or been resolved. */
  resolve: (decision: 'allow' | 'deny', note?: string, decided_by?: string) => boolean;
}

export interface ApprovalEngine {
  /** Decide whether to allow the command. Never throws on policy decisions;
   * the caller throws McpError on `deny`. Throws on misconfiguration. */
  decide(ctx: ApprovalContext): Promise<ApprovalDecision>;
  /** Snapshot of pending manual approvals (empty for yolo/smart). */
  listPending?(): PendingApproval[];
  /** External resolve hook for manual mode (used by WebUI). */
  resolvePending?(id: string, decision: 'allow' | 'deny', note?: string, decided_by?: string): boolean;
}
