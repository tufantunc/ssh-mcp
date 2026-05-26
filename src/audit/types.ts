/**
 * Audit log record shapes.
 *
 * Each invocation of the `exec` or `sudo-exec` MCP tool produces exactly one
 * JSONL line in the configured audit directory (default `~/.ssh-mcp`).
 *
 * Records are written AFTER execution finishes (success, failure, or denied
 * by the approval engine). Secrets are scrubbed by the redactor before the
 * record is serialized; stdout/stderr are capped to `auditMaxBytes` with a
 * `truncated` flag.
 */

export type AuditTool = 'exec' | 'sudo-exec';

export type ApprovalMode = 'yolo' | 'smart' | 'manual';

export type ApprovalDecisionKind = 'allow' | 'deny';

export interface AuditApprovalSection {
  /** Approval engine mode in effect when the decision was made. */
  mode: ApprovalMode;
  /** Final decision. `deny` means the transport never ran the command. */
  decision: ApprovalDecisionKind;
  /** Human-readable rationale (LLM reason, manual operator note, or "yolo"). */
  reason: string;
  /** ISO-8601 timestamp at which the decision was made. */
  decided_at: string;
  /** Source attribution: `smart-llm`, `webui:<user>`, `yolo`, etc. */
  decided_by: string;
}

export interface AuditExecSection {
  exit_code: number | null;
  duration_ms: number;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
  stdout: string;
  stderr: string;
}

export interface AuditRecord {
  /** ISO-8601 timestamp when the record was finalized (UTC). */
  ts: string;
  /** Unique record id (ULID-ish; lexicographically sortable). */
  id: string;
  /** Profile / connection name (`default`, `prod-bastion`, ...). */
  profile: string;
  /** Tool that invoked the audit. */
  tool: AuditTool;
  /** Sanitized + redacted command string. */
  command: string;
  /** Verbatim description from the MCP call, redacted. */
  description?: string;
  /** Approval engine decision. Always present once approval engine lands. */
  approval: AuditApprovalSection;
  /** Execution detail. Omitted when `approval.decision === 'deny'`. */
  exec?: AuditExecSection;
}

export interface AuditStoreConfig {
  /** Directory where executions-YYYYMMDD.jsonl files live. */
  auditDir: string;
  /** Per-record cap on stdout/stderr bytes (UTF-8). */
  auditMaxBytes: number;
  /** File size threshold (bytes) that triggers a size-based rotation. */
  maxFileBytes?: number;
  /** Number of rotated files to keep (excluding the current file). */
  retain?: number;
}

export const DEFAULT_AUDIT_MAX_BYTES = 10_000;
export const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MB
export const DEFAULT_RETAIN = 10;
