/**
 * Audit JSONL store.
 *
 * Responsibilities:
 *   - Resolve and ensure the audit directory exists (default ~/.ssh-mcp).
 *   - Compute the active file path from today's UTC date.
 *   - Cap stdout/stderr bytes per record at `auditMaxBytes`.
 *   - Apply the redactor to every text field.
 *   - Generate a sortable record id.
 *   - Delegate file rotation to `rotator.ts` before each append.
 *
 * Public surface:
 *   - `AuditStore` class with `appendExec` / `appendDeny` helpers.
 *   - `buildRecord` for tests / callers that just want a record without I/O.
 *   - `resolveAuditDir` to expand `~` / honor env overrides.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  AuditRecord,
  AuditStoreConfig,
  AuditTool,
  AuditApprovalSection,
  AuditExecSection,
  DEFAULT_AUDIT_MAX_BYTES,
  DEFAULT_MAX_FILE_BYTES,
  DEFAULT_RETAIN,
} from './types.js';
import { redact } from './redactor.js';
import { rotateIfNeeded, pruneOldDays } from './rotator.js';

/** Resolve audit directory, expanding `~` and honoring env override. */
export function resolveAuditDir(override?: string | null): string {
  const raw =
    override ??
    process.env.SSH_MCP_AUDIT_DIR ??
    path.join(os.homedir(), '.ssh-mcp');
  if (raw.startsWith('~')) {
    return path.join(os.homedir(), raw.slice(1));
  }
  return path.resolve(raw);
}

/** UTC YYYYMMDD string. */
export function utcDateStamp(d: Date = new Date()): string {
  const y = d.getUTCFullYear().toString().padStart(4, '0');
  const m = (d.getUTCMonth() + 1).toString().padStart(2, '0');
  const day = d.getUTCDate().toString().padStart(2, '0');
  return `${y}${m}${day}`;
}

export function activeFilePath(auditDir: string, d: Date = new Date()): string {
  return path.join(auditDir, `executions-${utcDateStamp(d)}.jsonl`);
}

/** Sortable id: timestamp + random suffix. */
let _counter = 0;
export function newRecordId(d: Date = new Date()): string {
  _counter = (_counter + 1) & 0xffff;
  const t = d.getTime().toString(36).padStart(9, '0');
  const r = Math.floor(Math.random() * 0xffffff)
    .toString(36)
    .padStart(5, '0');
  const c = _counter.toString(36).padStart(3, '0');
  return `${t}-${r}${c}`;
}

/** Truncate a string to at most `maxBytes` UTF-8 bytes. Returns text + truncated flag. */
export function capUtf8(s: string, maxBytes: number): { text: string; truncated: boolean } {
  if (maxBytes <= 0) return { text: '', truncated: s.length > 0 };
  const buf = Buffer.from(s, 'utf8');
  if (buf.byteLength <= maxBytes) return { text: s, truncated: false };
  // Slice to maxBytes, then walk back to avoid splitting a multi-byte char.
  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return { text: buf.slice(0, end).toString('utf8'), truncated: true };
}

export interface BuildRecordInput {
  profile: string;
  tool: AuditTool;
  command: string;
  description?: string;
  approval: AuditApprovalSection;
  exec?: {
    stdout: string;
    stderr: string;
    exitCode: number | null;
    durationMs: number;
  };
  now?: Date;
  auditMaxBytes?: number;
}

export function buildRecord(input: BuildRecordInput): AuditRecord {
  const now = input.now ?? new Date();
  const cap = input.auditMaxBytes ?? DEFAULT_AUDIT_MAX_BYTES;

  const rec: AuditRecord = {
    ts: now.toISOString(),
    id: newRecordId(now),
    profile: input.profile,
    tool: input.tool,
    command: redact(input.command),
    description: input.description ? redact(input.description) : undefined,
    approval: {
      mode: input.approval.mode,
      decision: input.approval.decision,
      reason: redact(input.approval.reason),
      decided_at: input.approval.decided_at,
      decided_by: input.approval.decided_by,
    },
  };

  if (input.exec) {
    const so = capUtf8(redact(input.exec.stdout), cap);
    const se = capUtf8(redact(input.exec.stderr), cap);
    const execSection: AuditExecSection = {
      exit_code: input.exec.exitCode,
      duration_ms: input.exec.durationMs,
      stdout_truncated: so.truncated,
      stderr_truncated: se.truncated,
      stdout: so.text,
      stderr: se.text,
    };
    rec.exec = execSection;
  }

  return rec;
}

export class AuditStore {
  private readonly auditDir: string;
  private readonly auditMaxBytes: number;
  private readonly maxFileBytes: number;
  private readonly retain: number;

  /** Track which day we last pruned, so we only prune once per day. */
  private lastPruneStamp: string | null = null;

  constructor(cfg: AuditStoreConfig) {
    this.auditDir = cfg.auditDir;
    this.auditMaxBytes = cfg.auditMaxBytes ?? DEFAULT_AUDIT_MAX_BYTES;
    this.maxFileBytes = cfg.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.retain = cfg.retain ?? DEFAULT_RETAIN;
    fs.mkdirSync(this.auditDir, { recursive: true });
  }

  /** Build + write a record. Returns the written record (after redaction/capping). */
  append(input: BuildRecordInput): AuditRecord {
    const now = input.now ?? new Date();
    const rec = buildRecord({ ...input, now, auditMaxBytes: this.auditMaxBytes });
    const filePath = activeFilePath(this.auditDir, now);

    rotateIfNeeded({
      filePath,
      maxFileBytes: this.maxFileBytes,
      retain: this.retain,
    });

    const line = JSON.stringify(rec) + '\n';
    fs.appendFileSync(filePath, line, { encoding: 'utf8' });

    const stamp = utcDateStamp(now);
    if (this.lastPruneStamp !== stamp) {
      this.lastPruneStamp = stamp;
      try {
        pruneOldDays(this.auditDir, this.retain);
      } catch {
        // best-effort
      }
    }
    return rec;
  }

  /** Path to the active file (today's UTC date). For tests + diagnostics. */
  currentFilePath(d: Date = new Date()): string {
    return activeFilePath(this.auditDir, d);
  }
}

/**
 * Build a yolo approval section — convenient placeholder for callers that
 * haven't wired the approval engine yet (this card lands before approval-engine).
 */
export function yoloApproval(now: Date = new Date()): AuditApprovalSection {
  return {
    mode: 'yolo',
    decision: 'allow',
    reason: 'approval engine not yet wired (yolo placeholder)',
    decided_at: now.toISOString(),
    decided_by: 'yolo',
  };
}
