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
import { EventEmitter } from 'node:events';

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
import { redact, preRedactUnboundedTokens } from './redactor.js';
import { rotateIfNeeded, pruneOldDays, retentionCutoffStamp } from './rotator.js';

/**
 * Resolve audit directory, expanding `~` and honoring env override.
 *
 * An empty / whitespace-only value (a `[server].audit_dir = ""` typo or
 * `SSH_MCP_AUDIT_DIR=""`) must NOT fall through to `path.resolve('')`, which
 * resolves to the process working directory — the AuditStore constructor
 * would then mkdir/chmod 0700 the service/repo cwd and write
 * `executions-*.jsonl` there. Treat empty as "not configured" and continue
 * down the fallback chain to the default `~/.ssh-mcp` (Codex 3556038508).
 */
export function resolveAuditDir(override?: string | null): string {
  let raw: string | undefined;
  for (const candidate of [override, process.env.SSH_MCP_AUDIT_DIR]) {
    if (typeof candidate !== 'string' || candidate.trim() === '') continue;
    raw = candidate;
    break;
  }
  raw = raw ?? path.join(os.homedir(), '.ssh-mcp');
  // Expand ONLY the current-user home forms (`~`, `~/...`, `~\...`) —
  // mirroring the TOML loader's stricter expandHome(). A `~user/...` form or
  // a literal directory named e.g. `~logs` must NOT be silently rewritten
  // under the current user's home; it resolves as a literal path instead,
  // matching how the same value behaves when it passes through expandHome()
  // during TOML loading (Codex 3568536833).
  if (raw === '~') {
    return os.homedir();
  }
  if (raw.startsWith('~/') || raw.startsWith('~\\')) {
    return path.join(os.homedir(), raw.slice(2));
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

/**
 * Headroom (bytes) scanned by the redactor beyond the final output cap.
 *
 * Bounded so a single secret token that *begins* within the retained `cap`
 * window is still fully present for the redactor to match, even if it
 * straddles the cap boundary — without paying redaction CPU/memory over an
 * unbounded (multi-MB) raw stdout/stderr. 4 KiB comfortably covers every
 * single-token shape the redactor knows (GitHub PAT ≤255, JWT, AWS, Google,
 * Slack) and a full RSA/ed25519 PEM private-key block.
 */
export const REDACT_SCAN_HEADROOM_BYTES = 4096;

/**
 * Floor (bytes) for the command/description audit cap.
 *
 * The command is capped so a rejected multi-MB payload cannot force expensive
 * redaction plus a large JSONL append (Codex 3541772945). But the cap must not
 * be the (possibly tiny) stdout/stderr `auditMaxBytes` — a legitimate command
 * is short and must survive even when output capture is set to a few bytes. So
 * the effective command cap is `max(auditMaxBytes, this floor)`: honor a larger
 * configured output cap, never drop below a bound generous enough to hold any
 * realistic command line, while still bounding a genuine multi-MB DoS payload.
 */
export const AUDIT_COMMAND_MIN_CAP_BYTES = 16384;

/**
 * Hard cap for short audit metadata labels such as `profile` / connectionName.
 * These fields originate from user-provided config or tool arguments on some
 * error paths, so cap+redact them before JSONL serialization to avoid a
 * rejected unknown-name request appending multi-MB records.
 */
export const AUDIT_PROFILE_MAX_BYTES = 1024;

/**
 * Bound, then redact, then cap — in that order.
 *
 * The naive `capUtf8(redact(s), cap)` redacts the *entire* raw string before
 * truncation, so a megabyte of command output pays full regex cost even
 * though only `cap` bytes survive. Here we first cap the raw text to
 * `cap + REDACT_SCAN_HEADROOM_BYTES` (the bytes the redactor is allowed to
 * scan), redact that bounded slice, then cap the redacted result to `cap`.
 * The headroom guarantees a token whose prefix lands inside the kept window
 * is matched in full (and thus replaced with `<redacted>`) rather than being
 * sliced mid-token into a partial-secret leak.
 *
 * The reported `truncated` flag is true if bytes were dropped at *either*
 * stage, preserving the semantics of the previous cap-after-redact path.
 */
export function capThenRedact(
  s: string,
  cap: number,
): { text: string; truncated: boolean } {
  if (cap <= 0) return { text: '', truncated: s.length > 0 };
  // 0. Pre-redact the UNBOUNDED token shapes over the FULL text first. PEM_RE is
  //    terminator-anchored and JWTs can carry large claims/cert chains, so a key
  //    or token whose end falls past the bounded scan window below would
  //    otherwise never fully match and its raw prefix could survive into the
  //    capped output. This full-scan is cheap when none are present and is the
  //    only step that must see the un-capped string (Codex 3541772953).
  const preRedacted = preRedactUnboundedTokens(s);
  // 1. Bound the bytes the remaining redaction rules scan.
  const scan = capUtf8(preRedacted, cap + REDACT_SCAN_HEADROOM_BYTES);
  // 2. Redact within the bounded window.
  const redacted = redact(scan.text);
  // 3. Cap the redacted text to the final size.
  const final = capUtf8(redacted, cap);
  // `truncated` is measured on the PEM-safe text: it reports whether real
  // *content* bytes were dropped by the cap, not the raw pre-redaction length.
  // A key that was fully replaced with `<redacted>` lost nothing to the cap, so
  // it is not "truncated"; genuine oversized output past the window still is.
  return { text: final.text, truncated: scan.truncated || final.truncated };
}

/**
 * Clamp a numeric config value to a safe integer.
 *
 * Returns `fallback` when `v` is undefined/null, non-finite (NaN, Infinity,
 * -Infinity), or below `minValid`; otherwise floors `v` to an integer. Guards
 * the store against surprising behavior from bad config — a negative
 * auditMaxBytes that empties output, a NaN/negative maxFileBytes that rotates
 * on every append, or retain <= 0 that breaks rotation/prune all collapse to
 * the documented default instead. `minValid` is the smallest *explicitly
 * honored* value (0 for auditMaxBytes so "capture nothing" is respected; 1 for
 * maxFileBytes/retain).
 */
export function clampInt(v: number | undefined | null, fallback: number, minValid: number): number {
  if (v === undefined || v === null || !Number.isFinite(v)) return fallback;
  const i = Math.floor(v);
  if (i < minValid) return fallback;
  return i;
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

  // Cap the command/description so a rejected multi-MB payload cannot force
  // expensive redaction plus a large JSONL append, bypassing the size guard
  // (Codex 3541772945). Use max(cap, floor) so a legitimate short command still
  // survives when the stdout/stderr auditMaxBytes is set very small, while a
  // genuine oversized command is still bounded. capThenRedact pre-redacts
  // unbounded key/token shapes over the full text before truncating. The same
  // auditCommand pattern feeds the sudo/helper paths.
  const cmdCap = Math.max(cap, AUDIT_COMMAND_MIN_CAP_BYTES);
  const command = capThenRedact(input.command, cmdCap).text;
  const description = input.description
    ? capThenRedact(input.description, cmdCap).text
    : undefined;

  const rec: AuditRecord = {
    ts: now.toISOString(),
    id: newRecordId(now),
    profile: capThenRedact(input.profile, AUDIT_PROFILE_MAX_BYTES).text,
    tool: input.tool,
    command,
    description,
    approval: {
      mode: input.approval.mode,
      decision: input.approval.decision,
      // Smart-mode reasons are supplied by an external LLM. Bound them before
      // JSONL serialization just like captured output so one oversized response
      // cannot bypass auditMaxBytes or make the general redactor scan megabytes.
      reason: capThenRedact(input.approval.reason, cap).text,
      decided_at: input.approval.decided_at,
      decided_by: input.approval.decided_by,
    },
  };

  if (input.exec) {
    const so = capThenRedact(input.exec.stdout, cap);
    const se = capThenRedact(input.exec.stderr, cap);
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

const DEFAULT_TAIL_BUFFER = 1000;

export class AuditStore extends EventEmitter {
  private readonly auditDir: string;
  private readonly auditMaxBytes: number;
  private readonly maxFileBytes: number;
  private readonly retain: number;
  private readonly tailBufferSize: number;
  /** Rolling in-memory tail for read-only WebUI /api/executions. */
  private readonly tailBuffer: AuditRecord[] = [];

  /** Track which day we last pruned, so we only prune once per day. */
  private lastPruneStamp: string | null = null;

  constructor(cfg: AuditStoreConfig & { tailBufferSize?: number }) {
    super();
    this.auditDir = cfg.auditDir;
    // Clamp config against negative / non-finite (NaN, Infinity) values so a
    // bad caller cannot produce surprising behavior: negative auditMaxBytes
    // silently empties output, NaN maxFileBytes rotates on every append, and
    // retain <= 0 breaks rotation/prune. Fall back to the documented default
    // for anything non-finite, and floor to a safe minimum otherwise.
    this.auditMaxBytes =
      typeof cfg.auditMaxBytes === 'number' && !Number.isInteger(cfg.auditMaxBytes)
        ? // A fractional cap must not floor: a value in (0, 1) would become 0
          // and silently empty every capture, conflating with the explicit
          // "capture nothing" 0. Byte counts are integer-only, so any
          // non-integer falls back to the documented default (Codex
          // 3556038524). The TOML loader also rejects fractional
          // [server].audit_max_bytes at parse time; this guards direct
          // AuditStore callers.
          DEFAULT_AUDIT_MAX_BYTES
        : clampInt(cfg.auditMaxBytes, DEFAULT_AUDIT_MAX_BYTES, 0);
    this.maxFileBytes = clampInt(cfg.maxFileBytes, DEFAULT_MAX_FILE_BYTES, 1);
    this.retain = clampInt(cfg.retain, DEFAULT_RETAIN, 1);
    this.tailBufferSize = cfg.tailBufferSize ?? DEFAULT_TAIL_BUFFER;
    // Audit logs contain command lines + captured output; keep them
    // owner-only. mkdir mode is masked by umask, so chmod afterwards to
    // enforce 0700 on both freshly-created and pre-existing directories.
    fs.mkdirSync(this.auditDir, { recursive: true, mode: 0o700 });
    try {
      fs.chmodSync(this.auditDir, 0o700);
    } catch {
      // best-effort: dir may live on a filesystem that ignores chmod
    }
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
    // Owner-only (0600). The mode option only applies when the file is
    // created, and is masked by umask; chmod enforces it on first create AND
    // on files that already exist with a permissive mode — a file pre-created
    // by an operator or left 0644 by an older setup must not keep that mode
    // while new records with commands/output are appended (Codex 3568536819).
    // The pre-append stat replaces the previous existence probe, so the hot
    // path costs no extra syscall; chmod only fires when the mode is wrong.
    let existingMode: number | null = null;
    try {
      existingMode = fs.statSync(filePath).mode & 0o777;
    } catch {
      // File does not exist yet — created by the append below.
    }
    fs.appendFileSync(filePath, line, { encoding: 'utf8', mode: 0o600 });
    if (existingMode !== 0o600) {
      try {
        fs.chmodSync(filePath, 0o600);
      } catch {
        // best-effort
      }
    }

    this.tailBuffer.push(rec);
    if (this.tailBuffer.length > this.tailBufferSize) {
      this.tailBuffer.splice(0, this.tailBuffer.length - this.tailBufferSize);
    }

    const stamp = utcDateStamp(now);
    if (this.lastPruneStamp !== stamp) {
      this.lastPruneStamp = stamp;
      try {
        pruneOldDays(this.auditDir, this.retain, now);
      } catch {
        // best-effort
      }
      // Mirror the on-disk prune in the in-memory tail: records already
      // copied into tailBuffer would otherwise stay visible through
      // /api/executions past the retain window that just removed them from
      // disk (Codex 3556038510). tail() also filters at read time, so this
      // is a memory-hygiene sweep, not the only guard.
      this.dropExpiredFromTail(now);
    }
    // Notify WebUI SSE subscribers after the line is flushed to disk so an
    // event only fires for records that were actually persisted.
    try {
      this.emit('execution', rec);
    } catch {
      /* listener errors must not affect the audit path */
    }

    return rec;
  }

  /** Read the most-recent records from the in-memory tail, optionally filtered by profile. */
  async tail(opts: { profile?: string; limit: number }): Promise<AuditRecord[]> {
    // Apply retention at read time as well as at prune time: the day-boundary
    // prune only fires on an append, so a long-lived low-traffic server could
    // otherwise keep serving expired records through /api/executions until
    // the next write arrives (Codex 3556038510).
    this.dropExpiredFromTail(new Date());
    const rows = opts.profile
      ? this.tailBuffer.filter(r => r.profile === opts.profile)
      : this.tailBuffer.slice();
    const limit = Math.max(1, opts.limit);
    return rows.slice(-limit);
  }

  /**
   * Remove records older than the retention window from the in-memory tail,
   * using the SAME cutoff stamp as the on-disk `pruneOldDays` so the WebUI
   * tail can never outlive the JSONL files backing it.
   */
  private dropExpiredFromTail(asOf: Date): void {
    const cutoffStamp = retentionCutoffStamp(this.retain, asOf);
    for (let i = this.tailBuffer.length - 1; i >= 0; i--) {
      // Record ts is `Date.toISOString()` (UTC), so the first 10 chars are
      // YYYY-MM-DD; strip the dashes to compare against the YYYYMMDD stamp.
      const recStamp = this.tailBuffer[i].ts.slice(0, 10).replace(/-/g, '');
      if (recStamp < cutoffStamp) {
        this.tailBuffer.splice(i, 1);
      }
    }
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
