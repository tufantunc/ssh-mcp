/**
 * Audit log rotation.
 *
 * Two triggers:
 *   1. Day boundary — the active file's name is derived from the UTC date,
 *      so writes naturally land in a fresh file. The rotator additionally
 *      prunes files older than `retain` days, regardless of size.
 *   2. Size cap — when the current file exceeds `maxFileBytes`, it is renamed
 *      with a numeric suffix (`.1`, `.2`, ...) shifted on each rotation,
 *      retaining at most `retain` historical files.
 *
 * The store calls `rotateIfNeeded` before each append; the rotator is the
 * single owner of file lifecycle. Synchronous fs calls used deliberately:
 * the audit volume is small (one line per exec) and serialization avoids
 * concurrent-rename races.
 */

import * as fs from 'fs';
import * as path from 'path';

import { DEFAULT_MAX_FILE_BYTES, DEFAULT_RETAIN } from './types.js';

export interface RotateOptions {
  /** Absolute path to the active file (executions-YYYYMMDD.jsonl). */
  filePath: string;
  /** Size cap before rotation. */
  maxFileBytes?: number;
  /** Number of rotated files to keep (excluding the active file). */
  retain?: number;
}

/**
 * Rotate `filePath` if its current size on disk is >= maxFileBytes.
 * Returns the rotation count performed (0 or 1).
 */
export function rotateIfNeeded(opts: RotateOptions): number {
  const maxBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const retain = opts.retain ?? DEFAULT_RETAIN;

  let size: number;
  try {
    size = fs.statSync(opts.filePath).size;
  } catch {
    return 0;
  }
  if (size < maxBytes) return 0;
  rotate(opts.filePath, retain);
  return 1;
}

/**
 * Shift `filePath` → `filePath.1`, `.1` → `.2`, ... , drop tail past `retain`.
 */
export function rotate(filePath: string, retain: number = DEFAULT_RETAIN): void {
  // Walk from the tail down to 0 so we don't clobber.
  // Step 1: remove `filePath.retain` if it exists.
  const tail = `${filePath}.${retain}`;
  if (fs.existsSync(tail)) {
    fs.unlinkSync(tail);
  }
  // Step 2: shift .N -> .N+1 for N in [retain-1 .. 1].
  for (let n = retain - 1; n >= 1; n--) {
    const src = `${filePath}.${n}`;
    const dst = `${filePath}.${n + 1}`;
    if (fs.existsSync(src)) {
      fs.renameSync(src, dst);
    }
  }
  // Step 3: move active -> .1.
  if (fs.existsSync(filePath)) {
    fs.renameSync(filePath, `${filePath}.1`);
  }
}

/**
 * Retention cutoff as a UTC YYYYMMDD stamp: `asOf - (retainDays - 1)` days,
 * so the window always includes today plus the previous `retainDays - 1`
 * calendar days. Anything whose date stamp is lexicographically < this stamp
 * is outside the retention window (string comparison is valid because
 * YYYYMMDD is zero-padded and monotonic). Shared by the on-disk prune below
 * and the AuditStore in-memory tail filter so both apply the SAME window
 * (Codex 3556038510).
 */
export function retentionCutoffStamp(
  retainDays: number = DEFAULT_RETAIN,
  asOf: Date = new Date(),
): string {
  const keep = Math.max(1, Math.floor(retainDays));
  const cutoffDate = new Date(
    Date.UTC(asOf.getUTCFullYear(), asOf.getUTCMonth(), asOf.getUTCDate()) -
      (keep - 1) * 24 * 60 * 60 * 1000,
  );
  const cy = cutoffDate.getUTCFullYear().toString().padStart(4, '0');
  const cm = (cutoffDate.getUTCMonth() + 1).toString().padStart(2, '0');
  const cd = cutoffDate.getUTCDate().toString().padStart(2, '0');
  return `${cy}${cm}${cd}`;
}

/**
 * Prune day-rolled files older than `retainDays` from the audit directory.
 *
 * Retention is by AGE, not by count of distinct dates: a file is removed when
 * its embedded date is strictly older than the cutoff (`asOf` minus
 * `retainDays - 1` days, so the cutoff window always includes today plus the
 * previous `retainDays - 1` calendar days). This guarantees data never lives
 * past the advertised window even when usage has gaps — e.g. with retain=10, an
 * `executions-20260501.jsonl` file is pruned once "today" is 2026-07-01 even
 * though only two distinct dates exist on disk. Rotated siblings
 * (`.jsonl.1`, `.jsonl.2`, ...) share the active file's date and are pruned
 * with it.
 *
 * `asOf` defaults to the current date; callers pass the append date so pruning
 * is anchored to the write that triggered it. Returns paths removed.
 */
export function pruneOldDays(
  auditDir: string,
  retainDays: number = DEFAULT_RETAIN,
  asOf: Date = new Date(),
): string[] {
  let entries: string[];
  try {
    entries = fs.readdirSync(auditDir);
  } catch {
    return [];
  }
  const re = /^executions-(\d{8})\.jsonl(?:\.\d+)?$/;
  // Cutoff = asOf - (retainDays - 1) days, as a YYYYMMDD stamp. Files whose
  // date stamp is lexicographically < cutoff are outside the window. String
  // comparison is valid because YYYYMMDD is zero-padded and monotonic.
  const cutoffStamp = retentionCutoffStamp(retainDays, asOf);

  const removed: string[] = [];
  for (const name of entries) {
    const m = re.exec(name);
    if (!m) continue;
    if (m[1] < cutoffStamp) {
      const p = path.join(auditDir, name);
      try {
        fs.unlinkSync(p);
        removed.push(p);
      } catch {
        // best-effort
      }
    }
  }
  return removed;
}
