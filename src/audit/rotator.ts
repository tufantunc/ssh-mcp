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
 * Prune day-rolled files older than `retainDays` from the audit directory.
 * Returns paths removed.
 */
export function pruneOldDays(
  auditDir: string,
  retainDays: number = DEFAULT_RETAIN,
): string[] {
  let entries: string[];
  try {
    entries = fs.readdirSync(auditDir);
  } catch {
    return [];
  }
  const re = /^executions-(\d{8})\.jsonl(?:\.\d+)?$/;
  const dates: { date: string; file: string }[] = [];
  for (const name of entries) {
    const m = re.exec(name);
    if (m) dates.push({ date: m[1], file: name });
  }
  if (dates.length === 0) return [];
  dates.sort((a, b) => b.date.localeCompare(a.date)); // newest first
  // Keep distinct dates up to retainDays; remove anything older.
  const keepDates = new Set<string>();
  for (const d of dates) {
    keepDates.add(d.date);
    if (keepDates.size >= retainDays) break;
  }
  const removed: string[] = [];
  for (const d of dates) {
    if (!keepDates.has(d.date)) {
      const p = path.join(auditDir, d.file);
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
