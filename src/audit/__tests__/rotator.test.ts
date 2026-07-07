import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { describe, expect, it } from 'vitest';

import { rotateIfNeeded, pruneOldDays } from '../rotator.js';

describe('audit rotator', () => {
  it('rotates active file when size cap is reached and keeps retention', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-rotator-'));
    try {
      const file = join(dir, 'executions-20260525.jsonl');
      writeFileSync(file, '0123456789');
      writeFileSync(`${file}.1`, 'old1');
      writeFileSync(`${file}.2`, 'old2');

      expect(rotateIfNeeded({ filePath: file, maxFileBytes: 10, retain: 2 })).toBe(1);
      expect(existsSync(file)).toBe(false);
      expect(readFileSync(`${file}.1`, 'utf8')).toBe('0123456789');
      expect(readFileSync(`${file}.2`, 'utf8')).toBe('old1');
      expect(existsSync(`${file}.3`)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('prunes files older than the retention window by age (not by count of distinct days)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-prune-'));
    try {
      for (const day of ['20260520', '20260521', '20260522']) {
        writeFileSync(join(dir, `executions-${day}.jsonl`), day);
      }
      // asOf = 2026-05-22, retain=2 → window is [05-21, 05-22]; 05-20 is out.
      const removed = pruneOldDays(dir, 2, new Date('2026-05-22T00:00:00Z'));
      expect(removed.some(p => p.endsWith('executions-20260520.jsonl'))).toBe(true);
      expect(existsSync(join(dir, 'executions-20260521.jsonl'))).toBe(true);
      expect(existsSync(join(dir, 'executions-20260522.jsonl'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('prunes an old file past the window even when few distinct dates exist (gap in usage)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-prune-gap-'));
    try {
      // Only two distinct dates on disk, far apart. The count-based prune kept
      // the old May file (2 distinct <= retain=10); age-based prune removes it.
      writeFileSync(join(dir, 'executions-20260501.jsonl'), 'old');
      writeFileSync(join(dir, 'executions-20260701.jsonl'), 'today');
      const removed = pruneOldDays(dir, 10, new Date('2026-07-01T00:00:00Z'));
      expect(removed.some(p => p.endsWith('executions-20260501.jsonl'))).toBe(true);
      expect(existsSync(join(dir, 'executions-20260501.jsonl'))).toBe(false);
      expect(existsSync(join(dir, 'executions-20260701.jsonl'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('prunes rotated siblings (.jsonl.N) sharing an out-of-window date', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-prune-sib-'));
    try {
      writeFileSync(join(dir, 'executions-20260501.jsonl'), 'a');
      writeFileSync(join(dir, 'executions-20260501.jsonl.1'), 'b');
      writeFileSync(join(dir, 'executions-20260501.jsonl.2'), 'c');
      writeFileSync(join(dir, 'executions-20260701.jsonl'), 'today');
      const removed = pruneOldDays(dir, 5, new Date('2026-07-01T00:00:00Z'));
      expect(removed.filter(p => /executions-20260501\.jsonl(\.\d+)?$/.test(p))).toHaveLength(3);
      expect(existsSync(join(dir, 'executions-20260501.jsonl.1'))).toBe(false);
      expect(existsSync(join(dir, 'executions-20260501.jsonl.2'))).toBe(false);
      expect(existsSync(join(dir, 'executions-20260701.jsonl'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
