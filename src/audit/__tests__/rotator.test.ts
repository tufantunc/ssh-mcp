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

  it('prunes old day-rolled files but retains newest distinct days', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-prune-'));
    try {
      for (const day of ['20260520', '20260521', '20260522']) {
        writeFileSync(join(dir, `executions-${day}.jsonl`), day);
      }
      const removed = pruneOldDays(dir, 2);
      expect(removed.some(p => p.endsWith('executions-20260520.jsonl'))).toBe(true);
      expect(existsSync(join(dir, 'executions-20260521.jsonl'))).toBe(true);
      expect(existsSync(join(dir, 'executions-20260522.jsonl'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
