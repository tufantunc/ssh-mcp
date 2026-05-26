import { mkdtempSync, readFileSync, rmSync, existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { describe, expect, it } from 'vitest';

import { AuditStore, activeFilePath, buildRecord, yoloApproval } from '../store.js';

function tmpAuditDir() {
  return mkdtempSync(join(tmpdir(), 'ssh-mcp-audit-'));
}

describe('audit store', () => {
  it('appends one JSONL record with redacted command and capped output', () => {
    const dir = tmpAuditDir();
    try {
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 5 });
      const now = new Date('2026-05-25T12:00:00.000Z');
      const rec = store.append({
        now,
        profile: 'default',
        tool: 'exec',
        command: 'echo --password=secret',
        description: 'uses token abc',
        approval: yoloApproval(now),
        exec: { stdout: 'abcdef', stderr: '秘密資料', exitCode: 0, durationMs: 12 },
      });

      const file = activeFilePath(dir, now);
      const line = readFileSync(file, 'utf8').trim();
      const parsed = JSON.parse(line);
      expect(parsed.id).toBe(rec.id);
      expect(parsed.command).toContain('--password=<redacted>');
      expect(parsed.command).not.toContain('secret');
      expect(parsed.description).toBe('uses token <redacted>');
      expect(parsed.exec.stdout).toBe('abcde');
      expect(parsed.exec.stdout_truncated).toBe(true);
      expect(Buffer.byteLength(parsed.exec.stderr, 'utf8')).toBeLessThanOrEqual(5);
      expect(parsed.exec.stderr_truncated).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rolls on UTC day boundary by writing to date-specific files', () => {
    const dir = tmpAuditDir();
    try {
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 100 });
      store.append({ now: new Date('2026-05-25T23:59:59Z'), profile: 'p', tool: 'exec', command: 'date', approval: yoloApproval(), exec: { stdout: '', stderr: '', exitCode: 0, durationMs: 1 } });
      store.append({ now: new Date('2026-05-26T00:00:00Z'), profile: 'p', tool: 'exec', command: 'date', approval: yoloApproval(), exec: { stdout: '', stderr: '', exitCode: 0, durationMs: 1 } });
      expect(existsSync(join(dir, 'executions-20260525.jsonl'))).toBe(true);
      expect(existsSync(join(dir, 'executions-20260526.jsonl'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('size-rolls before append and retains rotated files', () => {
    const dir = tmpAuditDir();
    try {
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 100, maxFileBytes: 1, retain: 2 });
      const now = new Date('2026-05-25T12:00:00Z');
      for (let i = 0; i < 4; i++) {
        store.append({ now, profile: 'p', tool: 'exec', command: `echo ${i}`, approval: yoloApproval(now), exec: { stdout: 'x', stderr: '', exitCode: 0, durationMs: 1 } });
      }
      const files = readdirSync(dir).sort();
      expect(files).toContain('executions-20260525.jsonl');
      expect(files).toContain('executions-20260525.jsonl.1');
      expect(files).toContain('executions-20260525.jsonl.2');
      expect(files).not.toContain('executions-20260525.jsonl.3');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('buildRecord redacts stdout/stderr without filesystem IO', () => {
    const bearer = 'Bearer ' + 'abc.def.ghi';
    const rec = buildRecord({
      now: new Date('2026-05-25T12:00:00Z'),
      profile: 'stub',
      tool: 'exec',
      command: 'cat',
      approval: yoloApproval(),
      exec: { stdout: `Authorization: ${bearer}`, stderr: 'ok', exitCode: 0, durationMs: 1 },
    });
    expect(rec.exec?.stdout).toContain('Bearer <redacted>');
  });
});
