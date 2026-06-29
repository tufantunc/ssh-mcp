import { mkdtempSync, readFileSync, rmSync, existsSync, readdirSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { describe, expect, it } from 'vitest';

import {
  AuditStore,
  activeFilePath,
  buildRecord,
  capThenRedact,
  yoloApproval,
  REDACT_SCAN_HEADROOM_BYTES,
} from '../store.js';

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

  it('creates the audit dir 0700 and JSONL files 0600 under a permissive umask', () => {
    const prevMask = process.umask(0o022);
    const dir = join(tmpAuditDir(), 'nested');
    try {
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 100 });
      const now = new Date('2026-05-25T12:00:00Z');
      store.append({ now, profile: 'p', tool: 'exec', command: 'date', approval: yoloApproval(now), exec: { stdout: 'x', stderr: '', exitCode: 0, durationMs: 1 } });

      // 0o777 mask isolates the permission bits from file-type bits.
      const dirMode = statSync(dir).mode & 0o777;
      const fileMode = statSync(activeFilePath(dir, now)).mode & 0o777;
      expect(dirMode).toBe(0o700);
      expect(fileMode).toBe(0o600);
    } finally {
      process.umask(prevMask);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('redacts a secret that lands far past the cap before truncating (large output)', () => {
    const dir = tmpAuditDir();
    try {
      const cap = 64;
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: cap });
      const now = new Date('2026-05-25T12:00:00Z');
      // Secret placed well beyond the final cap but inside the scan headroom.
      const filler = 'A'.repeat(cap + 100);
      const secret = 'ghp_' + 'B'.repeat(36);
      const rec = store.append({
        now,
        profile: 'p',
        tool: 'exec',
        command: 'dump',
        approval: yoloApproval(now),
        exec: { stdout: `${filler} ${secret} tail`, stderr: '', exitCode: 0, durationMs: 1 },
      });
      const file = activeFilePath(dir, now);
      const persisted = readFileSync(file, 'utf8');
      // The capped record must never carry the verbatim secret...
      expect(persisted).not.toContain(secret);
      expect(rec.exec?.stdout).not.toContain(secret);
      // ...and the kept stdout is bounded to the cap.
      expect(Buffer.byteLength(rec.exec?.stdout ?? '', 'utf8')).toBeLessThanOrEqual(cap);
      expect(rec.exec?.stdout_truncated).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not slice a boundary-straddling token into a partial-secret leak', () => {
    const cap = 32;
    // The secret token STARTS inside the kept cap window (after a word
    // boundary) but EXTENDS past it. A naive cap-then-redact would keep only
    // the token's prefix — too short for the {20,255} body matcher — leaving a
    // partial secret verbatim. The scan headroom must let the redactor match
    // the whole token and replace it with <redacted>.
    const secret = 'ghp_' + 'C'.repeat(36);
    const prefix = 'x'.repeat(cap - 11) + ' '; // ends on a word boundary
    const out = capThenRedact(`${prefix}${secret}`, cap);
    // No fragment of the secret body should survive (would be a partial leak).
    expect(out.text).not.toContain('ghp_');
    expect(out.text).not.toContain('CCCC');
    expect(out.text).toContain('<redacted>');
  });

  it('caps the redactor scan window to cap + headroom (does not redact unbounded input)', () => {
    const cap = 16;
    // A secret placed beyond cap + headroom is outside the scan window: it gets
    // truncated away by the first bounding cap, never reaching the persisted slice.
    const secret = 'ghp_' + 'D'.repeat(36);
    const filler = 'z'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 50);
    const out = capThenRedact(`${filler}${secret}`, cap);
    expect(out.text).not.toContain(secret);
    expect(Buffer.byteLength(out.text, 'utf8')).toBeLessThanOrEqual(cap);
    expect(out.truncated).toBe(true);
  });
});
