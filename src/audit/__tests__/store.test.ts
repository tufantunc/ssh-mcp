import { mkdtempSync, readFileSync, rmSync, existsSync, readdirSync, statSync } from 'fs';
import { tmpdir, homedir } from 'os';
import { join } from 'path';
import { describe, expect, it } from 'vitest';

import {
  AuditStore,
  activeFilePath,
  buildRecord,
  capThenRedact,
  clampInt,
  resolveAuditDir,
  utcDateStamp,
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

  it('redacts an open quoted secret before a cap can persist its prefix', () => {
    const cap = 64;
    const secretPrefix = 'S'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 1000);
    const out = capThenRedact(`run --password="${secretPrefix}" tail`, cap);

    expect(out.text).toContain('--password=<redacted>');
    expect(out.text).not.toContain('SSSS');
    expect(Buffer.byteLength(out.text, 'utf8')).toBeLessThanOrEqual(cap);
    expect(out.truncated).toBe(true);
  });

  it('redacts an open quoted JSON secret before a cap can persist its prefix', () => {
    const cap = 64;
    const secretPrefix = 'J'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 1000);
    const out = capThenRedact(`{"password":"${secretPrefix}"}`, cap);

    expect(out.text).toContain('"password":"<redacted>"');
    expect(out.text).not.toContain('JJJJ');
    expect(Buffer.byteLength(out.text, 'utf8')).toBeLessThanOrEqual(cap);
    expect(out.truncated).toBe(true);
  });

  it('redacts an open quoted nested API token before a cap can persist its prefix', () => {
    const cap = 64;
    const value = 'J'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 1000);
    const out = capThenRedact(`{"nested":{"api_token":"${value}"}}`, cap);

    expect(out.text).toContain('"api_token":"<redacted>"');
    expect(out.text).not.toContain('JJJJ');
    expect(Buffer.byteLength(out.text, 'utf8')).toBeLessThanOrEqual(cap);
    expect(out.truncated).toBe(true);
  });

  it('redacts a quoted attached -p password whose closing quote falls past the scan window', () => {
    const cap = 64;
    const value = 'M'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 1000);
    const out = capThenRedact(`mysql -p"${value}"`, cap);

    expect(out.text).toContain('mysql -p<redacted>');
    expect(out.text).not.toContain('MMMM');
    expect(Buffer.byteLength(out.text, 'utf8')).toBeLessThanOrEqual(cap);
    expect(out.truncated).toBe(true);
  });

  it('redacts a URL userinfo password whose at-sign falls past the scan window', () => {
    const cap = 64;
    const password = 'U'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 1000);
    const out = capThenRedact(`clone https://alice:${password}@example.com/repo.git`, cap);

    expect(out.text).toContain('https://alice:<redacted>@example.com');
    expect(out.text).not.toContain('UUUU');
    expect(Buffer.byteLength(out.text, 'utf8')).toBeLessThanOrEqual(cap);
  });

  it('caps and redacts profile names before serializing records', () => {
    const secret = 'ghp_' + 'P'.repeat(36);
    const rec = buildRecord({
      now: new Date('2026-05-25T12:00:00Z'),
      profile: `prod-${secret}-${'x'.repeat(2 * 1024 * 1024)}`,
      tool: 'exec',
      command: 'date',
      approval: yoloApproval(),
      auditMaxBytes: 64,
    });

    expect(rec.profile).not.toContain(secret);
    expect(rec.profile).toContain('<redacted>');
    expect(Buffer.byteLength(rec.profile, 'utf8')).toBeLessThanOrEqual(1024);
  });

  it('caps and redacts externally-controlled approval reasons', () => {
    const secret = 'ghp_' + 'R'.repeat(36);
    const rec = buildRecord({
      now: new Date('2026-05-25T12:00:00Z'),
      profile: 'prod',
      tool: 'exec',
      command: 'date',
      approval: {
        ...yoloApproval(),
        mode: 'smart',
        reason: `Bearer ${secret} ${'x'.repeat(2 * 1024 * 1024)}`,
        decided_by: 'smart-llm',
      },
      auditMaxBytes: 64,
    });

    expect(rec.approval.reason).not.toContain(secret);
    expect(rec.approval.reason).toContain('<redacted>');
    expect(Buffer.byteLength(rec.approval.reason, 'utf8')).toBeLessThanOrEqual(64);
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

  it('redacts a PEM private key whose END marker falls past the scan window', () => {
    const cap = 64;
    // Body large enough that the END terminator sits well beyond cap + headroom.
    // Under the old cap-before-redact ordering the terminator-anchored PEM_RE
    // could not match, leaving raw key material in the persisted slice.
    const begin = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----';
    const end = '-----END ' + 'OPENSSH PRIVATE KEY-----';
    const body = 'A'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 2000);
    const pem = `${begin}\n${body}\n${end}`;
    const out = capThenRedact(`prefix ${pem} suffix`, cap);
    expect(out.text).not.toContain('AAAA');
    expect(out.text).not.toContain('PRIVATE KEY');
    expect(out.text).toContain('<redacted>');
  });

  it('redacts a truncated PEM key with no END terminator (dangling BEGIN)', () => {
    const cap = 64;
    // A key whose END marker was truncated away entirely. The dangling-BEGIN
    // fallback must redact from the header to end-of-string so no raw key
    // material persists even without a reachable terminator.
    const begin = '-----BEGIN ' + 'RSA PRIVATE KEY-----';
    const body = 'K'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 500);
    const out = capThenRedact(`log ${begin}\n${body}`, cap);
    expect(out.text).not.toContain('KKKK');
    expect(out.text).not.toContain('PRIVATE KEY');
    expect(out.text).toContain('<redacted>');
  });

  it('redacts a long JWT whose signature falls past the scan window (Codex 3541772953)', () => {
    const cap = 64;
    // A JWT that STARTS inside the retained window but whose large payload/
    // signature pushes the third segment past cap + headroom. Under a
    // cap-before-redact ordering the JWT regex could not see a complete token,
    // leaving the token prefix in the persisted slice. Pre-redaction over the
    // full text must scrub the whole token.
    const header = 'eyJ' + 'a'.repeat(20);
    const payload = 'eyJ' + 'b'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 1000); // huge claims
    const sig = 'c'.repeat(50);
    const jwt = `${header}.${payload}.${sig}`;
    const out = capThenRedact(`token ${jwt} tail`, cap);
    expect(out.text).not.toContain(header);
    expect(out.text).not.toContain('eyJbbbb');
    expect(out.text).not.toContain(sig);
    expect(out.text).toContain('<redacted>');
  });

  it('redacts URL userinfo when the @ delimiter falls past the scan window', () => {
    const cap = 96;
    const password = 'p'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 1000);
    const out = capThenRedact(`clone https://alice:${password}@example.com/repo.git`, cap);
    expect(out.text).toContain('https://alice:<redacted>@example.com');
    expect(out.text).not.toContain('pppp');
  });

  it('caps a huge rejected command so it cannot bypass the size guard (Codex 3541772945)', () => {
    // A multi-MB command (e.g. a rejected over-maxChars payload) must not be
    // persisted verbatim — buildRecord caps command/description to bound the
    // JSONL append and redaction cost.
    const huge = 'A'.repeat(5 * 1024 * 1024); // 5 MB
    const rec = buildRecord({
      now: new Date('2026-05-25T12:00:00Z'),
      profile: 'p',
      tool: 'exec',
      command: huge,
      description: 'B'.repeat(5 * 1024 * 1024),
      approval: yoloApproval(),
      auditMaxBytes: 64,
    });
    // Bounded well under the raw 5 MB — the command cap floor keeps it modest.
    expect(Buffer.byteLength(rec.command, 'utf8')).toBeLessThanOrEqual(64 * 1024);
    expect(Buffer.byteLength(rec.description ?? '', 'utf8')).toBeLessThanOrEqual(64 * 1024);
    expect(rec.command.length).toBeLessThan(huge.length);
  });

  it('preserves a normal short command even when auditMaxBytes (output cap) is tiny', () => {
    // The command cap must not collapse to a tiny stdout cap: a legitimate
    // command line survives in full while output capture is set to a few bytes.
    const rec = buildRecord({
      now: new Date('2026-05-25T12:00:00Z'),
      profile: 'p',
      tool: 'exec',
      command: 'systemctl restart nginx && journalctl -u nginx --since "10 min ago"',
      approval: yoloApproval(),
      auditMaxBytes: 5,
    });
    expect(rec.command).toBe('systemctl restart nginx && journalctl -u nginx --since "10 min ago"');
  });

  it('caps a huge command that carries a secret past the window without leaking it', () => {
    // Belt-and-suspenders: a giant command with an embedded token must be both
    // bounded AND scrubbed of the token.
    const secret = 'ghp_' + 'Z'.repeat(36);
    const rec = buildRecord({
      now: new Date('2026-05-25T12:00:00Z'),
      profile: 'p',
      tool: 'exec',
      command: 'echo ' + 'x'.repeat(2 * 1024 * 1024) + ' ' + secret,
      approval: yoloApproval(),
      auditMaxBytes: 64,
    });
    expect(rec.command).not.toContain(secret);
    expect(Buffer.byteLength(rec.command, 'utf8')).toBeLessThanOrEqual(64 * 1024);
  });

  it('persists a redacted PEM key end-to-end through append (large key past window)', () => {
    const dir = tmpAuditDir();
    try {
      const cap = 128;
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: cap });
      const now = new Date('2026-05-25T12:00:00Z');
      const begin = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----';
      const end = '-----END ' + 'OPENSSH PRIVATE KEY-----';
      const body = 'Z'.repeat(cap + REDACT_SCAN_HEADROOM_BYTES + 3000);
      const pem = `${begin}\n${body}\n${end}`;
      const rec = store.append({
        now,
        profile: 'p',
        tool: 'exec',
        command: 'cat id_ed25519',
        approval: yoloApproval(now),
        exec: { stdout: pem, stderr: '', exitCode: 0, durationMs: 1 },
      });
      const persisted = readFileSync(activeFilePath(dir, now), 'utf8');
      expect(persisted).not.toContain('ZZZZ');
      expect(persisted).not.toContain('PRIVATE KEY');
      expect(rec.exec?.stdout).toContain('<redacted>');
      expect(rec.exec?.stdout).not.toContain('ZZZZ');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('clamps negative / non-finite config to safe values (no empty output, no per-append rotation, retain >= 1)', () => {
    // clampInt unit behavior across the surprising inputs Copilot flagged.
    expect(clampInt(NaN, 10, 1)).toBe(10);
    expect(clampInt(Infinity, 10, 1)).toBe(10);
    expect(clampInt(-Infinity, 10, 1)).toBe(10);
    expect(clampInt(undefined, 10, 1)).toBe(10);
    expect(clampInt(null, 10, 1)).toBe(10);
    expect(clampInt(-5, 99, 1)).toBe(99); // negative < minValid -> fallback (not floored to min)
    expect(clampInt(-5, 99, 0)).toBe(99); // negative < 0 -> fallback
    expect(clampInt(0, 99, 0)).toBe(0); // explicit 0 honored when minValid is 0
    expect(clampInt(0, 99, 1)).toBe(99); // 0 below minValid 1 -> fallback
    expect(clampInt(3.9, 99, 1)).toBe(3); // floored to integer

    // End-to-end: a store built with garbage config still writes a non-empty,
    // single record (negative auditMaxBytes would otherwise empty stdout, NaN
    // maxFileBytes would rotate on every append).
    const dir = tmpAuditDir();
    try {
      const store = new AuditStore({
        auditDir: dir,
        auditMaxBytes: -100,
        maxFileBytes: NaN,
        retain: -3,
      });
      const now = new Date('2026-05-25T12:00:00.000Z');
      store.append({
        now,
        profile: 'default',
        tool: 'exec',
        command: 'echo hello',
        approval: yoloApproval(now),
        exec: { stdout: 'output-visible', stderr: '', exitCode: 0, durationMs: 1 },
      });
      const file = activeFilePath(dir, now);
      // Only the active file exists — no spurious rotation from NaN maxFileBytes.
      const rotated = readdirSync(dir).filter((f) => /\.jsonl\.\d+$/.test(f));
      expect(rotated).toHaveLength(0);
      const parsed = JSON.parse(readFileSync(file, 'utf8').trim());
      // auditMaxBytes clamped to >= 0 default, so stdout is retained, not emptied.
      expect(parsed.exec.stdout.length).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects an empty audit_dir instead of resolving to cwd (Codex 3556038508)', () => {
    const savedEnv = process.env.SSH_MCP_AUDIT_DIR;
    try {
      delete process.env.SSH_MCP_AUDIT_DIR;
      const home = join(homedir(), '.ssh-mcp');
      // Empty / whitespace-only override falls back to the default, never cwd.
      expect(resolveAuditDir('')).toBe(home);
      expect(resolveAuditDir('   ')).toBe(home);
      // Empty env override is also ignored.
      process.env.SSH_MCP_AUDIT_DIR = '';
      expect(resolveAuditDir(undefined)).toBe(home);
      expect(resolveAuditDir(undefined)).not.toBe(process.cwd());
      // A real env value still wins over the default.
      process.env.SSH_MCP_AUDIT_DIR = '/tmp/ssh-mcp-audit-env';
      expect(resolveAuditDir(undefined)).toBe('/tmp/ssh-mcp-audit-env');
      // ...and an explicit non-empty override wins over env.
      expect(resolveAuditDir('/tmp/ssh-mcp-audit-override')).toBe('/tmp/ssh-mcp-audit-override');
    } finally {
      if (savedEnv === undefined) delete process.env.SSH_MCP_AUDIT_DIR;
      else process.env.SSH_MCP_AUDIT_DIR = savedEnv;
    }
  });

  it('falls back to the default for a fractional auditMaxBytes instead of flooring to 0 (Codex 3556038524)', () => {
    const dir = tmpAuditDir();
    try {
      // 0.5 would floor to 0 and silently empty every capture; it must fall
      // back to the documented default instead.
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 0.5 });
      const now = new Date('2026-05-25T12:00:00.000Z');
      const rec = store.append({
        now,
        profile: 'default',
        tool: 'exec',
        command: 'echo hello',
        approval: yoloApproval(now),
        exec: { stdout: 'output-visible', stderr: '', exitCode: 0, durationMs: 1 },
      });
      expect(rec.exec?.stdout).toBe('output-visible');
      expect(rec.exec?.stdout_truncated).toBe(false);
      // Explicit integer 0 ("capture nothing") is still honored.
      const zeroStore = new AuditStore({ auditDir: dir, auditMaxBytes: 0 });
      const zeroRec = zeroStore.append({
        now,
        profile: 'default',
        tool: 'exec',
        command: 'echo hello',
        approval: yoloApproval(now),
        exec: { stdout: 'output-visible', stderr: '', exitCode: 0, durationMs: 1 },
      });
      expect(zeroRec.exec?.stdout).toBe('');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('drops expired records from the in-memory tail with the same retention window as disk (Codex 3556038510)', async () => {
    const dir = tmpAuditDir();
    try {
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 100, retain: 2 });
      const base = {
        profile: 'p',
        tool: 'exec' as const,
        exec: { stdout: '', stderr: '', exitCode: 0, durationMs: 1 },
      };
      // Relative dates: tail() also filters against the real clock at read
      // time, so anchor the fixture to "now" rather than fixed past dates.
      const now = new Date();
      const old = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000);
      // Old record enters the tail buffer (and its own dated file).
      store.append({ ...base, now: old, command: 'echo old-day', approval: yoloApproval(old) });
      // Today's append crosses the day boundary: retain=2 prunes the 5-day-old
      // file from disk; the in-memory tail must drop its record with the same
      // cutoff instead of serving it through /api/executions.
      store.append({ ...base, now, command: 'echo today', approval: yoloApproval(now) });
      expect(existsSync(join(dir, `executions-${utcDateStamp(old)}.jsonl`))).toBe(false);
      const rows = await store.tail({ limit: 10 });
      const commands = rows.map(r => r.command);
      expect(commands).toContain('echo today');
      expect(commands).not.toContain('echo old-day');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
