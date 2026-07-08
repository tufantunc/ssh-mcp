import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, stat, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { AuditStore } from '../../../src/audit/store.js';

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'ssh-mcp-audit-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe('AuditStore', () => {
  it('writes audit record as JSONL', async () => {
    const logPath = join(tempDir, 'audit.log');
    const store = new AuditStore(logPath);
    await store.record({
      mcpRequestId: 1,
      profile: 'dev',
      user: 'test',
      command: 'ls -la',
      commandClass: 'read-only',
      binary: 'ls',
      decision: 'allow',
      exitCode: 0,
      durationMs: 100,
    });

    const content = await readFile(logPath, 'utf8');
    const record = JSON.parse(content.trim());
    expect(record.profile).toBe('dev');
    expect(record.command).toBe('ls -la');
    expect(record.commandClass).toBe('read-only');
    expect(record.eventId).toBeTruthy();
    expect(record.timestamp).toBeTruthy();
  });

  it('redacts secrets in command field', async () => {
    const logPath = join(tempDir, 'audit.log');
    const store = new AuditStore(logPath);
    await store.record({
      mcpRequestId: 1,
      profile: 'dev',
      user: 'test',
      command: 'echo AKIAIOSFODNN7EXAMPLE',
      commandClass: 'read-only',
      binary: 'echo',
      decision: 'allow',
    });

    const content = await readFile(logPath, 'utf8');
    expect(content).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(content).toContain('[REDACTED:aws-access-key');
  });

  it('rotates when file exceeds size limit', async () => {
    const logPath = join(tempDir, 'audit.log');
    const store = new AuditStore(logPath);
    await store.record({
      mcpRequestId: 0,
      profile: 'dev',
      user: 'test',
      command: 'init',
      commandClass: 'read-only',
      binary: 'init',
      decision: 'allow',
    });

    await writeFile(logPath, 'x'.repeat(101 * 1024 * 1024), 'utf8');

    await store.record({
      mcpRequestId: 1,
      profile: 'dev',
      user: 'test',
      command: 'after-rotate',
      commandClass: 'read-only',
      binary: 'after-rotate',
      decision: 'allow',
    });

    const rotatedStat = await stat(`${logPath}.1`);
    expect(rotatedStat.size).toBeGreaterThan(100 * 1024 * 1024);

    const newContent = await readFile(logPath, 'utf8');
    const record = JSON.parse(newContent.trim());
    expect(record.command).toBe('after-rotate');
  });
});
