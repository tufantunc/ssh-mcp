import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, stat } from 'fs/promises';
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

  // Drives rotation through the store with a small threshold instead of
  // writing a real 101MB file behind its back. The old shape both cost ~200MB
  // of I/O per run and only worked because the store re-stat()ed the file on
  // every record — it stopped testing rotation the moment that was optimised.
  it('rotates when the file reaches the size limit', async () => {
    const logPath = join(tempDir, 'audit.log');
    const store = new AuditStore(logPath, false, false, 2048);

    const write = (command: string) => store.record({
      mcpRequestId: 0,
      profile: 'dev',
      user: 'test',
      command,
      commandClass: 'read-only',
      binary: 'cmd',
      decision: 'allow',
    });

    // Each record is a couple hundred bytes; enough of them cross 2KB.
    for (let i = 0; i < 20; i++) await write(`filler-${i}`);
    await write('after-rotate');

    const rotatedStat = await stat(`${logPath}.1`);
    expect(rotatedStat.size).toBeGreaterThan(0);

    const newContent = await readFile(logPath, 'utf8');
    const lines = newContent.trim().split('\n').filter(Boolean);
    expect(lines.length).toBeLessThan(21);
    expect(JSON.parse(lines[lines.length - 1]).command).toBe('after-rotate');
  });

  it('does not rotate below the limit', async () => {
    const logPath = join(tempDir, 'audit.log');
    const store = new AuditStore(logPath, false, false, 1024 * 1024);
    for (let i = 0; i < 5; i++) {
      await store.record({
        mcpRequestId: i, profile: 'dev', user: 'test', command: `cmd-${i}`,
        commandClass: 'read-only', binary: 'cmd', decision: 'allow',
      });
    }
    await expect(stat(`${logPath}.1`)).rejects.toThrow();
    const lines = (await readFile(logPath, 'utf8')).trim().split('\n').filter(Boolean);
    expect(lines).toHaveLength(5);
  });
});
