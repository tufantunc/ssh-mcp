import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, readFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import { AuditStore } from '../../src/audit/store.js';
import type { SSHConnection } from '../../src/ssh/connection.js';

let status: ServerStatus;
let env: ReturnType<typeof setupEnv>;
let conn: SSHConnection;
let tempDir: string;
let audit: AuditStore;

beforeAll(async () => {
  status = await checkAllServers();
  if (!allServersUp(status)) return;
  env = setupEnv();
  tempDir = await mkdtemp(join(tmpdir(), 'ssh-mcp-audit-e2e-'));
  audit = new AuditStore(join(tempDir, 'audit.log'));
  conn = await createConnection('admin');
});

afterAll(async () => { await conn?.close(); env?.restore(); await rm(tempDir, { recursive: true, force: true }); });

async function readLast(): Promise<any> {
  const content = await readFile(join(tempDir, 'audit.log'), 'utf8');
  const lines = content.trim().split('\n').filter(Boolean);
  return JSON.parse(lines[lines.length - 1]);
}

describe.skipIf(!allServersUp(await checkAllServers()))('Audit log E2E', () => {
  it('successful command produces audit record', async () => {
    const result = await conn.exec('echo audit-test');
    await audit.record({ mcpRequestId: 1, profile: 'admin', user: 'admin', command: 'echo audit-test', commandClass: 'read-only', binary: 'echo', decision: 'allow', exitCode: result.exitCode, durationMs: result.durationMs });
    const r = await readLast();
    expect(r.profile).toBe('admin');
    expect(r.command).toBe('echo audit-test');
    expect(r.decision).toBe('allow');
    expect(r.exitCode).toBe(0);
  });

  it('denied command logged with deny decision', async () => {
    await audit.record({ mcpRequestId: 2, profile: 'admin', user: 'admin', command: 'rm -rf /', commandClass: 'destructive', binary: 'rm', decision: 'deny', error: 'POLICY_DENIED' });
    const r = await readLast();
    expect(r.decision).toBe('deny');
    expect(r.error).toBe('POLICY_DENIED');
  });

  it('secrets are redacted in audit command field', async () => {
    await audit.record({ mcpRequestId: 3, profile: 'admin', user: 'admin', command: 'echo AKIAIOSFODNN7EXAMPLE', commandClass: 'read-only', binary: 'echo', decision: 'allow', exitCode: 0, durationMs: 10 });
    const r = await readLast();
    expect(r.command).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(r.command).toContain('[REDACTED');
  });

  it('error path still writes audit record', async () => {
    await audit.record({ mcpRequestId: 4, profile: 'admin', user: 'admin', command: 'nonexistent-command', commandClass: 'safe', binary: 'nonexistent-command', decision: 'deny', error: 'Command failed: not found' });
    const r = await readLast();
    expect(r.error).toContain('not found');
  });
});
