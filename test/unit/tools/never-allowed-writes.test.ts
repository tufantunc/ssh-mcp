import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHarness, textOf, type Harness } from './harness.js';
import { DEFAULT_RULES } from '../../../src/policy/engine.js';

/**
 * The write tools declare their write, so the built-in never-allowed paths refuse
 * them without any operator denylist; the read tools of the same paths are left to
 * their class. A tool that stops declaring (or a read tool that starts) fails its row.
 */
const ADMIN_AUTO = { role: 'admin' as const, approvalPolicy: 'auto' as const };

let h: Harness;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'ssh-mcp-naw-'));
  await chmod(root, 0o700);
});

afterEach(async () => {
  await h?.close();
  await rm(root, { recursive: true, force: true });
});

async function call(tool: string, args: Record<string, unknown>) {
  h = await createHarness(ADMIN_AUTO, { localPath: { transferRoot: root } }, DEFAULT_RULES);
  return h.client.callTool({ name: tool, arguments: args }) as Promise<any>;
}

describe('the SFTP write tools and the never-allowed paths', () => {
  it.each([
    ['sftp-upload', { remotePath: '/root/.ssh/authorized_keys', content: 'k' }],
    ['sftp-upload', { remotePath: '/etc/cron.d/x', content: 'k' }],
    ['sftp-upload-file', { remotePath: '/root/.ssh/authorized_keys', localPath: 'k' }],
    ['sftp-upload-file', { remotePath: '/etc/systemd/system/x.service', localPath: 'k' }],
  ])('%s to %j is refused by the built-in list', async (tool, args) => {
    const result = await call(tool, args);
    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toMatch(/built-in never-allowed rule/);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  it.each([
    ['sftp-list', { remotePath: '/etc/cron.d' }],
    ['sftp-download', { remotePath: '/root/.ssh/authorized_keys' }],
    ['sftp-download-file', { remotePath: '/root/.ssh/authorized_keys', localPath: 'k' }],
  ])('%s of the same paths is not refused by the built-in list', async (tool, args) => {
    const result = await call(tool, args);
    // The stubbed connection may error for its own reasons; what must not happen is
    // the never-allowed refusal, which would mean a read declared itself a write.
    // The record-existence assertion keeps the row from passing vacuously if the
    // call dies before policy ever runs.
    expect(textOf(result)).not.toMatch(/never-allowed/);
    expect(h.auditRecords.at(-1)).toBeTruthy();
    expect(h.auditRecords.at(-1)?.decision).not.toBe('deny');
  });

  it('a write to a benign path is not refused by the built-ins', async () => {
    const result = await call('sftp-upload', { remotePath: '/tmp/x', content: 'k' });
    expect(textOf(result)).not.toMatch(/never-allowed/);
    expect(h.auditRecords.at(-1)).toBeTruthy();
    expect(h.auditRecords.at(-1)?.decision).not.toBe('deny');
  });
});
