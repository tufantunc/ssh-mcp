import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHarness, textOf, type Harness } from './harness.js';
import { DEFAULT_RULES } from '../../../src/policy/engine.js';

/**
 * #230 through the real tool handlers: every SFTP tool hands its remote path to the
 * engine, so a denylist rule written for the path refuses it whatever the composed
 * string looks like. A tool that stops passing its path fails its own row.
 */
const IS_WINDOWS = process.platform === 'win32';
const ADMIN_AUTO = { role: 'admin' as const, approvalPolicy: 'auto' as const };

let h: Harness;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'ssh-mcp-deny-path-'));
  await chmod(root, 0o700);
});

afterEach(async () => {
  await h?.close();
  await rm(root, { recursive: true, force: true });
});

const TOOLS: Array<{ name: string; args: (remotePath: string) => Record<string, unknown> }> = [
  { name: 'sftp-list', args: (remotePath) => ({ remotePath }) },
  { name: 'sftp-download', args: (remotePath) => ({ remotePath }) },
  { name: 'sftp-upload', args: (remotePath) => ({ remotePath, content: 'k' }) },
  { name: 'sftp-upload-file', args: (remotePath) => ({ remotePath, localPath: 'k' }) },
  { name: 'sftp-download-file', args: (remotePath) => ({ remotePath, localPath: 'k' }) },
];

async function callWith(denylist: string[], tool: (typeof TOOLS)[number], remotePath: string) {
  h = await createHarness(ADMIN_AUTO, { localPath: { transferRoot: root } }, { ...DEFAULT_RULES, denylist });
  return h.client.callTool({ name: tool.name, arguments: tool.args(remotePath) }) as Promise<any>;
}

describe('a denylist rule written for the path refuses every SFTP tool', () => {
  // sftp-list, sftp-download and sftp-upload end their string with the path, so the
  // command string matches first and keeps its wording; the two streaming tools end
  // with the local path, which is the #230 gap.
  it.each(TOOLS)('$name: refused when the path as given matches', async (tool) => {
    const result = await callWith(['authorized_keys$'], tool, '/root/.ssh/authorized_keys');
    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toMatch(/matches \/authorized_keys\$\//);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  it.each(TOOLS.filter((t) => t.name.endsWith('-file')))(
    '$name: the refusal names the remote path, since the composed string ends with the local one',
    async (tool) => {
      const result = await callWith(['authorized_keys$'], tool, '/root/.ssh/authorized_keys');
      expect(textOf(result)).toContain('Remote path "/root/.ssh/authorized_keys" matches /authorized_keys$/');
    },
  );

  it.each(TOOLS)('$name: refused when only the normalized path matches', async (tool) => {
    const result = await callWith(['^/root/\\.ssh/'], tool, '/srv/x/../../root/.ssh/authorized_keys');
    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toContain('read as "/root/.ssh/authorized_keys"');
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  // A spelling that reaches the same file on a Windows target (measured: case and a
  // trailing dot) and that neither the command string, the path as given, nor the plain
  // normalized reading matches.
  it('refused when only the Windows reading matches', async () => {
    const result = await callWith(
      ['\\.ssh/authorized_keys$'],
      TOOLS.find((t) => t.name === 'sftp-upload-file')!,
      'C:\\Users\\a\\.ssh\\Authorized_Keys.',
    );
    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toContain('the Windows reading');
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  // Skipped on Windows like the other transfer-root tests: the call gets past the policy
  // and into the local-path layer, whose permission checks differ there.
  //
  // The local path is not tested on its own. It is still part of the command string, which
  // every pattern sees as before, so `^authorized_keys$` is the probe: it matches the local
  // path alone and neither the command string nor the remote path.
  it.skipIf(IS_WINDOWS)('does not test the local path on its own', async () => {
    h = await createHarness(ADMIN_AUTO, { localPath: { transferRoot: root } }, { ...DEFAULT_RULES, denylist: ['^authorized_keys$'] });
    const result = await h.client.callTool({
      name: 'sftp-download-file',
      arguments: { remotePath: '/srv/backup.tar', localPath: 'authorized_keys' },
    }) as any;
    // The stubbed connection has no SFTP channel, so the transfer itself fails; what
    // matters is that the policy allowed it and the call got that far. Asserting the
    // record exists keeps the row from passing vacuously if a future change makes the
    // call die before policy ever runs.
    expect(textOf(result)).not.toContain('POLICY_DENIED');
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'allow' });
    expect(h.auditRecords.at(-1)?.ruleId).not.toBe('denylist');
  });
});
