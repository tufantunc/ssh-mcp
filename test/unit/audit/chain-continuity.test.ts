import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, writeFile, appendFile } from 'fs/promises';
import { createHash } from 'crypto';
import { tmpdir } from 'os';
import { join } from 'path';
import { AuditStore } from '../../../src/audit/store.js';

/**
 * The hash chain is what makes the audit log tamper-evident: each line commits
 * to the one before it, so a deleted or edited entry stops verifying instead of
 * simply disappearing.
 *
 * That only holds if the chain survives a restart. `loadLastHash()` reads the
 * tail of an existing log to pick the chain back up, and it had no test — so a
 * silent restart to `prevHash: ""` would look exactly like a normal log, and
 * anything spanning a restart would be unverifiable without anyone noticing.
 */
const base = {
  mcpRequestId: 1,
  profile: 'dev',
  user: 'test',
  commandClass: 'read-only' as const,
  binary: 'ls',
  decision: 'allow' as const,
  exitCode: 0,
  durationMs: 1,
};

let dir: string;
let logPath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-chain-'));
  logPath = join(dir, 'audit.log');
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function lines(): Promise<any[]> {
  const raw = await readFile(logPath, 'utf8');
  return raw.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

async function write(store: AuditStore, command: string): Promise<void> {
  await store.record({ ...base, command });
}

describe('audit hash chain', () => {
  it('links each entry to the one before it', async () => {
    const store = new AuditStore(logPath, false, true);
    await write(store, 'ls -la');
    await write(store, 'df -h');
    await write(store, 'whoami');
    await store.close();

    const [a, b, c] = await lines();
    expect(a.prevHash).toBe('');
    expect(b.prevHash).toBe(a.selfHash);
    expect(c.prevHash).toBe(b.selfHash);
    expect(new Set([a.selfHash, b.selfHash, c.selfHash]).size).toBe(3);
  });

  // The regression this file exists for.
  it('picks the chain back up in a new process', async () => {
    const first = new AuditStore(logPath, false, true);
    await write(first, 'ls -la');
    await write(first, 'df -h');
    await first.close();

    const before = await lines();

    const second = new AuditStore(logPath, false, true);
    await write(second, 'whoami');
    await second.close();

    const after = await lines();
    expect(after).toHaveLength(3);
    // Not a fresh chain: the entry written by the second instance commits to
    // the last entry written by the first.
    expect(after[2].prevHash).toBe(before[1].selfHash);
    expect(after[2].prevHash).not.toBe('');
  });

  it('produces a chain that verifies end to end', async () => {
    const first = new AuditStore(logPath, false, true);
    await write(first, 'ls -la');
    await first.close();
    const second = new AuditStore(logPath, false, true);
    await write(second, 'df -h');
    await second.close();

    // Recompute the way the writer does: the line without its hash fields,
    // plus the previous hash.
    let prev = '';
    for (const entry of await lines()) {
      const { prevHash, selfHash, ...body } = entry;
      expect(prevHash).toBe(prev);
      expect(createHash('sha256').update(JSON.stringify(body) + prevHash).digest('hex')).toBe(selfHash);
      prev = selfHash;
    }
  });

  it('detects an edited entry', async () => {
    const store = new AuditStore(logPath, false, true);
    await write(store, 'ls -la');
    await write(store, 'rm -rf /tmp/evidence');
    await store.close();

    const all = await lines();
    // Someone rewrites the second command to look harmless but leaves the
    // hashes alone.
    all[1].command = 'ls -la';
    await writeFile(logPath, all.map((l) => JSON.stringify(l)).join('\n') + '\n');

    const [, tampered] = await lines();
    const { prevHash, selfHash, ...body } = tampered;
    expect(createHash('sha256').update(JSON.stringify(body) + prevHash).digest('hex')).not.toBe(selfHash);
  });

  it('starts a fresh chain when there is no log yet', async () => {
    const store = new AuditStore(logPath, false, true);
    await write(store, 'ls -la');
    await store.close();
    expect((await lines())[0].prevHash).toBe('');
  });

  // An empty file is the state left by a crash between create and first write.
  it('starts fresh on an empty file rather than failing to open', async () => {
    await writeFile(logPath, '');
    const store = new AuditStore(logPath, false, true);
    await write(store, 'ls -la');
    await store.close();

    const all = await lines();
    expect(all).toHaveLength(1);
    expect(all[0].prevHash).toBe('');
  });

  // A half-written trailing line is what a kill -9 mid-append leaves behind.
  // Logging must keep working; the broken line is the evidence of the crash.
  it('keeps logging when the last line is truncated', async () => {
    const first = new AuditStore(logPath, false, true);
    await write(first, 'ls -la');
    await first.close();
    await appendFile(logPath, '{"command":"df -h","selfHa');

    const second = new AuditStore(logPath, false, true);
    await expect(write(second, 'whoami')).resolves.not.toThrow();
    await second.close();

    const raw = await readFile(logPath, 'utf8');
    expect(raw).toContain('whoami');
  });
});
