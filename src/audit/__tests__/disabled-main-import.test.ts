import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AuditStore } from '../store.js';

/**
 * Regression test for the deferred-AuditStore fix.
 *
 * Before the fix, `src/index.ts` constructed the AuditStore eagerly at module
 * top-level, so merely importing the module under SSH_MCP_DISABLE_MAIN=1 (the
 * library/test path) performed audit-directory filesystem I/O. An invalid
 * audit dir therefore made the import itself throw (ENOTDIR). With the store
 * built lazily, the import must succeed regardless of audit-dir validity.
 */
describe('index import under SSH_MCP_DISABLE_MAIN=1', () => {
  let root: string;
  let badDir: string;
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'ssh-mcp-disabled-main-'));
    // A regular file standing where a directory parent is expected: any
    // mkdirSync under it fails with ENOTDIR.
    const notADir = join(root, 'notadir');
    writeFileSync(notADir, 'x');
    badDir = join(notADir, 'audit');
    for (const k of ['SSH_MCP_DISABLE_MAIN', 'SSH_MCP_TEST', 'SSH_MCP_AUDIT_DIR']) {
      saved[k] = process.env[k];
    }
    process.env.SSH_MCP_DISABLE_MAIN = '1';
    delete process.env.SSH_MCP_TEST;
    process.env.SSH_MCP_AUDIT_DIR = badDir;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    rmSync(root, { recursive: true, force: true });
  });

  it('imports cleanly even when the audit dir is invalid (construction deferred)', async () => {
    // Sanity: the dir really is invalid, so a real construction would throw.
    expect(() => new AuditStore({ auditDir: badDir, auditMaxBytes: 10 })).toThrow();

    // The import must NOT touch the filesystem for the audit store.
    const mod = await import('../../index.js');
    expect(mod).toBeTruthy();
    expect(typeof mod.executeAuditedTransportCommand).toBe('function');
  });
});
