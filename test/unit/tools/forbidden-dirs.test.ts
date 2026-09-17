import { describe, it, expect } from 'vitest';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { platform } from 'node:os';
import { transferForbiddenDirs } from '../../../src/tools/forbidden-dirs.js';
import { getAuditLogPath } from '../../../src/audit/store.js';
import { localFileForRead } from '../../../src/tools/local-path.js';

/**
 * The list itself, and that the gate actually acts on it.
 *
 * Two directories pass every privacy check the transfer-root gate applies —
 * both are conventionally 0700 and owner-owned — and both would be disastrous
 * as a transfer root. Nothing else can catch a list that silently lost an
 * entry: the gate is generic over whatever it is handed, and the handing-over
 * used to sit inside `main()`'s body in `index.ts`, which is unexported and so
 * unreachable from any test.
 */

const IS_WINDOWS = platform() === 'win32';

describe('the directories a transfer root may not overlap', () => {
  it('names the audit log directory and ~/.ssh', () => {
    const dirs = transferForbiddenDirs();
    const paths = dirs.map((d) => d.path);

    // Derived the same way the audit store derives it, rather than spelled out:
    // the path is platform-specific, and a literal here would pass on the
    // author's machine and describe nothing on the other two.
    expect(paths).toContain(dirname(getAuditLogPath()));
    expect(paths).toContain(join(homedir(), '.ssh'));
    expect(dirs).toHaveLength(2);
  });

  it('gives each one a reason an operator can act on', () => {
    for (const { reason } of transferForbiddenDirs()) {
      expect(reason).toMatch(/directory/);
      // The reason is interpolated into "transferRoot must be separate from
      // ...", so a bare path would read as a sentence fragment.
      expect(reason.startsWith('/')).toBe(false);
    }
  });

  it.skipIf(IS_WINDOWS)('is enforced, not merely reported', async () => {
    // A real directory standing in for a forbidden one: the gate resolves the
    // entries it is given, so what is under test is that a root overlapping an
    // entry is refused — not the specific paths, which the first test pins.
    const root = await mkdtemp(join(tmpdir(), 'ssh-mcp-forbidden-'));
    await chmod(root, 0o700);
    try {
      await expect(
        localFileForRead(
          { transferRoot: root, forbidden: [{ path: root, reason: 'the audit log directory' }] },
          'anything.txt',
        ),
      ).rejects.toThrow(/must be separate from the audit log directory/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
