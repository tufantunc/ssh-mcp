import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { platform } from 'node:os';
import { startE2E, e2eAvailable, textOf } from './harness.js';

/**
 * The streaming file tools through the built binary, over a real stdio
 * transport, with a real config file.
 *
 * The in-process tests cannot reach this: `transferRoot` arrives from
 * `[defaults]` through `normalizeConfig`, and the gate's context is assembled
 * in `index.ts`, which runs `main()` on import and so appears in no unit test.
 * A round trip here is the only thing that shows the config key an operator
 * writes ends up as the directory the tools are confined to.
 */

const IS_WINDOWS = platform() === 'win32';
const available = !IS_WINDOWS && await e2eAvailable();

let root: string;

beforeAll(async () => {
  if (!available) return;
  // Its own directory, not the harness's config directory — which the gate
  // refuses to overlap, and rightly.
  root = await mkdtemp(join(tmpdir(), 'ssh-mcp-e2e-root-'));
  await chmod(root, 0o700);
});

afterAll(async () => {
  if (root) await rm(root, { recursive: true, force: true });
});

describe.skipIf(!available)('E2E — streaming file transfer', () => {
  it('moves a file to the host and back through the configured transfer root', async () => {
    const e2e = await startE2E({ defaults: `transferRoot = "${root}"` });
    try {
      const payload = Buffer.from(Array.from({ length: 50_000 }, (_, i) => (i * 31) & 0xff));
      await writeFile(join(root, 'payload.bin'), payload);

      const up = await e2e.callTool('sftp-upload-file', {
        localPath: 'payload.bin',
        remotePath: '/tmp/ssh-mcp-e2e-payload.bin',
        overwrite: true,
      });
      expect(up.isError, textOf(up)).toBeFalsy();

      const down = await e2e.callTool('sftp-download-file', {
        remotePath: '/tmp/ssh-mcp-e2e-payload.bin',
        localPath: 'returned.bin',
      });
      expect(down.isError, textOf(down)).toBeFalsy();

      expect((await readFile(join(root, 'returned.bin'))).equals(payload)).toBe(true);
      expect((await readdir(root)).filter((f) => f.includes('.part'))).toEqual([]);
    } finally {
      await e2e.cleanup();
    }
  }, 90_000);

  it('confines a caller to the configured root', async () => {
    const e2e = await startE2E({ defaults: `transferRoot = "${root}"` });
    try {
      const result = await e2e.callTool('sftp-download-file', {
        remotePath: '/etc/hostname',
        localPath: '/etc/ssh-mcp-should-not-exist',
      }).catch((err: any) => ({ isError: true, content: [{ text: err.message }] }));
      expect((result as any).isError).toBeTruthy();
      // The confinement refusal specifically, not merely a message mentioning
      // the key: a server that never received the root at all also says
      // "transferRoot", and that assertion passed with the wiring removed.
      expect(textOf(result)).toContain('must stay within defaults.transferRoot');
    } finally {
      await e2e.cleanup();
    }
  }, 60_000);

  it('refuses the transfer tools entirely when no root is configured', async () => {
    // The default state. The tools are still advertised — tool definitions are
    // static metadata and a client must be able to list them — but every call
    // is refused, naming the key the operator has to set.
    const e2e = await startE2E();
    try {
      const { tools } = await e2e.client.listTools();
      expect(tools.map((t) => t.name)).toContain('sftp-download-file');

      const result = await e2e.callTool('sftp-download-file', {
        remotePath: '/etc/hostname',
        localPath: 'anything.bin',
      }).catch((err: any) => ({ isError: true, content: [{ text: err.message }] }));
      expect((result as any).isError).toBeTruthy();
      expect(textOf(result)).toContain('defaults.transferRoot');

      // sftp-list has no local side, so it keeps working without a root.
      const listed = await e2e.callTool('sftp-list', { remotePath: '/etc', maxEntries: 5 });
      expect(listed.isError, textOf(listed)).toBeFalsy();
    } finally {
      await e2e.cleanup();
    }
  }, 60_000);
});
