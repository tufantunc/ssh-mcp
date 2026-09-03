import { afterEach, describe, expect, it, vi } from 'vitest';
import { ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { chmod, mkdtemp, mkdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createLocalDownload, localFileForRead, localFileForWrite } from '../../../src/tools/local-path.js';

const roots: string[] = [];

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'ssh-mcp-local-path-'));
  roots.push(root);
  return root;
}

async function canSymlink(target: string, path: string, type?: 'file' | 'dir' | 'junction'): Promise<boolean> {
  try {
    await symlink(target, path, type);
    return true;
  } catch (err: any) {
    if (err?.code === 'EPERM') return false;
    throw err;
  }
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('streaming SFTP local path confinement', () => {
  it('requires an explicitly configured absolute transfer root', async () => {
    await expect(localFileForWrite(undefined, 'file', false)).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
    await expect(localFileForWrite('relative', 'file', false)).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
  });

  it('rejects local path control characters as InvalidParams', async () => {
    const root = await tempRoot();
    for (const path of ['bad\npath', 'bad\tpath', 'bad\u001bpath', 'safe\u202Etxt']) {
      await expect(localFileForWrite(root, path, false)).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
    }
  });

  it('rejects traversal and absolute sibling paths without disclosing the root', async () => {
    const root = await tempRoot();
    const outside = join(dirname(root), 'outside.txt');
    for (const path of ['../outside.txt', outside]) {
      await expect(localFileForWrite(root, path, false)).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
    }
  });

  it('opens a regular upload file once and reports only its relative display path', async () => {
    const root = await tempRoot();
    await writeFile(join(root, 'source.bin'), Buffer.from([1, 2, 3]));
    const local = await localFileForRead(root, 'source.bin');
    try {
      expect(local.size).toBe(3);
      expect(local.displayPath).toBe('source.bin');
    } finally {
      await local.handle.close();
    }
  });

  it('rejects upload symlinks, directories and missing files as InvalidParams', async () => {
    const root = await tempRoot();
    await writeFile(join(root, 'target'), 'secret');
    if (await canSymlink(join(root, 'target'), join(root, 'link'), 'file')) {
      await expect(localFileForRead(root, 'link')).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
    }
    await mkdir(join(root, 'directory'));
    await expect(localFileForRead(root, 'directory')).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
    await expect(localFileForRead(root, 'missing')).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
  });

  it('rejects overwrite attempts with clear file, symlink and directory errors', async () => {
    const root = await tempRoot();
    await writeFile(join(root, 'file'), 'old');
    await expect(localFileForWrite(root, 'file', false)).rejects.toThrow(/Refusing to overwrite/);
    await mkdir(join(root, 'directory'));
    await expect(localFileForWrite(root, 'directory', true)).rejects.toThrow(/not a regular file/);
    if (await canSymlink(join(root, 'file'), join(root, 'link'), 'file')) {
      await expect(localFileForWrite(root, 'link', true)).rejects.toThrow(/symlink/);
    }
  });

  it('publishes new downloads exclusively and never replaces a racing file', async () => {
    const root = await tempRoot();
    const download = await createLocalDownload(root, 'result', false);
    try {
      await download.handle.writeFile('new');
      await writeFile(join(root, 'result'), 'racer');
      await expect(download.publish()).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
      expect(await readFile(join(root, 'result'), 'utf8')).toBe('racer');
    } finally {
      await download.cleanup();
    }
  });

  it('atomically replaces an existing regular file only with overwrite enabled', async () => {
    const root = await tempRoot();
    await writeFile(join(root, 'result'), 'old');
    const download = await createLocalDownload(root, 'result', true);
    try {
      await download.handle.writeFile('new');
      await download.publish();
      expect(await readFile(join(root, 'result'), 'utf8')).toBe('new');
    } finally {
      await download.cleanup();
    }
  });

  it('does not disclose absolute local paths when publishing fails', async () => {
    const root = await tempRoot();
    const download = await createLocalDownload(root, 'result', false);
    try {
      await download.handle.close();
      let failure: unknown;
      try { await download.publish(); } catch (err) { failure = err; }
      expect(failure).toMatchObject({ code: ErrorCode.InternalError });
      expect(String(failure)).not.toContain(root);
    } finally {
      await download.cleanup();
    }
  });

  it('re-verifies the destination parent before publishing', async () => {
    const root = await tempRoot();
    await mkdir(join(root, 'parent'));
    await mkdir(join(root, 'other'));
    const download = await createLocalDownload(root, 'parent/result', false);
    const warning = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      await download.handle.writeFile('new');
      await rename(join(root, 'parent'), join(root, 'moved'));
      if (!(await canSymlink(join(root, 'other'), join(root, 'parent'), process.platform === 'win32' ? 'junction' : 'dir'))) {
        await download.cleanup();
        return;
      }
      try {
        await expect(download.publish()).rejects.toThrow(/parent changed/);
        await expect(readFile(join(root, 'other', 'result'))).rejects.toMatchObject({ code: 'ENOENT' });
      } finally {
        await download.cleanup();
      }
      expect(warning).toHaveBeenCalledWith(expect.stringContaining('stale .part files'));
    } finally {
      warning.mockRestore();
    }
  });

  it('rejects transfer roots overlapping the installation or config directory', async () => {
    await expect(localFileForWrite(process.cwd(), 'result', false)).rejects.toThrow(/installation/);

    const root = await tempRoot();
    await writeFile(join(root, 'config.toml'), 'config');
    await expect(localFileForWrite(root, 'result', false, join(root, 'config.toml'))).rejects.toThrow(/config directory/);
  });

  it.skipIf(process.platform === 'win32')('rejects a group/world-accessible transfer root', async () => {
    const root = await tempRoot();
    await chmod(root, 0o755);
    await expect(localFileForWrite(root, 'result', false)).rejects.toThrow(/0700/);
  });

  it.skipIf(process.platform === 'win32')('checks the canonical target of a symlinked config file', async () => {
    const root = await tempRoot();
    const linkRoot = await tempRoot();
    const config = join(root, 'config.toml');
    const configLink = join(linkRoot, 'config-link.toml');
    await writeFile(config, 'config');
    await symlink(config, configLink, 'file');
    await expect(localFileForWrite(root, 'result', false, configLink)).rejects.toThrow(/config directory/);
  });
});
