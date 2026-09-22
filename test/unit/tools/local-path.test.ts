import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { platform, tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import {
  createLocalDownload,
  localFileForRead,
  localFileForWrite,
  type LocalPathContext,
} from '../../../src/tools/local-path.js';

// Two spellings of the same directory. On macOS `os.tmpdir()` is
// `/var/folders/...`, a symlink to `/private/var/folders/...`; on Linux they
// are usually identical. Every test that matters here is written so that it
// passes on both, and the ones that specifically exercise the difference skip
// themselves where there is no difference to exercise.
// B1 refuses a transfer root on Windows outright: the config-file ACL posture
// waives a read-exposed directory, never consults the `O:` owner, and treats a
// missing icacls.exe as a pass, so an unverifiable root has to disable the
// tools. Everything below this line therefore describes POSIX behaviour, and
// the Windows contract gets its own block at the end — which is where that
// refusal is actually covered rather than merely untested.
const IS_WINDOWS = platform() === 'win32';

let rootAsSpelled: string;
let rootCanonical: string;
let ctx: LocalPathContext;

const SYMLINKED_TMP = async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-probe-'));
  const differs = (await realpath(dir)) !== dir;
  await rm(dir, { recursive: true, force: true });
  return differs;
};
const TMP_IS_SYMLINKED = await SYMLINKED_TMP();

beforeEach(async () => {
  rootAsSpelled = await mkdtemp(join(tmpdir(), 'ssh-mcp-transfer-'));
  await chmod(rootAsSpelled, 0o700);
  rootCanonical = await realpath(rootAsSpelled);
  ctx = { transferRoot: rootAsSpelled };
});

afterEach(async () => {
  await chmod(rootAsSpelled, 0o700).catch(() => {});
  await rm(rootAsSpelled, { recursive: true, force: true });
});

describe.skipIf(IS_WINDOWS)('localFileForRead', () => {
  it('accepts a relative path inside the root', async () => {
    await writeFile(join(rootCanonical, 'payload.txt'), 'hello');

    const file = await localFileForRead(ctx, 'payload.txt');
    try {
      expect(file.size).toBe(5);
      expect(file.displayPath).toBe('payload.txt');
    } finally {
      await file.handle.close();
    }
  });

  // The regression this module was rewritten for. `resolve(root, input)`
  // ignores `root` when `input` is absolute, so an absolute path spelled the
  // way the operator's shell shows it does not lexically sit under a
  // realpath'd root. Confining that form first refused every such path.
  it.skipIf(!TMP_IS_SYMLINKED)(
    'accepts an absolute path spelled with the pre-symlink prefix',
    async () => {
      await writeFile(join(rootCanonical, 'payload.txt'), 'hello');
      expect(rootAsSpelled).not.toBe(rootCanonical);

      const file = await localFileForRead(ctx, join(rootAsSpelled, 'payload.txt'));
      try {
        expect(file.size).toBe(5);
        expect(file.displayPath).toBe('payload.txt');
      } finally {
        await file.handle.close();
      }
    },
  );

  it('accepts an absolute path spelled canonically', async () => {
    await writeFile(join(rootCanonical, 'payload.txt'), 'hello');

    const file = await localFileForRead(ctx, join(rootCanonical, 'payload.txt'));
    try {
      expect(file.displayPath).toBe('payload.txt');
    } finally {
      await file.handle.close();
    }
  });

  it('refuses a path that escapes the root with ..', async () => {
    await expect(localFileForRead(ctx, '../escaped.txt')).rejects.toThrow(
      /must stay within defaults.transferRoot/,
    );
  });

  it('refuses an absolute path outside the root', async () => {
    await expect(localFileForRead(ctx, '/etc/passwd')).rejects.toThrow(
      /must stay within defaults.transferRoot/,
    );
  });

  // The refusal has to be lexical, i.e. decided before anything stats the
  // path. If it were not, these tools would answer "does this file exist?" for
  // any path on the host: an existing target and an absent one would come back
  // with different errors. Identical messages are the evidence that nothing
  // outside the root was touched.
  it('refuses paths outside the root without revealing whether they exist', async () => {
    // The pair differs in whether the *parent directory* exists, which is what
    // a realpath-before-confine shape would leak: /etc resolves, the invented
    // root does not, so the two would come back with different errors.
    const existing = localFileForRead(ctx, '/etc/hosts');
    const absent = localFileForRead(ctx, '/ssh-mcp-no-such-root-9f3a/file');

    const [a, b] = await Promise.all([
      existing.catch((err) => String(err.message)),
      absent.catch((err) => String(err.message)),
    ]);
    expect(a).toBe(b);
    expect(a).toMatch(/must stay within defaults.transferRoot/);
  });

  // A sibling directory whose name merely begins with `..` is inside nothing.
  // A prefix test on the relative path (`rel.startsWith('..')`) rejects it;
  // isWithinRoot checks the `..` segment instead.
  it('does not confuse a sibling named ..cache with an escape', async () => {
    await mkdir(join(rootCanonical, '..cache'));
    await writeFile(join(rootCanonical, '..cache', 'entry.txt'), 'x');

    const file = await localFileForRead(ctx, join('..cache', 'entry.txt'));
    try {
      expect(file.displayPath).toBe(join('..cache', 'entry.txt'));
    } finally {
      await file.handle.close();
    }
  });

  it('refuses a symlink source rather than following it', async () => {
    const secret = join(rootCanonical, 'secret.txt');
    await writeFile(secret, 'classified');
    await symlink(secret, join(rootCanonical, 'link.txt'));

    await expect(localFileForRead(ctx, 'link.txt')).rejects.toThrow(/cannot be a symlink/);
  });

  it('refuses a directory', async () => {
    await mkdir(join(rootCanonical, 'subdir'));
    await expect(localFileForRead(ctx, 'subdir')).rejects.toThrow(
      /not an accessible regular file|not a regular file/,
    );
  });

  it('refuses an empty path and one carrying control characters', async () => {
    await expect(localFileForRead(ctx, '   ')).rejects.toThrow(/cannot be empty/);
    await expect(localFileForRead(ctx, 'a\u0001b')).rejects.toThrow(
      /control or bidi formatting/,
    );
  });

  it('accepts a local name carrying a zero-width joiner', async () => {
    // The local half of the same character class, which `guard/sanitizer.ts`
    // exports and this file's `validateInput` consumes. Narrowing it to let
    // U+200C/U+200D through was argued on the remote half and silently changed
    // this one too — measured, widening it back was caught only by remote-half
    // tests, so the local side of a deliberate change was unpinned in both
    // directions. ZWNJ is orthographic in Persian; the file really exists.
    const name = 'mi\u200Cravad.txt';
    await writeFile(join(rootCanonical, name), 'x');
    await expect(localFileForRead(ctx, name)).resolves.toBeDefined();
  });
});

describe.skipIf(IS_WINDOWS)('the transfer root itself', () => {
  it('is required', async () => {
    await expect(localFileForRead({ transferRoot: undefined }, 'x')).rejects.toThrow(
      /require defaults.transferRoot/,
    );
  });

  it('must be absolute', async () => {
    await expect(localFileForRead({ transferRoot: 'relative/dir' }, 'x')).rejects.toThrow(
      /must be an absolute path/,
    );
  });

  it('must exist', async () => {
    await expect(
      localFileForRead({ transferRoot: join(rootCanonical, 'absent') }, 'x'),
    ).rejects.toThrow(/not an accessible directory/);
  });

  it('must be a directory, not a file', async () => {
    const file = join(rootCanonical, 'a-file');
    await writeFile(file, 'x');
    await expect(localFileForRead({ transferRoot: file }, 'x')).rejects.toThrow(
      /must name a directory/,
    );
  });

  it('must not be group- or world-accessible', async () => {
    await chmod(rootAsSpelled, 0o750);
    await expect(localFileForRead(ctx, 'x')).rejects.toThrow(/permissions must be 0700/);
  });

  // Both of these are conventionally 0700 and owned by the operator, so the
  // privacy checks accept them; only an explicit exclusion keeps a download
  // from overwriting the audit log or reading an SSH private key.
  it('must not contain a forbidden directory', async () => {
    const nested = join(rootCanonical, 'logs');
    await mkdir(nested);

    await expect(
      localFileForRead(
        { transferRoot: rootAsSpelled, forbidden: [{ path: nested, reason: 'the audit log directory' }] },
        'x',
      ),
    ).rejects.toThrow(/must be separate from the audit log directory/);
  });

  it('must not sit inside a forbidden directory', async () => {
    await expect(
      localFileForRead(
        {
          transferRoot: rootAsSpelled,
          forbidden: [{ path: rootCanonical, reason: 'the SSH key directory' }],
        },
        'x',
      ),
    ).rejects.toThrow(/must be separate from the SSH key directory/);
  });

  // An exclusion for a directory that does not exist yet still has to hold —
  // otherwise creating it afterwards silently re-opens the hole.
  it('applies a forbidden directory that does not exist yet', async () => {
    await expect(
      localFileForRead(
        {
          transferRoot: rootAsSpelled,
          forbidden: [{ path: join(rootCanonical, 'not-created'), reason: 'the audit log directory' }],
        },
        'x',
      ),
    ).rejects.toThrow(/must be separate from the audit log directory/);
  });

  it('accepts a forbidden directory that does not overlap', async () => {
    const elsewhere = await mkdtemp(join(tmpdir(), 'ssh-mcp-other-'));
    try {
      await writeFile(join(rootCanonical, 'payload.txt'), 'hello');
      const file = await localFileForRead(
        { transferRoot: rootAsSpelled, forbidden: [{ path: elsewhere, reason: 'somewhere else' }] },
        'payload.txt',
      );
      await file.handle.close();
    } finally {
      await rm(elsewhere, { recursive: true, force: true });
    }
  });
});

describe.skipIf(IS_WINDOWS)('localFileForWrite', () => {
  it('resolves a destination that does not exist yet', async () => {
    const target = await localFileForWrite(ctx, 'new.txt', false);
    expect(target.displayPath).toBe('new.txt');
    expect(target.parent).toBe(rootCanonical);
  });

  it.skipIf(!TMP_IS_SYMLINKED)(
    'resolves an absolute destination spelled with the pre-symlink prefix',
    async () => {
      const target = await localFileForWrite(ctx, join(rootAsSpelled, 'new.txt'), false);
      expect(target.displayPath).toBe('new.txt');
      expect(target.parent).toBe(rootCanonical);
    },
  );

  it('refuses an existing file unless overwrite is requested', async () => {
    await writeFile(join(rootCanonical, 'taken.txt'), 'old');

    await expect(localFileForWrite(ctx, 'taken.txt', false)).rejects.toThrow(
      /Refusing to overwrite existing local file/,
    );
    const target = await localFileForWrite(ctx, 'taken.txt', true);
    expect(target.displayPath).toBe('taken.txt');
  });

  it('refuses to overwrite a symlink even when overwrite is requested', async () => {
    const outside = join(rootCanonical, 'real.txt');
    await writeFile(outside, 'x');
    await symlink(outside, join(rootCanonical, 'link.txt'));

    await expect(localFileForWrite(ctx, 'link.txt', true)).rejects.toThrow(
      /Refusing to overwrite a local symlink/,
    );
  });

  it('refuses a destination outside the root', async () => {
    await expect(localFileForWrite(ctx, '/tmp/escaped.txt', false)).rejects.toThrow(
      /must stay within defaults.transferRoot/,
    );
  });
});

describe.skipIf(IS_WINDOWS)('createLocalDownload', () => {
  it('stages a .part file in the destination directory and publishes it', async () => {
    const download = await createLocalDownload(ctx, 'result.txt', false);
    expect(download.temporary.startsWith(rootCanonical + sep)).toBe(true);
    expect(download.temporary).toMatch(/\.part$/);

    await download.handle.write('published');
    await download.publish();
    await download.cleanup();

    const { readFile } = await import('node:fs/promises');
    expect(await readFile(join(rootCanonical, 'result.txt'), 'utf8')).toBe('published');
  });

  it('removes the .part file when the transfer is abandoned', async () => {
    const download = await createLocalDownload(ctx, 'aborted.txt', false);
    const staged = download.temporary;
    await download.cleanup();

    const { access } = await import('node:fs/promises');
    await expect(access(staged)).rejects.toThrow();
  });

  it('refuses to publish over a file that appeared during the transfer', async () => {
    const download = await createLocalDownload(ctx, 'racy.txt', false);
    try {
      await writeFile(join(rootCanonical, 'racy.txt'), 'someone else');
      await download.handle.write('mine');
      await expect(download.publish()).rejects.toThrow(
        /Refusing to overwrite a local file created during transfer/,
      );
    } finally {
      await download.cleanup();
    }
  });
});

describe.skipIf(IS_WINDOWS)('the transfer root, continued', () => {
  // The privacy checks walk every ancestor, because a world-writable parent
  // could swap the root between realpath() and open(). /tmp is exempt by being
  // sticky; a plain 0777 directory is not.
  it('refuses a root under a world-writable, non-sticky parent', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'ssh-mcp-openparent-'));
    const root = join(parent, 'transfers');
    await mkdir(root);
    await chmod(root, 0o700);
    await chmod(parent, 0o777);
    try {
      await expect(localFileForRead({ transferRoot: root }, 'x')).rejects.toThrow(
        /unsafe writable parent directory/,
      );
    } finally {
      await chmod(parent, 0o700).catch(() => {});
      await rm(parent, { recursive: true, force: true });
    }
  });
});

describe.skipIf(IS_WINDOWS)('createLocalDownload, publishing over an existing file', () => {
  // The overwrite path publishes with rename rather than link, so it replaces
  // the destination instead of refusing on EEXIST.
  it('replaces the destination when overwrite is requested', async () => {
    const existing = join(rootCanonical, 'target.txt');
    await writeFile(existing, 'old contents');

    const download = await createLocalDownload(ctx, 'target.txt', true);
    try {
      await download.handle.write('new contents');
      await download.publish();
    } finally {
      await download.cleanup();
    }

    const { readFile } = await import('node:fs/promises');
    expect(await readFile(existing, 'utf8')).toBe('new contents');
    // The staging file is gone: rename consumed it rather than leaving a link.
    const { readdir } = await import('node:fs/promises');
    expect((await readdir(rootCanonical)).filter((n) => n.endsWith('.part'))).toEqual([]);
  });

  it('hands out one stream, and the same one on a second call', async () => {
    const download = await createLocalDownload(ctx, 'streamed.txt', false);
    try {
      const first = download.createStream();
      expect(download.createStream()).toBe(first);
      first.end('streamed');
      await new Promise((resolve) => first.once('finish', resolve));
      await download.publish();
    } finally {
      // cleanup() destroys the stream before closing the handle; without that
      // ordering this call hangs, which is why the object owns both.
      await download.cleanup();
    }

    const { readFile } = await import('node:fs/promises');
    expect(await readFile(join(rootCanonical, 'streamed.txt'), 'utf8')).toBe('streamed');
  });
});

describe.runIf(IS_WINDOWS)('on Windows', () => {
  it('refuses any transfer root rather than verifying it with the config-file posture', async () => {
    await expect(localFileForRead({ transferRoot: rootAsSpelled }, 'payload.txt')).rejects.toThrow(
      /not available on Windows/,
    );
  });

  it('refuses before deciding anything about the path, so the message never varies', async () => {
    const inside = await localFileForRead({ transferRoot: rootAsSpelled }, 'payload.txt')
      .catch((err) => String(err.message));
    const outside = await localFileForRead({ transferRoot: rootAsSpelled }, 'C:\\Windows\\win.ini')
      .catch((err) => String(err.message));
    expect(inside).toBe(outside);
  });
});
