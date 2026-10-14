import { describe, it, expect } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { join } from 'path';

const run = promisify(execFile);

const SCRIPT = fileURLToPath(new URL('../../scripts/sync-lockfile-version.mjs', import.meta.url));

/**
 * scripts/sync-lockfile-version.mjs, run by `npm run version` after `changeset version`.
 *
 * `changeset version` bumps package.json and never touches package-lock.json, so
 * the lockfile's own two version fields fell behind on every release — measured
 * on main at 2.19.0, the lockfile still said 2.16.0 until a Dependabot rebase
 * happened to rewrite it. Driven the way sync-server-json.test.ts drives its
 * script: a copy in a temp tree reads that tree's fixtures.
 */
async function withFixture(
  pkg: Record<string, unknown>,
  lock: Record<string, unknown>,
  args: string[] = [],
) {
  const root = await mkdtemp(join(tmpdir(), 'ssh-mcp-lock-'));
  try {
    await mkdir(join(root, 'scripts'));
    await copyFile(SCRIPT, join(root, 'scripts', 'sync-lockfile-version.mjs'));
    await writeFile(join(root, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
    const lockPath = join(root, 'package-lock.json');
    await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
    const before = await readFile(lockPath, 'utf8');

    let result: { code: number; stdout: string; stderr: string };
    try {
      const ok = await run('node', [join(root, 'scripts', 'sync-lockfile-version.mjs'), ...args]);
      result = { code: 0, stdout: ok.stdout, stderr: ok.stderr };
    } catch (err: any) {
      result = { code: err.code, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
    }

    return { ...result, before, after: await readFile(lockPath, 'utf8') };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

const PKG = { name: 'ssh-mcp', version: '9.9.9' };

const LOCK = (version = '1.0.0', over: Record<string, unknown> = {}) => ({
  name: 'ssh-mcp',
  version,
  lockfileVersion: 3,
  requires: true,
  packages: {
    '': { name: 'ssh-mcp', version, license: 'MIT', dependencies: { ssh2: '^1.17.0' } },
    'node_modules/ssh2': { version: '1.17.0' },
  },
  ...over,
});

describe('sync-lockfile-version — write mode', () => {
  it('writes package.json version into both lockfile version fields', async () => {
    const r = await withFixture(PKG, LOCK());
    expect(r.code).toBe(0);
    const lock = JSON.parse(r.after);
    expect(lock.version).toBe('9.9.9');
    expect(lock.packages[''].version).toBe('9.9.9');
  });

  it('changes nothing else: dependency entries, key order, indentation, trailing newline', async () => {
    const r = await withFixture(PKG, LOCK());
    expect(r.after).toBe(`${JSON.stringify(LOCK('9.9.9'), null, 2)}\n`);
  });

  it('updates the root package entry even when the top-level field is already current', async () => {
    const lock = LOCK('1.0.0', { version: '9.9.9' });
    const r = await withFixture(PKG, lock);
    expect(JSON.parse(r.after).packages[''].version).toBe('9.9.9');
  });

  it('leaves the file untouched when it is already in sync', async () => {
    const r = await withFixture(PKG, LOCK('9.9.9'));
    expect(r.code).toBe(0);
    expect(r.after).toBe(r.before);
  });
});

describe('sync-lockfile-version — --check', () => {
  it('fails on a stale lockfile without writing to it', async () => {
    const r = await withFixture(PKG, LOCK(), ['--check']);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/stale/);
    expect(r.after).toBe(r.before);
  });

  it('passes when the versions already agree', async () => {
    const r = await withFixture(PKG, LOCK('9.9.9'), ['--check']);
    expect(r.code).toBe(0);
  });
});

describe('sync-lockfile-version — guard', () => {
  it('refuses a lockfile that belongs to another package', async () => {
    const r = await withFixture(PKG, LOCK('1.0.0', { name: 'other' }));
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/other/);
    expect(r.after).toBe(r.before);
  });
});
