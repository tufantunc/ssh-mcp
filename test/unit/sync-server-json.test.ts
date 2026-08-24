import { describe, it, expect } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { join } from 'path';

const run = promisify(execFile);

const SCRIPT = fileURLToPath(new URL('../../scripts/sync-server-json.mjs', import.meta.url));
const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

/**
 * scripts/sync-server-json.mjs, the one gate on the registry listing.
 *
 * Every guard in that script exists because the registry reports the mistake it
 * catches *after* `npm publish` has made the version immutable — recovering from
 * that means shipping another release, not re-running a job. And on a healthy
 * repo every one of those branches is false, so a guard that silently stopped
 * firing would look exactly like a guard that passed: the script exits 0 either
 * way, and `scripts/` sits outside `sonar.sources`, the coverage report and both
 * tsconfigs, so nothing else would notice. Without this file the first execution
 * of an edited guard is the release itself.
 *
 * The script reads `package.json` and `server.json` relative to its own location
 * (`new URL('..', import.meta.url)`), so a copy of the real file in a temp tree
 * reads that tree's fixtures. That is deliberately how these tests drive it:
 * copying rather than importing means no export seam, no root argument, and no
 * divergence between the file under test and the file the release runs.
 */
async function withFixture(
  pkg: Record<string, unknown>,
  registry: Record<string, unknown>,
  args: string[] = [],
) {
  const root = await mkdtemp(join(tmpdir(), 'ssh-mcp-sync-'));
  try {
    await mkdir(join(root, 'scripts'));
    await copyFile(SCRIPT, join(root, 'scripts', 'sync-server-json.mjs'));
    await writeFile(join(root, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
    const registryPath = join(root, 'server.json');
    await writeFile(registryPath, `${JSON.stringify(registry, null, 2)}\n`);
    const before = await readFile(registryPath, 'utf8');

    let result: { code: number; stdout: string; stderr: string };
    try {
      const ok = await run('node', [join(root, 'scripts', 'sync-server-json.mjs'), ...args]);
      result = { code: 0, stdout: ok.stdout, stderr: ok.stderr };
    } catch (err: any) {
      result = { code: err.code, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
    }

    return { ...result, before, after: await readFile(registryPath, 'utf8') };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

const PKG = {
  name: 'ssh-mcp',
  version: '9.9.9',
  mcpName: 'io.github.tufantunc/ssh-mcp',
};

const REGISTRY = (over: Record<string, unknown> = {}, pkgOver: Record<string, unknown> = {}) => ({
  name: 'io.github.tufantunc/ssh-mcp',
  title: 'SSH',
  description: 'Policy-gated SSH.',
  version: '1.0.0',
  packages: [{ registryType: 'npm', identifier: 'ssh-mcp', version: '1.0.0', ...pkgOver }],
  ...over,
});

describe('sync-server-json — write mode', () => {
  /**
   * Both version fields, asserted separately.
   *
   * `packages[].version` is the one the registry resolves against
   * `registry.npmjs.org/<identifier>/<version>` to read `mcpName` out of, so a
   * script that updated only the listing's own `version` would publish an entry
   * pointing at the previous release — whose manifest has no `mcpName` at all.
   * A single deep-equal over the object would still pass if only one of the two
   * were written and the fixture happened to agree.
   */
  it('writes package.json version into both version fields', async () => {
    const r = await withFixture(PKG, REGISTRY());
    expect(r.code).toBe(0);
    const after = JSON.parse(r.after);
    expect(after.version).toBe('9.9.9');
    expect(after.packages[0].version).toBe('9.9.9');
  });

  // The release PR carries this file, so a reformat on every bump would be diff
  // noise a reviewer has to read past to check the version.
  it('preserves 2-space indentation, key order and the trailing newline', async () => {
    const r = await withFixture(PKG, REGISTRY());
    expect(r.after).toBe(`${JSON.stringify(JSON.parse(r.after), null, 2)}\n`);
    expect(Object.keys(JSON.parse(r.after))).toEqual(Object.keys(REGISTRY()));
  });

  it('leaves the file untouched when it is already in sync', async () => {
    const r = await withFixture(PKG, REGISTRY({ version: '9.9.9' }, { version: '9.9.9' }));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('already at 9.9.9');
    expect(r.after).toBe(r.before);
  });
});

describe('sync-server-json — --check', () => {
  /**
   * The release job runs `--check` before it publishes a listing. If that
   * degraded to exit 0 the step would always pass, which is indistinguishable
   * from the step working — so both halves are pinned: the non-zero exit, and
   * that nothing was written.
   */
  it('fails on a stale server.json without writing to it', async () => {
    const r = await withFixture(PKG, REGISTRY(), ['--check']);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('is stale');
    expect(r.after).toBe(r.before);
  });

  it('passes when the versions already agree', async () => {
    const r = await withFixture(
      PKG,
      REGISTRY({ version: '9.9.9' }, { version: '9.9.9' }),
      ['--check'],
    );
    expect(r.code).toBe(0);
  });
});

describe('sync-server-json — ownership guards', () => {
  /**
   * The registry compares the npm manifest's `mcpName` against the submitted
   * server name as its proof that the publisher owns the package. A mismatch is
   * reported as "ownership validation failed" — after the publish.
   */
  it('refuses a mcpName that does not match server.json name', async () => {
    const r = await withFixture({ ...PKG, mcpName: 'io.github.someone/else' }, REGISTRY());
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('does not match');
    expect(r.after).toBe(r.before);
  });

  it('refuses a package.json with no mcpName at all', async () => {
    const { mcpName: _omit, ...noName } = PKG;
    const r = await withFixture(noName, REGISTRY());
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('unset');
  });

  it('refuses an identifier that is not the npm package name', async () => {
    const r = await withFixture(PKG, REGISTRY({}, { identifier: 'ssh-mcp-renamed' }));
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('identifier');
    expect(r.after).toBe(r.before);
  });

  it.each([
    ['no packages key', REGISTRY({ packages: undefined })],
    ['no npm entry', REGISTRY({ packages: [{ registryType: 'oci', identifier: 'x' }] })],
  ])('refuses server.json with %s', async (_label, registry) => {
    const r = await withFixture(PKG, registry);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('no npm package entry');
  });

  /**
   * Ordering, not a second copy of the guards above.
   *
   * The staleness comparison ends in an early `process.exit(0)` for the in-sync
   * case, which is the case every release-PR run and every `--check` run hits.
   * If a guard were ever moved below it, it would stop running exactly when it
   * matters and these tests — which all use a stale fixture — would still pass.
   */
  it('checks ownership even when the versions already agree', async () => {
    const r = await withFixture(
      { ...PKG, mcpName: 'io.github.someone/else' },
      REGISTRY({ version: '9.9.9' }, { version: '9.9.9' }),
      ['--check'],
    );
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('does not match');
  });
});

/**
 * The repo's own two files, with no fixtures.
 *
 * This is the half that fails on the pull request that breaks something, rather
 * than on the release two merges later: `npm run version` only runs when a
 * release PR is generated, and `mcp-publisher validate` only in the registry
 * job. The values below are hand-edited — nothing generates a title or a
 * description — so they are exactly the ones a person can get wrong.
 *
 * The 100-character caps are the registry schema's, on `title` and
 * `description`. They live here rather than in the script because the script
 * would be copying two rules out of a schema `mcp-publisher validate` checks in
 * full; what a test adds is the timing, not the rule.
 */
describe('server.json — the committed state', () => {
  const read = async (name: string) =>
    JSON.parse(await readFile(join(REPO_ROOT, name), 'utf8'));

  it('names the same server as package.json mcpName', async () => {
    const [pkg, registry] = await Promise.all([read('package.json'), read('server.json')]);
    expect(registry.name).toBe(pkg.mcpName);
  });

  it('points at exactly one npm package, and it is this one', async () => {
    const [pkg, registry] = await Promise.all([read('package.json'), read('server.json')]);
    const npm = registry.packages.filter((p: { registryType: string }) => p.registryType === 'npm');
    expect(npm).toHaveLength(1);
    expect(npm[0].identifier).toBe(pkg.name);
    // Not optional the way the schema suggests: the official registry's npm
    // validator rejects a package entry with no version outright, because the
    // version is what identifies the manifest it reads `mcpName` from.
    expect(npm[0].version).toBe(pkg.version);
    expect(registry.version).toBe(pkg.version);
  });

  it.each(['title', 'description'])('keeps %s within the schema cap', async (field) => {
    const registry = await read('server.json');
    expect(registry[field].length).toBeLessThanOrEqual(100);
  });

  // The npm description is over that cap, which is why the two texts differ
  // rather than one being copied from the other. If npm's ever fits, someone
  // will reasonably wonder whether the divergence was still deliberate.
  it('has an npm description that genuinely could not be reused', async () => {
    const pkg = await read('package.json');
    expect(pkg.description.length).toBeGreaterThan(100);
  });
});
