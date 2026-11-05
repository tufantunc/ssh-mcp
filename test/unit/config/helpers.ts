import { beforeEach, afterEach, expect } from 'vitest';
import { mkdtemp, writeFile, chmod, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * The tempdir + writeConfig lifecycle the config test files need.
 *
 * Extracted because it existed twice verbatim, along with two copies of the
 * minimal valid config under two names. The next change to the schema that makes
 * this TOML invalid should break one place, not leave a second copy passing for
 * the wrong reason — the same argument test/integration/helpers.ts already makes.
 */
export const MINIMAL_CONFIG = `
[[profiles]]
name = "dev"
host = "localhost"
user = "test"
`;

export interface ConfigDir {
  dir: string;
  /** Write config.toml into the temp dir. `mode` is a no-op on Windows. */
  write(content?: string, mode?: number): Promise<string>;
  cleanup(): Promise<void>;
}

export async function makeConfigDir(prefix = 'ssh-mcp-test-'): Promise<ConfigDir> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  return {
    dir,
    async write(content = MINIMAL_CONFIG, mode = 0o600) {
      const path = join(dir, 'config.toml');
      await writeFile(path, content, 'utf8');
      await chmod(path, mode);
      return path;
    },
    async cleanup() {
      await rm(dir, { recursive: true, force: true });
    },
  };
}

/**
 * A fresh config dir for every test in the calling file, created and removed by hooks it
 * registers itself. Four files spelled out the same `let tempDir` / `beforeEach` /
 * `afterEach` / `writeConfig` shim around `makeConfigDir` or a copy of it.
 */
export function useConfigDir(prefix?: string): ConfigDir {
  let current: ConfigDir | undefined;
  beforeEach(async () => { current = await makeConfigDir(prefix); });
  afterEach(async () => { await current?.cleanup(); current = undefined; });
  const live = (): ConfigDir => {
    if (!current) throw new Error('useConfigDir: used outside a test');
    return current;
  };
  return {
    get dir() { return live().dir; },
    write: (content, mode) => live().write(content, mode),
    cleanup: () => live().cleanup(),
  };
}

/**
 * Awaits a refusal and names the behaviour when there isn't one. `.catch(e => e)` leaves
 * `undefined` on the success path, so the assertion after it fails with "cannot read
 * properties of undefined" — which points at the test rather than at "the check accepted
 * a file granted to Everyone", on a job a reviewer may not be able to reproduce locally.
 */
export async function refusal(
  pending: Promise<unknown>,
  type: abstract new (...args: never[]) => Error = Error,
): Promise<Error> {
  const err = await pending.then(() => null, (e: unknown) => e);
  expect(err, 'expected a refusal, but the call resolved').toBeInstanceOf(type);
  return err as Error;
}

/**
 * Ask the Windows ACL check to enforce rather than report.
 *
 * One spelling for both config suites: they had a frozen `STRICT` literal in one and a
 * spreading `strict()` builder in the other, for one concept — and the literal forced
 * `{ ...STRICT, allowUnchecked: true }` at the one call site that extends it, which is
 * the spread a builder exists to hide.
 */
export const enforceAcl = <T extends object>(extra: T = {} as T) =>
  ({ ...extra, enforce: true as const });
