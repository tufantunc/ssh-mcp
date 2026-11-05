import { beforeEach, afterEach, expect, onTestFinished, vi, type Mock } from 'vitest';
import { mkdtemp, writeFile, chmod, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { OperatorError } from '../../../src/errors.js';

/**
 * A minimal valid config, in one place. The next change to the schema that makes this
 * TOML invalid should break one place, not leave a second copy passing for the wrong
 * reason — the same argument test/integration/helpers.ts already makes.
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
 * A fresh temp dir for every test in the calling file or `describe`, created and removed
 * by hooks this registers itself, so no caller writes its own lifecycle. `write` puts
 * `config.toml` in it.
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
  // OperatorError is what every check under test refuses with. `Error` is for the caller
  // that imports the module after `resetModules`, whose OperatorError is another class.
  type: abstract new (...args: never[]) => Error = OperatorError,
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

type Errors = typeof import('../../../src/errors.js');

/**
 * cli.ts, freshly imported, with the loader's parse replaced by the mock `makeParse`
 * returns — for the branches that read `getConfigPath()`, which on macOS no env var can
 * redirect. The mock is undone when the test finishes.
 *
 * `makeParse` receives the post-reset instance of errors.js on purpose. Some checks under
 * test are `instanceof`, and a class imported before `resetModules` is a different object
 * from the one cli.ts resolves afterwards — the test would fail on the module registry
 * rather than on the behaviour.
 */
export async function withMockedLoader(makeParse: (E: Errors) => Mock<(...a: unknown[]) => unknown>) {
  vi.resetModules();
  const E = await import('../../../src/errors.js');
  const parse = makeParse(E);
  vi.doMock('../../../src/config/loader.js', async () => {
    const actual = await vi.importActual<typeof import('../../../src/config/loader.js')>(
      '../../../src/config/loader.js',
    );
    // cli.ts loads through loadConfigWithDigest; the mock stands in for the parse.
    return { ...actual, loadConfigWithDigest: async (...a: unknown[]) => ({ config: await parse(...a), sha256: 'stub' }) };
  });
  onTestFinished(() => {
    vi.doUnmock('../../../src/config/loader.js');
    vi.resetModules();
  });
  const loader = await import('../../../src/config/loader.js');
  const { loadAppConfig } = await import('../../../src/cli.js');
  return { E, loader, loadAppConfig, parse };
}
