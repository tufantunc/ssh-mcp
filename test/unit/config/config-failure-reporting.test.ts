import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { chmod } from 'fs/promises';
import { platform } from 'os';
import { join } from 'path';
import { loadConfig, getConfigPath } from '../../../src/config/loader.js';
import { ConfigNotFoundError, OperatorError } from '../../../src/errors.js';
import { makeConfigDir, MINIMAL_CONFIG, type ConfigDir } from './helpers.js';

/**
 * These import `src/cli.ts`, not `src/index.ts`. That is the whole reason `cli.ts` exists:
 * index.ts runs `main()` at import time unless `SSH_MCP_DISABLE_MAIN=1`, and the dynamic
 * imports below re-evaluated that gate on every call — so this file used to carry a
 * `vi.stubEnv` for it, without which a single-file run failed with "process.exit
 * unexpectedly called with 2" — and started connecting on a machine with a real config.
 * (2 is EXIT_OPERATOR_ERROR: a missing config file is the operator's, not our defect,
 * which is the distinction errors.ts exists to keep. The comment this replaces said 1,
 * and had said it since before the split.) Nothing in cli.ts has an import-time side
 * effect.
 *
 * #138: a Windows operator put a valid config at the documented path and was
 * told "No config file found". The file was there. `checkPermissions` rejected
 * it over POSIX mode bits that Windows does not have, and `buildAppConfig`'s
 * bare `catch {}` relabelled that as a missing file.
 *
 * Two separate defects, so two separate groups of tests: what `loadConfig`
 * reports, and what the caller does with it. The bug needed both to be wrong.
 */

let cfg: ConfigDir;
let tempDir: string;

beforeEach(async () => {
  cfg = await makeConfigDir('ssh-mcp-fail-');
  tempDir = cfg.dir;
});

afterEach(async () => {
  await cfg.cleanup();
  vi.unstubAllEnvs();
  vi.resetModules();
  vi.doUnmock('../../../src/config/loader.js');
});

const writeConfig = (content: string, mode = 0o600): Promise<string> => cfg.write(content, mode);

describe('loadConfig distinguishes "absent" from "unusable"', () => {
  it('reports a missing file as ConfigNotFoundError', async () => {
    const missing = join(tempDir, 'nope.toml');
    await expect(loadConfig(missing)).rejects.toBeInstanceOf(ConfigNotFoundError);
  });

  it('names the path it actually looked in', async () => {
    const missing = join(tempDir, 'nope.toml');
    await expect(loadConfig(missing)).rejects.toThrow(missing);
  });

  // Each of these is a file that exists. Reporting any of them as "not found"
  // sends the operator to re-create a file they already have.
  it('does not report malformed TOML as not-found', async () => {
    const path = await writeConfig('this is not = valid = toml [[[[');
    await expect(loadConfig(path)).rejects.not.toBeInstanceOf(ConfigNotFoundError);
    await expect(loadConfig(path)).rejects.toThrow(/Failed to parse TOML/);
  });

  it('does not report a schema violation as not-found', async () => {
    const path = await writeConfig('[defaults]\ndefaultProfile = "dev"\n');
    await expect(loadConfig(path)).rejects.not.toBeInstanceOf(ConfigNotFoundError);
  });

  it.skipIf(platform() === 'win32')('does not report a permission failure as not-found', async () => {
    const path = await writeConfig(MINIMAL_CONFIG, 0o644);
    await expect(loadConfig(path)).rejects.not.toBeInstanceOf(ConfigNotFoundError);
    await expect(loadConfig(path)).rejects.toThrow(/accessible/);
  });

  // Every config failure is the operator's file, not our bug, so none of them
  // should reach them as a stack trace.
  it('marks config failures as operator errors', async () => {
    const path = await writeConfig('nope = = =');
    await expect(loadConfig(path)).rejects.toBeInstanceOf(OperatorError);
  });

  // The neighbouring case to #138: a config that exists but cannot be opened.
  // It used to escape as the raw EACCES SystemError, which reportFatal prints
  // with a stack — the presentation defect this change set out to remove.
  it.skipIf(platform() === 'win32' || process.getuid?.() === 0)(
    'reports an unreadable file as an operator error naming the path',
    async () => {
      const path = await writeConfig(MINIMAL_CONFIG);
      await chmod(path, 0o000);
      try {
        await expect(loadConfig(path)).rejects.toBeInstanceOf(OperatorError);
        await expect(loadConfig(path)).rejects.toThrow(path);
        await expect(loadConfig(path)).rejects.not.toBeInstanceOf(ConfigNotFoundError);
      } finally {
        await chmod(path, 0o600);
      }
    },
  );
});

describe('buildAppConfig only falls through when the file is absent', () => {
  /**
   * Driven through a mocked loader rather than a real file: the fall-through
   * branch calls `loadConfig()` with no argument, so it reads
   * `getConfigPath()`, and on macOS that path is not redirectable by any env
   * var. Mocking the module tests the branch itself, which is the part that
   * was wrong.
   */
  type Errors = typeof import('../../../src/errors.js');

  let loadConfigMock: ReturnType<typeof vi.fn>;

  async function buildWith(
    makeErr: (E: Errors) => Error,
    argv: Record<string, string | null>,
  ) {
    vi.resetModules();
    // Built from the post-reset instance of errors.js on purpose. The check
    // under test is `instanceof`, and a class imported before resetModules is a
    // different object from the one cli.ts resolves afterwards — the test
    // would fail on the module registry rather than on the behaviour.
    const E = await import('../../../src/errors.js');
    const err = makeErr(E);
    vi.doMock('../../../src/config/loader.js', async () => {
      const actual = await vi.importActual<typeof import('../../../src/config/loader.js')>(
        '../../../src/config/loader.js',
      );
      loadConfigMock = vi.fn().mockRejectedValue(err);
      return { ...actual, loadConfig: loadConfigMock };
    });
    const { buildAppConfig } = await import('../../../src/cli.js');
    return buildAppConfig(argv);
  }

  it('falls through to --host/--user when there is no config file', async () => {
    const config = await buildWith((E) => new E.ConfigNotFoundError('/nowhere/config.toml'), {
      host: 'example.com',
      user: 'deploy',
    });
    expect(config.profiles[0].host).toBe('example.com');
    // Without this the test would also pass if buildAppConfig stopped consulting
    // the config file at all.
    expect(loadConfigMock).toHaveBeenCalledTimes(1);
  });

  // The defect. A config that exists and is broken must not be reported as a
  // missing config, and must not be reported as a missing --host either.
  it('surfaces a permission failure instead of relabelling it', async () => {
    await expect(
      // Deliberately not a copy of the real wording: the loader is mocked here,
      // so a full replica would rot into fiction while still passing. The real
      // text is asserted against the real loader in loader.test.ts.
      buildWith((E) => new E.OperatorError('... group/world accessible ...'), {}),
    ).rejects.toThrow(/group\/world accessible/);
  });

  it('surfaces a broken config even when --host/--user would have worked', async () => {
    // Falling through here is worse than failing: the operator gets a server
    // that silently ignores every profile, policy and role binding they wrote.
    await expect(
      buildWith(
        (E) => new E.OperatorError('Failed to parse TOML config at /home/x/config.toml: unexpected token'),
        { host: 'example.com', user: 'deploy' },
      ),
    ).rejects.toThrow(/Failed to parse TOML/);
  });

  it('names the platform config path when nothing was given at all', async () => {
    // The message hardcoded ~/.config/ssh-mcp/config.toml on every platform,
    // while getConfigPath() sends Windows to %APPDATA% and macOS to Library.
    // It told Windows operators to create a file the code never reads.
    //
    // The assertion moved with the message rather than being dropped: nothing given at all
    // is no longer a rejection — the server starts unconfigured so it can be introspected —
    // so the path is checked where it is now said, on stderr at startup. #138's lesson is
    // about the path being right, not about which call reports it.
    const warnings: string[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
      warnings.push(String(a[0]));
    });
    try {
      await buildWith((E) => new E.ConfigNotFoundError(getConfigPath()), {});
    } finally {
      spy.mockRestore();
    }
    expect(warnings.join('\n')).toContain(getConfigPath());
  });

  describe('an unconfigured server still describes itself', () => {
    /**
     * Starting with no config used to be fatal, which meant an MCP directory or a client's
     * "add this server" flow got a process that exits before the handshake — measured against
     * our own image, `initialize` and `tools/list` drew no JSON-RPC response at all, only the
     * config error on stderr.
     *
     * Tool definitions are static metadata; the config decides what those tools may *reach*.
     * Coupling "no config" to "no server" bought no safety and cost every introspection.
     */
    it('builds an empty config instead of refusing', async () => {
      const config = await buildWith((E) => new E.ConfigNotFoundError('/nowhere/config.toml'), {});
      expect(config.profiles).toEqual([]);
    });

    it('says so on stderr rather than starting silently', async () => {
      // An operator who mistypes a flag would otherwise get a server that looks fine and
      // fails per call. The warning names the same remedy the old refusal did.
      const warnings: string[] = [];
      const spy = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
        warnings.push(String(a[0]));
      });
      try {
        await buildWith((E) => new E.ConfigNotFoundError('/nowhere/config.toml'), {});
      } finally {
        spy.mockRestore();
      }
      expect(warnings.join('\n')).toMatch(/No config file found/);
    });

    it('still refuses when --config names a file that is not there', async () => {
      // A named path that does not exist is a typo, not a discovery scenario. Only the
      // no-config-at-all case softens.
      await expect(
        buildWith((E) => new E.ConfigNotFoundError('/x/typo.toml'), { config: '/x/typo.toml' }),
      ).rejects.toThrow(/typo\.toml/);
    });

    it('still refuses a half-given quick start', async () => {
      await expect(
        buildWith((E) => new E.ConfigNotFoundError('/nowhere/config.toml'), { host: 'example.com' }),
      ).rejects.toThrow(/--host\/--user/);
    });
  });
});

describe('buildAppConfig threads --allowUncheckedConfigAcl to the loader', () => {
  /**
   * The escape hatch, tested at its wiring rather than below it.
   *
   * Both halves of this were mutation survivors on *every* platform: replacing
   * `flagEnabled(argv, 'allowUncheckedConfigAcl')` with `false`, and dropping the
   * options argument from either `loadConfig` call, left the whole suite green.
   * That matters more here than for any other flag, because it is the only way out
   * of a startup the server is already refusing — an operator whose ACL cannot be
   * read would be locked out with no exit, which is the shape of #138.
   */
  let loadConfigMock: ReturnType<typeof vi.fn>;

  async function build(argv: Record<string, string | null>) {
    vi.resetModules();
    vi.doMock('../../../src/config/loader.js', async () => {
      const actual = await vi.importActual<typeof import('../../../src/config/loader.js')>(
        '../../../src/config/loader.js',
      );
      loadConfigMock = vi.fn().mockResolvedValue({
        defaults: { defaultProfile: 'p' },
        profiles: [{ name: 'p', host: 'h', user: 'u' }],
      });
      return { ...actual, loadConfig: loadConfigMock };
    });
    const { buildAppConfig } = await import('../../../src/cli.js');
    await buildAppConfig(argv);
    return loadConfigMock;
  }

  it('passes allowUnchecked on the --config branch', async () => {
    // `null` is what parseArgv stores for a bare `--flag`, which is how every
    // documented boolean flag is written (#91).
    const mock = await build({ config: '/x/config.toml', allowUncheckedConfigAcl: null });
    expect(mock).toHaveBeenCalledWith('/x/config.toml', expect.objectContaining({ allowUnchecked: true }));
  });

  it('passes allowUnchecked on the default-path branch', async () => {
    const mock = await build({ allowUncheckedConfigAcl: null });
    expect(mock).toHaveBeenCalledWith(undefined, expect.objectContaining({ allowUnchecked: true }));
  });

  it('defaults to false when the flag is absent', async () => {
    const mock = await build({ config: '/x/config.toml' });
    expect(mock).toHaveBeenCalledWith('/x/config.toml', expect.objectContaining({ allowUnchecked: false }));
  });

  it('supplies a sink, so the loader does not own the operator output channel', async () => {
    // Three reviewers pointed out the seam existed and nothing used it: the option was
    // documented as letting main() decide, while main() took the module's stderr default.
    const mock = await build({ config: '/x/config.toml' });
    const opts = mock.mock.calls[0][1] as { onFinding?: unknown };
    expect(typeof opts.onFinding).toBe('function');
  });

  it.each([
    ['strictConfigAcl', 'enforce'],
    ['allowUncheckedConfigAcl', 'allowUnchecked'],
  ] as const)('threads --%s to the loader as %s', async (flag, option) => {
    // Both flags, at their wiring rather than below it. `strict: true` — reinstating the
    // 2.3.0 default that blocked the reporter of #138 — survived the whole suite, exactly
    // as the allowUnchecked mutations did a round earlier. The flag's presence is the
    // evidence an operator relies on, so an unconnected flag is worse than none.
    const on = await build({ config: '/x/config.toml', [flag]: null });
    expect(on).toHaveBeenCalledWith('/x/config.toml', expect.objectContaining({ [option]: true }));

    const off = await build({ config: '/x/config.toml' });
    expect(off).toHaveBeenCalledWith('/x/config.toml', expect.objectContaining({ [option]: false }));

    const explicit = await build({ config: '/x/config.toml', [flag]: 'false' });
    expect(explicit).toHaveBeenCalledWith('/x/config.toml', expect.objectContaining({ [option]: false }));

    // The default-path branch passes the same object, so neither can drift.
    const viaDefault = await build({ [flag]: null });
    expect(viaDefault).toHaveBeenCalledWith(undefined, expect.objectContaining({ [option]: true }));
  });

  it('honours an explicit --allowUncheckedConfigAcl=false', async () => {
    const mock = await build({ config: '/x/config.toml', allowUncheckedConfigAcl: 'false' });
    expect(mock).toHaveBeenCalledWith('/x/config.toml', expect.objectContaining({ allowUnchecked: false }));
  });
});
