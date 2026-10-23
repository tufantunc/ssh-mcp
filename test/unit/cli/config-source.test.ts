import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { makeConfigDir, MINIMAL_CONFIG, type ConfigDir } from '../config/helpers.js';

/**
 * A reload has to know where the running config came from, so `loadAppConfig` tags
 * each of `buildAppConfig`'s three outcomes. The default-path cases go through a mocked
 * loader for the reason config-failure-reporting.test.ts gives: that path is not
 * redirectable on macOS.
 */

let cfg: ConfigDir;

beforeEach(async () => {
  cfg = await makeConfigDir('ssh-mcp-source-');
});

afterEach(async () => {
  await cfg.cleanup();
  vi.resetModules();
  vi.doUnmock('../../../src/config/loader.js');
});

async function withLoader(impl: (path?: string) => Promise<unknown>) {
  vi.resetModules();
  const E = await import('../../../src/errors.js');
  vi.doMock('../../../src/config/loader.js', async () => {
    const actual = await vi.importActual<typeof import('../../../src/config/loader.js')>(
      '../../../src/config/loader.js',
    );
    return { ...actual, loadConfig: vi.fn(impl) };
  });
  const loader = await import('../../../src/config/loader.js');
  const cli = await import('../../../src/cli.js');
  return { E, loader, cli };
}

describe('loadAppConfig tags the config with its source', () => {
  it('reports an explicit --config file as source file', async () => {
    const path = await cfg.write(MINIMAL_CONFIG, 0o600);
    vi.resetModules();
    const { loadAppConfig } = await import('../../../src/cli.js');
    const loaded = await loadAppConfig({ config: path });
    expect(loaded.source).toBe('file');
    expect(loaded.path).toBe(path);
    expect(loaded.config.profiles.length).toBeGreaterThan(0);
  });

  it('reports the default-path file as source file', async () => {
    const { loader, cli } = await withLoader(async () => ({ defaults: {}, profiles: [] }));
    const loaded = await cli.loadAppConfig({});
    expect(loaded.source).toBe('file');
    expect(loaded.path).toBe(loader.getConfigPath());
  });

  it('reports --host/--user with no file as source flags', async () => {
    const { E, loader, cli } = await withLoader(async () => {
      throw new E.ConfigNotFoundError('/nowhere/config.toml');
    });
    const loaded = await cli.loadAppConfig({ host: 'example.com', user: 'deploy' });
    expect(loaded.source).toBe('flags');
    expect(loaded.path).toBe(loader.getConfigPath());
    expect(loaded.config.profiles[0].host).toBe('example.com');
  });

  it('reports nothing configured as source unconfigured with no profiles', async () => {
    const { E, loader, cli } = await withLoader(async () => {
      throw new E.ConfigNotFoundError('/nowhere/config.toml');
    });
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const loaded = await cli.loadAppConfig({});
    err.mockRestore();
    expect(loaded.source).toBe('unconfigured');
    expect(loaded.path).toBe(loader.getConfigPath());
    expect(loaded.config.profiles).toEqual([]);
  });

  it('buildAppConfig still returns just the config', async () => {
    const path = await cfg.write(MINIMAL_CONFIG, 0o600);
    vi.resetModules();
    const { buildAppConfig, loadAppConfig } = await import('../../../src/cli.js');
    expect(await buildAppConfig({ config: path })).toEqual((await loadAppConfig({ config: path })).config);
  });
});

describe('loadConfigFile and aclOptionsFromArgv', () => {
  it('loadConfigFile loads a file through the startup validation path', async () => {
    const path = await cfg.write(MINIMAL_CONFIG, 0o600);
    vi.resetModules();
    const { loadConfigFile } = await import('../../../src/cli.js');
    const config = await loadConfigFile(path, {});
    expect(config.profiles.length).toBeGreaterThan(0);
  });

  it('aclOptionsFromArgv reads the two ACL flags', async () => {
    vi.resetModules();
    const { aclOptionsFromArgv } = await import('../../../src/cli.js');
    const o = aclOptionsFromArgv({ strictConfigAcl: 'true', allowUncheckedConfigAcl: 'true' });
    expect(o.enforce).toBe(true);
    expect(o.allowUnchecked).toBe(true);
    expect(typeof o.onFinding).toBe('function');
  });
});
