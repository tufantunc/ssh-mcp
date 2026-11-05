import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'crypto';
import { readFile } from 'fs/promises';
import { useConfigDir, withMockedLoader, MINIMAL_CONFIG } from '../config/helpers.js';

/**
 * A reload has to know where the running config came from, so `loadAppConfig` tags
 * each of its three outcomes. The default-path cases go through a mocked
 * loader for the reason config-failure-reporting.test.ts gives: that path is not
 * redirectable on macOS.
 */

const cfg = useConfigDir('ssh-mcp-source-');

describe('loadAppConfig tags the config with its source', () => {
  it('reports an explicit --config file as source file', async () => {
    const path = await cfg.write(MINIMAL_CONFIG, 0o600);
    vi.resetModules();
    const { loadAppConfig } = await import('../../../src/cli.js');
    const loaded = await loadAppConfig({ config: path });
    expect(loaded.source).toBe('file');
    expect(loaded.path).toBe(path);
    expect(loaded.config.profiles.length).toBeGreaterThan(0);
    expect(loaded.sha256).toBe(createHash('sha256').update(await readFile(path)).digest('hex'));
    expect(Number.isNaN(Date.parse(loaded.loadedAt))).toBe(false);
  });

  it('reports the default-path file as source file', async () => {
    const { loader, loadAppConfig } = await withMockedLoader(() => vi.fn(async () => ({ defaults: {}, profiles: [] })));
    const loaded = await loadAppConfig({});
    expect(loaded.source).toBe('file');
    expect(loaded.path).toBe(loader.getConfigPath());
  });

  it('reports --host/--user with no file as source flags', async () => {
    const { loader, loadAppConfig } = await withMockedLoader((E) => vi.fn(async () => {
      throw new E.ConfigNotFoundError('/nowhere/config.toml');
    }));
    const loaded = await loadAppConfig({ host: 'example.com', user: 'deploy' });
    expect(loaded.source).toBe('flags');
    expect(loaded.path).toBe(loader.getConfigPath());
    expect(loaded.sha256).toBeNull();
    expect(loaded.config.profiles[0].host).toBe('example.com');
  });

  it('reports nothing configured as source unconfigured with no profiles', async () => {
    const { loader, loadAppConfig } = await withMockedLoader((E) => vi.fn(async () => {
      throw new E.ConfigNotFoundError('/nowhere/config.toml');
    }));
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const loaded = await loadAppConfig({});
    err.mockRestore();
    expect(loaded.source).toBe('unconfigured');
    expect(loaded.path).toBe(loader.getConfigPath());
    expect(loaded.sha256).toBeNull();
    expect(loaded.config.profiles).toEqual([]);
  });
});

describe('loadConfigWithDigest and aclOptionsFromArgv', () => {
  it('loadConfigWithDigest loads a file through the startup validation path, with its hash', async () => {
    const path = await cfg.write(MINIMAL_CONFIG, 0o600);
    vi.resetModules();
    const { loadConfigWithDigest } = await import('../../../src/config/loader.js');
    const { config, sha256 } = await loadConfigWithDigest(path, {});
    expect(config.profiles.length).toBeGreaterThan(0);
    expect(sha256).toBe(createHash('sha256').update(await readFile(path)).digest('hex'));
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
