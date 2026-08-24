import { describe, it, expect } from 'vitest';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { defaultsFromArgv } from '../../../src/cli.js';
import { UnconfiguredError, OperatorError } from '../../../src/errors.js';
import type { AppConfig } from '../../../src/types.js';

/**
 * The unconfigured refusal belongs to the registry, not to the loader's lookup.
 *
 * It was first written into `getProfile` in the config loader, which can only check the
 * branch where no profile was named. A client with a profile name baked into its MCP
 * config — a common setup — took the other branch and got `Profile "prod" not found`:
 * a message telling the operator they mistyped a name when in fact they had no config at
 * all, and omitting the config path the whole change exists to deliver. `ConnectionRegistry`
 * is the only importer of the loader's `getProfile` anywhere under `src/`, so checking here
 * covers both branches and every tool that resolves a profile.
 */

/** The exact shape `cli.ts` builds when nothing is configured — not a hand-written cast. */
const unconfigured = (): AppConfig => ({ defaults: defaultsFromArgv({}), profiles: [] });

describe('ConnectionRegistry with nothing configured', () => {
  it('refuses a profile lookup with the operator message', () => {
    const registry = new ConnectionRegistry(unconfigured());
    expect(() => registry.getProfile()).toThrow(UnconfiguredError);
    expect(() => registry.getProfile()).toThrow(/No config file found and missing required --host\/--user/);
  });

  it('gives the same explanation when a profile name was asked for', () => {
    // The branch the loader's own guard could never reach.
    const registry = new ConnectionRegistry(unconfigured());
    expect(() => registry.getProfile('prod')).toThrow(/No config file found/);
    expect(() => registry.getProfile('prod')).not.toThrow(/Profile "prod" not found/);
  });

  it('names the config path, so the caller learns the remedy and not just the problem', () => {
    const registry = new ConnectionRegistry(unconfigured());
    try {
      registry.getProfile();
      expect.unreachable('should have refused');
    } catch (err) {
      expect(err).toBeInstanceOf(UnconfiguredError);
      expect((err as UnconfiguredError).configPath).toMatch(/config\.toml$/);
      expect((err as Error).message).toContain((err as UnconfiguredError).configPath);
    }
  });

  it('refuses `get` too, so no tool reaches a connection', () => {
    const registry = new ConnectionRegistry(unconfigured());
    expect(() => registry.get()).toThrow(UnconfiguredError);
  });

  it('is an OperatorError, so it exits 2 rather than reading as a crash', () => {
    // The startup refusal it replaced was one, and a supervisor tells the two apart by
    // exit status.
    const registry = new ConnectionRegistry(unconfigured());
    expect(() => registry.getProfile()).toThrow(OperatorError);
  });

  it('stops refusing once a profile exists', () => {
    // The guard must key on the profile list rather than on anything about startup:
    // a configured server is unaffected by any of this.
    const config = unconfigured();
    const profile = { name: 'dev', host: 'h', port: 22, user: 'u' } as any;
    const registry = new ConnectionRegistry({ ...config, profiles: [profile] });
    expect(registry.getProfile()).toBe(profile);
    expect(registry.getProfile('dev')).toBe(profile);
  });
});
