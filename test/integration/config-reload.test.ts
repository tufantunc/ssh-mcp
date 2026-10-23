import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import type { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import type { AppConfig } from '../../src/types.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';
import { PORTS, createAppConfig, createRegistry, setupEnv } from './fixtures.js';

/** The same config with one profile's fields overridden. */
function withProfile(name: string, overrides: Record<string, unknown>): AppConfig {
  const config = createAppConfig();
  return {
    ...config,
    profiles: config.profiles.map((p) => (p.name === name ? { ...p, ...overrides } : p)),
  };
}

const up = await isSshServerUp(SSH_HOST, PORTS.admin);
assertAvailable(up, `admin (${SSH_HOST}:${PORTS.admin})`);

describe.skipIf(!up)('config reload during an in-flight connect (Review Focus 2)', () => {
  const env = setupEnv();
  let registry: ConnectionRegistry;

  beforeAll(() => env.save());
  afterAll(() => env.restore());
  afterEach(async () => {
    await registry?.closeAll();
  });

  it('discards a connect that resolves after a connection-field swap', async () => {
    registry = createRegistry();
    const connecting = registry.getOrCreate('admin');

    const result = registry.applyConfig(withProfile('admin', { user: 'operator' }));
    expect(result.diff.changed).toEqual([{ name: 'admin', fields: ['user'] }]);

    await expect(connecting).rejects.toThrow(
      'The configuration was reloaded while connecting; retry the call.',
    );
    expect(registry.get('admin')).toBeUndefined();
    expect(registry.liveConnections()).toEqual([]);
  });

  it('discards it on a policy-only swap too, and the retry connects under the new profile', async () => {
    registry = createRegistry();
    const connecting = registry.getOrCreate('admin');

    registry.applyConfig(withProfile('admin', { role: 'viewer' }));

    await expect(connecting).rejects.toThrow(/reloaded while connecting/);
    expect(registry.get('admin')).toBeUndefined();

    const conn = await registry.getOrCreate('admin');
    expect(conn.isConnected()).toBe(true);
    expect(conn.profile.role).toBe('viewer');
    expect(registry.get('admin')).toBe(conn);
  });

  it('keeps a stored connection reconnecting across a policy-only swap', async () => {
    // applyConfig saw this one (it is in the map) and swapped its profile in place, so it
    // is current: discarding it would kill its sessions for nothing.
    registry = createRegistry();
    const conn = await registry.getOrCreate('admin');
    await conn.close();
    expect(conn.isConnected()).toBe(false);

    const reconnecting = registry.getOrCreate('admin');
    const result = registry.applyConfig(withProfile('admin', { role: 'viewer' }));
    expect(result.toClose).toEqual([]);

    await expect(reconnecting).resolves.toBe(conn);
    expect(conn.isConnected()).toBe(true);
    expect(conn.profile.role).toBe('viewer');
    expect(registry.get('admin')).toBe(conn);
  });

  it('refuses a stored connection reconnecting across a connection-field swap', async () => {
    registry = createRegistry();
    const conn = await registry.getOrCreate('admin');
    await conn.close();

    const reconnecting = registry.getOrCreate('admin');
    const result = registry.applyConfig(withProfile('admin', { user: 'operator' }));
    expect(result.toClose.map((c) => c.conn)).toEqual([conn]);

    await expect(reconnecting).rejects.toThrow(/reloaded while connecting/);
    expect(registry.get('admin')).toBeUndefined();
    await conn.close();
  });
});
