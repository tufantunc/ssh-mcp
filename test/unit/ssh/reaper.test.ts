import { describe, it, expect, vi } from 'vitest';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { reapOnce } from '../../../src/ssh/reaper.js';
import { defaultsFromArgv } from '../../../src/cli.js';
import type { AppConfig, Profile } from '../../../src/types.js';

const profile = (name: string): Profile =>
  ({ name, host: 'h', port: 22, username: 'u' }) as unknown as Profile;

const configWith = (...names: string[]): AppConfig => ({
  defaults: defaultsFromArgv({}),
  profiles: names.map(profile),
});

/** A stand-in for SSHConnection with just what the reaper touches. */
const fakeConn = (reapExpiredSessions = vi.fn(async () => {})) => ({
  reapExpiredSessions,
  toInfo: () => ({ sessionCount: 0, lastActivity: new Date(0) }),
  close: vi.fn(async () => {}),
});

describe('reapOnce', () => {
  it('survives a connection whose profile has been removed from the config', async () => {
    const registry = new ConnectionRegistry(configWith('a'));
    const conn = fakeConn();
    (registry as any).connections.set('a', conn);
    // Not applyConfig: it takes a removed profile's connection out of the map, so the
    // reaper would never see it. This pins the reaper's own guard, should a connection
    // without a profile ever be stored by some other path.
    (registry as any).config = configWith('b');

    await expect(reapOnce(registry)).resolves.toBeUndefined();
    expect(conn.reapExpiredSessions).toHaveBeenCalledTimes(1);
    expect(registry.liveConnections()).toHaveLength(0); // idle, so reaped
  });

  it('keeps going when one connection fails to reap its sessions', async () => {
    const registry = new ConnectionRegistry(configWith('a', 'b'));
    const bad = fakeConn(vi.fn(async () => { throw new Error('boom'); }));
    const good = fakeConn();
    (registry as any).connections.set('a', bad);
    (registry as any).connections.set('b', good);

    await expect(reapOnce(registry)).resolves.toBeUndefined();
    expect(good.reapExpiredSessions).toHaveBeenCalledTimes(1);
  });
});
