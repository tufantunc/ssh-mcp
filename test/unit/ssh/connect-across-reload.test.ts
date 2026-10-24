import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import { defaultsFromArgv } from '../../../src/cli.js';
import type { AppConfig, Profile } from '../../../src/types.js';

/**
 * A new connection still being opened when a reload lands.
 *
 * Every applied reload used to fail every connect in flight, on every profile, even for
 * an unchanged file, so a client calling reload-config in a loop could keep failing other
 * sessions' first connects. Only a connect the reload actually invalidates is discarded:
 * its profile was removed, a connection field changed, or it runs through a bastion that
 * is closing. Any other is stored, with the profile as the reload left it.
 *
 * Stubbed `ssh2.Client` whose handshake completes only when the test says so, so the
 * reload can land at exactly the point a connect is in flight.
 */

interface Fake extends EventEmitter {
  ended: boolean;
  ready(): void;
}

let clients: Fake[];

beforeEach(() => {
  clients = [];
  // Any password: the stubbed client never checks it.
  vi.stubEnv('SSH_MCP_PASSWORD', 'x');
  vi.resetModules();
  vi.doMock('ssh2', () => {
    class FakeClient extends EventEmitter {
      ended = false;
      constructor() {
        super();
        clients.push(this as unknown as Fake);
      }
      connect() { return this; }
      ready() { this.emit('ready'); }
      forwardOut(_a: string, _b: number, _h: string, _p: number, cb: (err: Error | undefined, s: unknown) => void) {
        cb(undefined, new EventEmitter());
      }
      end() { this.ended = true; }
    }
    return { Client: FakeClient, default: { Client: FakeClient } };
  });
});

afterEach(() => {
  vi.doUnmock('ssh2');
  vi.unstubAllEnvs();
  vi.resetModules();
});

const profile = (name: string, overrides: Partial<Profile> = {}): Profile => ({
  name, group: 'dev', host: `${name}.example.test`, port: 22, user: 'deploy', auth: 'password',
  tty: false, timeout: 30_000, maxChars: 5000, maxOutputBytes: 1000, role: 'admin', readOnly: false,
  announceAgent: true, approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 10_000, sessionBackgroundMaxMs: 10_000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  ...overrides,
});

const configOf = (...profiles: Profile[]): AppConfig => ({ defaults: defaultsFromArgv({}), profiles });

const RELOADED = 'The configuration was reloaded while connecting; retry the call.';

async function registryOf(...profiles: Profile[]) {
  const { ConnectionRegistry } = await import('../../../src/ssh/connection-registry.js');
  return new ConnectionRegistry(configOf(...profiles), 'insecure');
}

/** Wait until `n` clients exist, i.e. the connect reached the handshake. */
const clientsReach = (n: number) => vi.waitFor(() => expect(clients).toHaveLength(n));

describe('a new connect in flight when a reload lands', () => {
  it('survives a reload that does not touch its profile', async () => {
    const registry = await registryOf(profile('web'), profile('db'));
    const connecting = registry.getOrCreate('web');
    await clientsReach(1);

    registry.applyConfig(configOf(profile('web'), profile('db', { role: 'viewer' })));
    clients[0]!.ready();

    const conn = await connecting;
    expect(registry.get('web')).toBe(conn);
    expect(clients[0]!.ended).toBe(false);
  });

  it('survives a reload of an unchanged file', async () => {
    const registry = await registryOf(profile('web'));
    const connecting = registry.getOrCreate('web');
    await clientsReach(1);

    registry.applyConfig(configOf(profile('web')));
    registry.applyConfig(configOf(profile('web')));
    clients[0]!.ready();

    const conn = await connecting;
    expect(registry.get('web')).toBe(conn);
  });

  it('is stored with the new profile when only policy fields changed', async () => {
    const registry = await registryOf(profile('web'));
    const connecting = registry.getOrCreate('web');
    await clientsReach(1);

    registry.applyConfig(configOf(profile('web', { role: 'viewer', approvalPolicy: 'ask-all' })));
    clients[0]!.ready();

    const conn = await connecting;
    expect(registry.get('web')).toBe(conn);
    expect(conn.profile).toBe(registry.getProfile('web'));
    expect(conn.profile.role).toBe('viewer');
    expect(conn.profile.approvalPolicy).toBe('ask-all');
  });

  it('is discarded and closed when a connection field changed', async () => {
    const registry = await registryOf(profile('web'));
    const connecting = registry.getOrCreate('web');
    await clientsReach(1);

    registry.applyConfig(configOf(profile('web', { user: 'other' })));
    clients[0]!.ready();

    await expect(connecting).rejects.toThrow(RELOADED);
    expect(registry.get('web')).toBeUndefined();
    expect(clients[0]!.ended).toBe(true);
  });

  it('is discarded and closed when its profile was removed', async () => {
    const registry = await registryOf(profile('web'), profile('db'));
    const connecting = registry.getOrCreate('web');
    await clientsReach(1);

    registry.applyConfig(configOf(profile('db')));
    clients[0]!.ready();

    await expect(connecting).rejects.toThrow(RELOADED);
    expect(registry.liveConnections()).toEqual([]);
    expect(clients[0]!.ended).toBe(true);
  });

  it('is discarded when the bastion it runs through is closing', async () => {
    const registry = await registryOf(profile('jump'), profile('inner', { via: 'jump' }));
    const connecting = registry.getOrCreate('inner');
    await clientsReach(1);
    clients[0]!.ready();
    // The bastion is up and stored; the dependent's own handshake is now in flight.
    await clientsReach(2);
    const jump = registry.get('jump');
    expect(jump).toBeDefined();

    // The dependent's own fields are unchanged; it is the bastion that moves.
    const { toClose } = registry.applyConfig(
      configOf(profile('jump', { host: 'moved.example.test' }), profile('inner', { via: 'jump' })),
    );
    expect(toClose.map((c) => c.profile)).toEqual(['jump']);
    clients[1]!.ready();

    await expect(connecting).rejects.toThrow(RELOADED);
    expect(registry.get('inner')).toBeUndefined();
    expect(clients[1]!.ended).toBe(true);
  });

  it('is discarded when its profile was removed and added back by a later reload', async () => {
    const registry = await registryOf(profile('web'), profile('db'));
    const connecting = registry.getOrCreate('web');
    await clientsReach(1);

    registry.applyConfig(configOf(profile('db')));
    registry.applyConfig(configOf(profile('web'), profile('db')));
    clients[0]!.ready();

    await expect(connecting).rejects.toThrow(RELOADED);
    expect(registry.get('web')).toBeUndefined();
  });
});
