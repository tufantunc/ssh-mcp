import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import { defaultsFromArgv } from '../../../src/cli.js';
import type { AppConfig, Profile } from '../../../src/types.js';

/**
 * A connection a reload closes must never dial again.
 *
 * The registry hands the reloader its toClose list, but a tool call that resolved the
 * connection before the swap still holds it. If its link had dropped, that call's
 * `exec` used to redial with the pre-reload profile, and the redialled connection then
 * lived outside the registry, where no reload or reaper would ever see it. Retiring the
 * connection in applyConfig makes it terminal before anyone can do that.
 *
 * Stubbed `ssh2.Client`, as in exec-announce: what is counted is how many clients were
 * built, which is exactly "did it dial".
 */

let clients: EventEmitter[];

/** A channel that completes immediately with exit code 0. */
function fakeStream() {
  const stream = Object.assign(new EventEmitter(), {
    stderr: new EventEmitter(),
    write: vi.fn(), end: vi.fn(), close: vi.fn(), signal: vi.fn(),
  });
  setTimeout(() => stream.emit('close', 0, null), 0);
  return stream;
}

beforeEach(() => {
  clients = [];
  vi.resetModules();
  vi.doMock('ssh2', () => {
    class FakeClient extends EventEmitter {
      constructor() {
        super();
        clients.push(this);
      }
      connect() { setTimeout(() => this.emit('ready'), 0); return this; }
      exec(_cmd: string, _opts: unknown, cb: (err: Error | undefined, stream: unknown) => void) {
        setTimeout(() => cb(undefined, fakeStream()), 0);
      }
      end() { /* nothing to tear down */ }
    }
    return { Client: FakeClient, default: { Client: FakeClient } };
  });
});

afterEach(() => {
  vi.doUnmock('ssh2');
  vi.resetModules();
});

const profile = (overrides: Partial<Profile> = {}): Profile => ({
  name: 'web', group: 'dev', host: 'web.example.test', port: 22, user: 'deploy', auth: 'password',
  tty: false, timeout: 30_000, maxChars: 5000, maxOutputBytes: 1000, role: 'admin', readOnly: false,
  announceAgent: true, approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 10_000, sessionBackgroundMaxMs: 10_000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  ...overrides,
});

const configOf = (...profiles: Profile[]): AppConfig => ({ defaults: defaultsFromArgv({}), profiles });

const RETIRED = 'This connection was closed by a configuration reload; retry the call.';

/** A registry holding one real (stubbed-transport) connection that has connected once. */
async function held() {
  const { SSHConnection } = await import('../../../src/ssh/connection.js');
  const { ConnectionRegistry } = await import('../../../src/ssh/connection-registry.js');
  const registry = new ConnectionRegistry(configOf(profile()), 'insecure');
  const conn = new SSHConnection(profile(), { password: 'x' } as never, new Map(), 'insecure');
  (registry as any).connections.set('web', conn);
  await conn.exec('true');
  expect(clients).toHaveLength(1);
  return { registry, conn };
}

describe('a connection the reload closes', () => {
  it('does not redial after its link dropped, and builds no new client', async () => {
    const { registry, conn } = await held();
    // The link drops: the next exec would normally redial.
    clients[0]!.emit('close');
    expect(conn.isConnected()).toBe(false);

    const { toClose } = registry.applyConfig(configOf(profile({ user: 'other' })));
    expect(toClose.map((c) => c.conn)).toEqual([conn]);

    await expect(conn.exec('id -un')).rejects.toThrow(RETIRED);
    expect(clients).toHaveLength(1);
  });

  it('refuses a new command even while its link is still up, before the reloader closes it', async () => {
    const { registry, conn } = await held();
    expect(conn.isConnected()).toBe(true);

    registry.applyConfig(configOf());

    await expect(conn.exec('id -un')).rejects.toThrow(RETIRED);
    await expect(conn.ensureConnected()).rejects.toThrow(RETIRED);
    expect(clients).toHaveLength(1);
  });

  it('is not retired when the reload only swaps its profile', async () => {
    const { registry, conn } = await held();

    const { toClose } = registry.applyConfig(configOf(profile({ role: 'viewer' })));
    expect(toClose).toEqual([]);

    await expect(conn.exec('id -un')).resolves.toMatchObject({ exitCode: 0 });
  });
});
