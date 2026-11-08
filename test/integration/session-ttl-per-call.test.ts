import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';

/**
 * `open-session` can override the profile's idle timeout for one session.
 *
 * The manager already honoured `opts.ttlMs`; these exercise it against a real
 * SSH host, which is where a dropped value would show up as a session that
 * outlived — or died before — what the caller asked for.
 */

let status: ServerStatus;
let env: ReturnType<typeof setupEnv>;
let conn: SSHConnection;

beforeAll(async () => {
  status = await checkAllServers();
  if (!allServersUp(status)) return;
  env = setupEnv();
  conn = await createConnection('admin');
});

afterAll(async () => { await conn?.close(); env?.restore(); });

describe.skipIf(!allServersUp(await checkAllServers()))('per-call session TTL', () => {
  it('honours a short per-call TTL over a longer profile default', async () => {
    // The fixture profile's idle timeout is a minute; this asks for one second.
    const session = await conn.openSession({
      name: 'per-call-short', type: 'background', command: 'exec sleep 5', ttlMs: 1_000,
    });

    expect(session.ttlMs).toBe(1_000);
    expect(session.isExpired()).toBe(false);
    await new Promise((r) => setTimeout(r, 1_400));
    expect(session.isExpired()).toBe(true);

    await conn.closeSession('per-call-short').catch(() => {});
  }, 30000);

  it('ttlMs 0 outlives the profile default instead of expiring at once', async () => {
    const session = await conn.openSession({
      name: 'per-call-unbounded', type: 'background', command: 'exec sleep 5', ttlMs: 0,
    });

    expect(session.ttlMs).toBe(0);
    // Longer than the one-second TTL above: an unhandled 0 would read as "expire
    // immediately" here, which is the failure this test exists for.
    await new Promise((r) => setTimeout(r, 1_400));
    expect(session.isExpired()).toBe(false);

    await conn.closeSession('per-call-unbounded').catch(() => {});
  }, 30000);
});
