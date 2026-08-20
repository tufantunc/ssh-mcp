import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';

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

describe.skipIf(!allServersUp(await checkAllServers()))('Session TTL and idle reaper', () => {
  it('session with short TTL expires', async () => {
    const session = await conn.openSession({ name: 'ttl-test', type: 'interactive', ttlMs: 1000 });
    expect(session.isExpired()).toBe(false);
    await new Promise((r) => setTimeout(r, 1500));
    expect(session.isExpired()).toBe(true);
    await conn.closeSession('ttl-test').catch(() => {});
  }, 10000);

  it('reapExpiredSessions removes expired sessions', async () => {
    await conn.openSession({ name: 'reap-test', type: 'interactive', ttlMs: 500 });
    await new Promise((r) => setTimeout(r, 800));
    await conn.reapExpiredSessions();
    expect(conn.getSession('reap-test')).toBeUndefined();
  }, 10000);

  it('reaping a background session waits for its command to be stopped', async () => {
    // The reaper used to fire `close()` without awaiting it. That dispatched INT and
    // returned, the session was removed so `sessionCount` hit zero in the same tick, and
    // the very next call — `reapIdleConnections`, which gates on `sessionCount` — closed
    // the connection microseconds later, discarding the TERM and KILL rungs. So a command
    // that ignores INT survived its own reaping. The trailing `; true` keeps the shell
    // alive; without it it exec-replaces itself and there is no tree to observe.
    const marker = 4917;
    try {
      await conn.openSession({
        name: 'reap-bg',
        type: 'background',
        command: `sh -c 'trap "" INT TERM; sleep ${marker}; true'`,
        ttlMs: 500,
      });
      await new Promise((r) => setTimeout(r, 800));

      await conn.reapExpiredSessions();

      // Checked immediately after the await: if the reaper did not wait for the ladder,
      // the command is still running here.
      const { stdout } = await conn.exec(`ps -ef | grep -c "[s]leep ${marker}"`, { timeoutMs: 5000 });
      expect(Number(stdout.trim()), 'the reaped command outlived its own reaping').toBe(0);
      expect(conn.getSession('reap-bg')).toBeUndefined();
    } finally {
      await conn.exec(`pkill -9 -f "sleep ${marker}" || true`, { timeoutMs: 5000 }).catch(() => {});
    }
  }, 30000);

  it('active session prevents connection reap', async () => {
    await conn.openSession({ name: 'keep-alive', type: 'interactive' });
    expect(conn.toInfo().sessionCount).toBeGreaterThan(0);
    expect(conn.isConnected()).toBe(true);
    await conn.closeSession('keep-alive');
  });
});
