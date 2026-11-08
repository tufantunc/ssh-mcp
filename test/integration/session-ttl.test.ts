import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';
import type { BackgroundSession } from '../../src/ssh/session.js';
import { treeSize, killMarkers } from './process-table.js';

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
      expect(await treeSize(conn, marker), 'the reaped command outlived its own reaping').toBe(0);
      expect(conn.getSession('reap-bg')).toBeUndefined();
    } finally {
      await killMarkers(conn, [marker]);
    }
  }, 30000);

  it('active session prevents connection reap', async () => {
    await conn.openSession({ name: 'keep-alive', type: 'interactive' });
    expect(conn.toInfo().sessionCount).toBeGreaterThan(0);
    expect(conn.isConnected()).toBe(true);
    await conn.closeSession('keep-alive');
  });

  it('a polled session survives past its idle TTL, an unpolled one does not', async () => {
    // The bug this pins: a background command whose output goes to a file emits
    // nothing on the channel, so lastActivity froze at creation and the reaper
    // closed the session under a caller that was reading it every second. Both
    // sessions here are silent; the only difference is that one is read.
    const ttl = 1_000;
    await conn.openSession({ name: 'polled', type: 'background', command: 'exec sleep 5', ttlMs: ttl });
    await conn.openSession({ name: 'ignored', type: 'background', command: 'exec sleep 5', ttlMs: ttl });

    const started = Date.now();
    while (Date.now() - started < ttl * 3) {
      (conn.getSession('polled') as BackgroundSession | undefined)?.readOutput(5);
      await new Promise((r) => setTimeout(r, 250));
    }

    expect(conn.getSession('polled')?.isExpired()).toBe(false);
    expect(conn.getSession('ignored')?.isExpired()).toBe(true);

    await conn.closeSession('polled').catch(() => {});
    await conn.closeSession('ignored').catch(() => {});
  }, 30000);
});
