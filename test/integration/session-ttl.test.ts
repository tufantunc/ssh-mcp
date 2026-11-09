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

  it('the reaper spares a polled session and takes an unpolled one', async () => {
    // The bug this pins: a background command whose output goes to a file emits nothing
    // on the channel, so lastActivity froze at creation and the reaper closed the
    // session under a caller that was reading it. Both sessions here are silent and both
    // are aged past their TTL; the only difference is that one is then read. Aged by
    // moving lastActivity back rather than by waiting, so the outcome is not a race
    // against the clock.
    const markers = { polled: 4931, ignored: 4932 };
    try {
      for (const [name, marker] of Object.entries(markers)) {
        await conn.openSession({ name, type: 'background', command: `exec sleep ${marker}`, ttlMs: 60_000 });
        conn.getSession(name)!.lastActivity = new Date(Date.now() - 120_000);
      }
      (conn.getSession('polled') as BackgroundSession).readOutput(5);

      await conn.reapExpiredSessions();

      expect(conn.getSession('polled'), 'the reaper closed a session that was being read').toBeDefined();
      expect(conn.getSession('ignored'), 'an unread idle session must still be reaped').toBeUndefined();
      expect(await treeSize(conn, markers.ignored), 'the reaped command outlived its reaping').toBe(0);
    } finally {
      await conn.closeSession('polled').catch(() => {});
      await killMarkers(conn, Object.values(markers));
    }
  }, 30000);
});
