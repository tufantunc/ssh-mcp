import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';
import { treeSize, killMarkers } from './process-table.js';

/**
 * `open-session` can set one session's idle timeout, within what the operator allows.
 *
 * Against a real SSH host, which is where a dropped value would show up as a session
 * the reaper took too early or not at all. Sessions are aged by moving `lastActivity`
 * back rather than by waiting, so the outcome is not a race against the clock.
 */

let status: ServerStatus;
let env: ReturnType<typeof setupEnv>;
let conn: SSHConnection;

const SHORT = 4941;
const LONG = 4942;
const OVER = 4943;

beforeAll(async () => {
  status = await checkAllServers();
  if (!allServersUp(status)) return;
  env = setupEnv();
  conn = await createConnection('admin');
});

afterAll(async () => {
  await killMarkers(conn, [SHORT, LONG, OVER]);
  await conn?.close();
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()))('per-call session TTL', () => {
  it('reaps by the per-call timeout, not the profile default', async () => {
    // The fixture profile's idle timeout is 60s. The short session is 30s idle, inside
    // the default and past its own 10s; the long one is 90s idle, past the default and
    // inside its own 120s. So each outcome is the opposite of what the default gives.
    try {
      await conn.openSession({ name: 'per-call-short', type: 'background', command: `exec sleep ${SHORT}`, ttlMs: 10_000 });
      await conn.openSession({ name: 'per-call-long', type: 'background', command: `exec sleep ${LONG}`, ttlMs: 120_000 });
      conn.getSession('per-call-short')!.lastActivity = new Date(Date.now() - 30_000);
      conn.getSession('per-call-long')!.lastActivity = new Date(Date.now() - 90_000);

      await conn.reapExpiredSessions();

      expect(conn.getSession('per-call-short'), 'a session past its own timeout was kept').toBeUndefined();
      expect(await treeSize(conn, SHORT), 'the reaped command outlived its reaping').toBe(0);
      expect(conn.getSession('per-call-long'), 'a session inside its own timeout was reaped').toBeDefined();
    } finally {
      await conn.closeSession('per-call-short').catch(() => {});
      await conn.closeSession('per-call-long').catch(() => {});
      await killMarkers(conn, [SHORT, LONG]);
    }
  }, 30000);

  it('refuses a timeout above the background cap before anything runs on the host', async () => {
    const cap = conn.profile.sessionBackgroundMaxMs;
    await expect(conn.openSession({
      name: 'per-call-over', type: 'background', command: `exec sleep ${OVER}`, ttlMs: cap + 1,
    })).rejects.toThrow(String(cap));
    expect(conn.getSession('per-call-over')).toBeUndefined();
    expect(await treeSize(conn, OVER), 'the refused command ran anyway').toBe(0);
  }, 30000);
});
