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
    conn.reapExpiredSessions();
    expect(conn.getSession('reap-test')).toBeUndefined();
  }, 10000);

  it('active session prevents connection reap', async () => {
    await conn.openSession({ name: 'keep-alive', type: 'interactive' });
    expect(conn.toInfo().sessionCount).toBeGreaterThan(0);
    expect(conn.isConnected()).toBe(true);
    await conn.closeSession('keep-alive');
  });
});
