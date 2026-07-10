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

afterAll(async () => {
  await conn?.close();
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()))('Concurrent sessions', () => {
  it('opens 3 interactive sessions on the same connection', async () => {
    await conn.openSession({ name: 'conc-1', type: 'interactive' });
    await conn.openSession({ name: 'conc-2', type: 'interactive' });
    await conn.openSession({ name: 'conc-3', type: 'interactive' });
    const sessions = conn.listSessions();
    expect(sessions.length).toBe(3);
    expect(sessions.every((s) => s.status === 'active')).toBe(true);
    await conn.closeSession('conc-1');
    await conn.closeSession('conc-2');
    await conn.closeSession('conc-3');
  });

  it('parallel commands keep independent CWD', async () => {
    const s1 = await conn.openSession({ name: 'cwd-1', type: 'interactive' });
    const s2 = await conn.openSession({ name: 'cwd-2', type: 'interactive' });
    await s1.run('cd /tmp');
    await s2.run('cd /etc');
    const [r1, r2] = await Promise.all([s1.run('pwd'), s2.run('pwd')]);
    expect(r1.stdout.trim()).toBe('/tmp');
    expect(r2.stdout.trim()).toBe('/etc');
    await conn.closeSession('cwd-1');
    await conn.closeSession('cwd-2');
  }, 15000);

  it('4th session exceeds sessionMaxPerConnection', async () => {
    const conn5 = await createConnection('admin');
    (conn5 as any).profile = { ...(conn5 as any).profile, sessionMaxPerConnection: 2 };
    await conn5.openSession({ name: 'max-1', type: 'interactive' });
    await conn5.openSession({ name: 'max-2', type: 'interactive' });
    await expect(conn5.openSession({ name: 'max-3', type: 'interactive' })).rejects.toThrow(/limit/i);
    await conn5.close();
  });

  it('closing 1 of 3 sessions leaves others active', async () => {
    await conn.openSession({ name: 'rem-1', type: 'interactive' });
    await conn.openSession({ name: 'rem-2', type: 'interactive' });
    await conn.openSession({ name: 'rem-3', type: 'interactive' });
    await conn.closeSession('rem-2');
    const sessions = conn.listSessions();
    expect(sessions.length).toBe(2);
    expect(sessions.find((s) => s.name === 'rem-1')?.status).toBe('active');
    expect(sessions.find((s) => s.name === 'rem-3')?.status).toBe('active');
    await conn.closeSession('rem-1');
    await conn.closeSession('rem-3');
  });
});
