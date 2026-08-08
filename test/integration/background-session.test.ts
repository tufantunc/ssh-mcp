import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';
import { BackgroundSession } from '../../src/ssh/session.js';

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

describe.skipIf(!allServersUp(await checkAllServers()))('BackgroundSession', () => {
  it('opens a background session with tail -f and reports running', async () => {
    await conn.exec('echo "line1" > /tmp/bg-test.log');
    const session = await conn.openSession({ name: 'tail-test', type: 'background', command: 'tail -f /tmp/bg-test.log' }) as BackgroundSession;
    expect(session.isRunning()).toBe(true);
    await new Promise((r) => setTimeout(r, 500));
    expect(session.readOutput(10)).toContain('line1');
    await conn.closeSession('tail-test');
  }, 15000);

  it('readOutput sees newly appended lines', async () => {
    await conn.exec('echo "initial" > /tmp/bg-tail.log');
    const session = await conn.openSession({ name: 'tail-append', type: 'background', command: 'tail -f /tmp/bg-tail.log' }) as BackgroundSession;
    await new Promise((r) => setTimeout(r, 1000));
    await conn.exec('echo "appended" >> /tmp/bg-tail.log');
    await new Promise((r) => setTimeout(r, 1500));
    expect(session.readOutput(20)).toContain('appended');
    await conn.closeSession('tail-append').catch(() => {});
  }, 15000);

  it('close marks session as closed and frees channel', async () => {
    const session = await conn.openSession({ name: 'kill-test', type: 'background', command: 'sleep 300' }) as BackgroundSession;
    expect(session.isRunning()).toBe(true);
    await conn.closeSession('kill-test').catch(() => {});
    expect(conn.getSession('kill-test')).toBeUndefined();
  }, 10000);

  it('ring buffer handles overflow — last N lines returned', async () => {
    const session = await conn.openSession({ name: 'ring-test', type: 'background', command: 'for i in $(seq 1 5000); do echo "line-$i"; done' }) as BackgroundSession;
    await new Promise((r) => setTimeout(r, 3000));
    const lines = session.readOutput(10).split('\n').filter(Boolean);
    expect(lines.length).toBeLessThanOrEqual(10);
    expect(lines[lines.length - 1]).toContain('line-5000');
    await conn.closeSession('ring-test').catch(() => {});
  }, 15000);
});
