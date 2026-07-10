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

describe.skipIf(!allServersUp(await checkAllServers()))('Command cancellation', () => {
  it('long command times out with error', async () => {
    await expect(conn.exec('sleep 30', { timeoutMs: 2000 })).rejects.toThrow(/timed out/i);
  }, 10000);

  it('background session close marks session closed', async () => {
    await conn.openSession({ name: 'cancel-bg', type: 'background', command: 'sleep 300' });
    await conn.closeSession('cancel-bg').catch(() => {});
    expect(conn.getSession('cancel-bg')).toBeUndefined();
  }, 10000);

  it('large output is capped', async () => {
    const result = await conn.exec('yes "x" | head -n 100000', { timeoutMs: 10000 });
    expect(result.stdout.length).toBeLessThanOrEqual(2 * 1048576);
    expect(result.exitCode).toBe(0);
  }, 15000);
});
