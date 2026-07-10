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
  conn = await createConnection('operator');
});

afterAll(async () => { await conn?.close(); env?.restore(); });

describe.skipIf(!allServersUp(await checkAllServers()))('Sudo via stdin', () => {
  it('sudo -S whoami returns root', async () => {
    const pwd = conn.getSudoPassword();
    expect(pwd).toBeTruthy();
    const result = await conn.exec(`sudo -p "" -S sh -c 'whoami'`, { stdin: pwd + '\n', timeoutMs: 10000 });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('root');
  }, 15000);

  it('wrong sudo password fails without leaking', async () => {
    const result = await conn.exec(`sudo -p "" -S sh -c 'whoami'`, { stdin: 'wrongpassword\n', timeoutMs: 10000 });
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).not.toContain('wrongpassword');
  }, 15000);

  it('sudo -S can access root-only file', async () => {
    const pwd = conn.getSudoPassword();
    const result = await conn.exec(`sudo -p "" -S sh -c 'head -1 /etc/shadow'`, { stdin: pwd + '\n', timeoutMs: 10000 });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('root:');
  }, 15000);

  it('password not visible in remote process list', async () => {
    const pwd = conn.getSudoPassword()!;
    const p = conn.exec(`sudo -p "" -S sh -c 'sleep 2'`, { stdin: pwd + '\n', timeoutMs: 10000 });
    await new Promise((r) => setTimeout(r, 500));
    const ps = await conn.exec('ps aux');
    expect(ps.stdout).not.toContain(pwd);
    await p;
  }, 15000);
});
