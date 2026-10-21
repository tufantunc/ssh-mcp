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

/**
 * GHSA-9m75-x2ch-j4jr: `sudo -S` reads stdin only when it needs a password.
 * With NOPASSWD (or any policy that skips the prompt) the password line stays
 * in the pipe, sudo exec's the wrapper's `sh -c` with that same stdin, and a
 * stdin-reading command reads the password back. The wrapper must therefore
 * point the child shell's stdin at /dev/null.
 *
 * The NOPASSWD policy is provisioned here on the throwaway fixture container:
 * appended to /etc/sudoers, where sudo's last-match-wins rule makes it take
 * effect over the fixture's password-required line (which itself sits after
 * the @includedir, so a sudoers.d drop-in would NOT win — verified the hard
 * way). Removed again in afterAll.
 */
describe.skipIf(!allServersUp(await checkAllServers()))('Sudo without a prompt (GHSA-9m75-x2ch-j4jr)', () => {
  const NOPASSWD_LINE = 'operator ALL=(ALL) NOPASSWD:ALL';

  beforeAll(async () => {
    const pwd = conn.getSudoPassword();
    const append = await conn.exec(
      `sudo -p "" -S sh -c 'echo "${NOPASSWD_LINE}" >> /etc/sudoers'`,
      { stdin: pwd + '\n', timeoutMs: 10000 },
    );
    // Fail loudly if the fixture did not switch to NOPASSWD: green-testing the
    // prompt case here would prove nothing about the leak.
    const probe = await conn.exec('sudo -n true');
    if (append.exitCode !== 0 || probe.exitCode !== 0) {
      throw new Error(`NOPASSWD fixture could not be provisioned (append exit ${append.exitCode}, probe exit ${probe.exitCode})`);
    }
  }, 15000);

  afterAll(async () => {
    if (!conn) return;
    await conn.exec(`sudo -n sed -i '/^${NOPASSWD_LINE}$/d' /etc/sudoers`).catch(() => {});
  });

  it('a stdin-reading command cannot read the password left for sudo', async () => {
    const pwd = conn.getSudoPassword()!;
    const result = await conn.exec(
      `sudo -p "" -S sh -c 'exec 0</dev/null; head -1'`,
      { stdin: pwd + '\n', timeoutMs: 10000 },
    );
    expect(result.exitCode).toBe(0);
    // head saw EOF, not the password: nothing comes back.
    expect(result.stdout).toBe('');
    expect(result.stdout + result.stderr).not.toContain(pwd);
  }, 15000);

  it('file-reading privileged commands still work with stdin isolated', async () => {
    const result = await conn.exec(
      `sudo -p "" -S sh -c 'exec 0</dev/null; head -1 /etc/shadow'`,
      { stdin: 'nopasswd-ignores-this\n', timeoutMs: 10000 },
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('root:');
  }, 15000);

  it('elevation itself still works through the isolated wrapper', async () => {
    const result = await conn.exec(
      `sudo -p "" -S sh -c 'exec 0</dev/null; id -u'`,
      { stdin: 'nopasswd-ignores-this\n', timeoutMs: 10000 },
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('0');
  }, 15000);
});
