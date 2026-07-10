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

describe.skipIf(!allServersUp(await checkAllServers()))('InteractiveSession sentinel edge cases', () => {
  it('multiline output returns all lines', async () => {
    const session = await conn.openSession({ name: 'multi', type: 'interactive' });
    const result = await session.run('seq 1 100');
    const lines = result.stdout.trim().split('\n');
    expect(lines.length).toBe(100);
    expect(lines[0]).toBe('1');
    expect(lines[99]).toBe('100');
    await conn.closeSession('multi');
  }, 15000);

  it('output containing # does not cause false sentinel match', async () => {
    const session = await conn.openSession({ name: 'hash', type: 'interactive' });
    const result = await session.run('echo "a#b#c#d"');
    expect(result.stdout.trim()).toBe('a#b#c#d');
    await conn.closeSession('hash');
  }, 15000);

  it('output containing fake sentinel text is not spoofed', async () => {
    const session = await conn.openSession({ name: 'spoof', type: 'interactive' });
    const result = await session.run('echo "SSHMCP_END_fake_marker__12345__"');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('SSHMCP_END_fake_marker');
    await conn.closeSession('spoof');
  }, 15000);

  it('ANSI escape codes are stripped from output', async () => {
    const session = await conn.openSession({ name: 'ansi', type: 'interactive' });
    const result = await session.run('echo -e "\\033[31mred text\\033[0m"');
    expect(result.stdout).not.toContain('\x1b[');
    expect(result.stdout.toLowerCase()).toContain('red text');
    await conn.closeSession('ansi');
  }, 15000);

  it('empty output returns exit code 0', async () => {
    const session = await conn.openSession({ name: 'empty', type: 'interactive' });
    const result = await session.run('true');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
    await conn.closeSession('empty');
  }, 15000);

  it('large output (5000 lines) is fully returned', async () => {
    const session = await conn.openSession({ name: 'large', type: 'interactive' });
    const result = await session.run('seq 1 5000');
    const lines = result.stdout.trim().split('\n');
    expect(lines.length).toBe(5000);
    await conn.closeSession('large');
  }, 15000);
});
