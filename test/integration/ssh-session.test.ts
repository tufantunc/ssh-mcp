import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import type { Profile } from '../../src/types.js';
import type { HostKeyMode } from '../../src/ssh/host-key.js';

const knownHosts = new Map<string, string>();

const testProfile: Profile = {
  name: 'test',
  host: '127.0.0.1',
  port: 2222,
  user: 'test',
  auth: 'password',
  tty: false,
  timeout: 10000,
  maxChars: 5000,
  role: 'admin',
  readOnly: false,
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60000,
};

let conn: SSHConnection;

beforeAll(async () => {
  process.env.SSH_MCP_TEST_PASSWORD = 'secret';
  const creds = await resolveCredentials(testProfile);
  conn = new SSHConnection(testProfile, creds, knownHosts, 'insecure' as HostKeyMode);
  await conn.ensureConnected();
});

afterAll(async () => {
  await conn?.close();
});

describe('InteractiveSession', () => {
  it('opens and closes an interactive session', async () => {
    const session = await conn.openSession({ name: 'test-sess', type: 'interactive' });
    expect(session.name).toBe('test-sess');
    expect(session.type).toBe('interactive');
    await conn.closeSession('test-sess');
  });

  it('CWD persists between commands', async () => {
    const session = await conn.openSession({ name: 'cwd-test', type: 'interactive' });

    await session.run('cd /tmp');
    const result = await session.run('pwd');

    expect(result.stdout.trim()).toBe('/tmp');
    await conn.closeSession('cwd-test');
  }, 15000);

  it('env vars persist between commands', async () => {
    const session = await conn.openSession({ name: 'env-test', type: 'interactive' });

    await session.run('export MY_VAR=hello123');
    const result = await session.run('echo $MY_VAR');

    expect(result.stdout.trim()).toBe('hello123');
    await conn.closeSession('env-test');
  }, 15000);

  it('reports session info', async () => {
    const session = await conn.openSession({ name: 'info-test', type: 'interactive' });
    const info = session.toInfo();

    expect(info.name).toBe('info-test');
    expect(info.type).toBe('interactive');
    expect(info.profile).toBe('test');

    await conn.closeSession('info-test');
  });

  it('rejects duplicate session name', async () => {
    await conn.openSession({ name: 'dup-test', type: 'interactive' });
    await expect(
      conn.openSession({ name: 'dup-test', type: 'interactive' }),
    ).rejects.toThrow(/already exists/);
    await conn.closeSession('dup-test');
  });

  it('lists active sessions', async () => {
    await conn.openSession({ name: 'list-a', type: 'interactive' });
    await conn.openSession({ name: 'list-b', type: 'interactive' });

    const sessions = conn.listSessions();
    expect(sessions.length).toBeGreaterThanOrEqual(2);
    expect(sessions.some((s) => s.name === 'list-a')).toBe(true);
    expect(sessions.some((s) => s.name === 'list-b')).toBe(true);

    await conn.closeSession('list-a');
    await conn.closeSession('list-b');
  });
});
