import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import type { Profile } from '../../src/types.js';
import type { HostKeyMode } from '../../src/ssh/host-key.js';
import { sshAvailable, SSH_HOST, SSH_PORT } from './helpers.js';

const knownHosts = new Map<string, string>();

const testProfile: Profile = {
  name: 'admin',
  host: SSH_HOST,
  port: SSH_PORT,
  user: 'admin',
  auth: 'password',
  tty: false,
  timeout: 10000,
  maxChars: 5000,
  maxOutputBytes: 1048576,
  maxTransferBytes: 1_073_741_824,
  role: 'admin',
  readOnly: false,
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60000,
  sessionBackgroundMaxMs: 3600000,
  commandQuotaPerDay: 0,
};

let conn: SSHConnection;
let savedEnv: NodeJS.ProcessEnv;
const SSH_AVAILABLE = sshAvailable();

beforeAll(async () => {
  if (!(await SSH_AVAILABLE)) return;
  savedEnv = { ...process.env };
  process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';
  const creds = await resolveCredentials(testProfile);
  conn = new SSHConnection(testProfile, creds, knownHosts, 'insecure' as HostKeyMode);
  await conn.ensureConnected();
});

afterAll(async () => {
  await conn?.close();
  if (savedEnv) process.env = savedEnv;
});

describe.skipIf(await SSH_AVAILABLE === false)('InteractiveSession', () => {
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
    expect(info.profile).toBe('admin');

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

  // Regression: close() only ends the stream, so the channel's 'close' event
  // can arrive after a session with the same name has been reopened. The
  // handler deleted by name unconditionally, evicting the *new* session — its
  // channel stayed open but was unreachable via getSession/list/close/reap.
  it('reopening a session under the same name survives the old channel closing', async () => {
    // close() only ends the stream. A background command that ignores stdin EOF
    // keeps its channel open afterwards, so the 'close' event lands seconds
    // later — after the name has been reused. That is the ordering the guard
    // exists for; an interactive shell exits immediately on EOF and never
    // exercises it.
    await conn.openSession({ name: 'reuse-name', type: 'background', command: 'sleep 3' });
    await conn.closeSession('reuse-name');

    const reopened = await conn.openSession({ name: 'reuse-name', type: 'interactive' });

    // Wait past the old command's lifetime so its channel close fires now.
    await new Promise((r) => setTimeout(r, 4000));

    expect(conn.getSession('reuse-name')).toBe(reopened);
    expect(conn.listSessions().some((s) => s.name === 'reuse-name')).toBe(true);

    const result = await reopened.run('echo still-here');
    expect(result.stdout.trim()).toBe('still-here');

    await conn.closeSession('reuse-name');
  }, 30000);

  it('reports the shell CWD rather than inferring it from the command', async () => {
    const session = await conn.openSession({ name: 'cwd-real', type: 'interactive' });

    // A relative cd: the old code recorded the literal argument ("..").
    await session.run('cd /tmp');
    const sub = await session.run('mkdir -p /tmp/nested/dir && cd /tmp/nested/dir');
    expect(sub.cwd).toBe('/tmp/nested/dir');

    const up = await session.run('cd ..');
    expect(up.cwd).toBe('/tmp/nested');

    const pwd = await session.run('pwd');
    expect(pwd.stdout.trim()).toBe('/tmp/nested');
    expect(pwd.cwd).toBe('/tmp/nested');

    await conn.closeSession('cwd-real');
  }, 20000);
});
