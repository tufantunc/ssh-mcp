import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import type { Profile } from '../../src/types.js';
import type { HostKeyMode } from '../../src/ssh/host-key.js';
import { sshAvailable, SSH_HOST, SSH_PORT } from './helpers.js';

const knownHosts = new Map<string, string>();

const testProfile: Profile = {
  name: 'test',
  host: SSH_HOST,
  port: SSH_PORT,
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
let savedEnv: NodeJS.ProcessEnv;
const SSH_AVAILABLE = sshAvailable();

beforeAll(async () => {
  if (!(await SSH_AVAILABLE)) return;
  savedEnv = { ...process.env };
  process.env.SSH_MCP_TEST_PASSWORD = 'secret';
  const creds = await resolveCredentials(testProfile);
  conn = new SSHConnection(testProfile, creds, knownHosts, 'insecure' as HostKeyMode);
  await conn.ensureConnected();
});

afterAll(async () => {
  await conn?.close();
  if (savedEnv) process.env = savedEnv;
});

describe.skipIf(await SSH_AVAILABLE === false)('SSHConnection exec', () => {
  it('executes a simple command', async () => {
    const result = await conn.exec('echo hello');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('hello');
  });

  it('captures stderr', async () => {
    const result = await conn.exec('echo error >&2');
    expect(result.exitCode).toBe(0);
    expect(result.stderr.trim()).toBe('error');
  });

  it('returns non-zero exit code', async () => {
    const result = await conn.exec('exit 42');
    expect(result.exitCode).toBe(42);
  });

  it('handles commands with special characters', async () => {
    const result = await conn.exec("echo 'hello world!@#$%'");
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('hello world');
  });

  it('handles piped commands', async () => {
    const result = await conn.exec("printf 'a\\nb\\nc\\n' | grep b");
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('b');
  });

  it('records duration', async () => {
    const result = await conn.exec('sleep 0.5');
    expect(result.durationMs).toBeGreaterThanOrEqual(400);
    expect(result.durationMs).toBeLessThan(5000);
  });

  it('includes profile name in result', async () => {
    const result = await conn.exec('whoami');
    expect(result.profile).toBe('test');
  });
});

describe.skipIf(await SSH_AVAILABLE === false)('SSHConnection connection lifecycle', () => {
  it('reports connected status', () => {
    expect(conn.isConnected()).toBe(true);
  });

  it('reports connection info', () => {
    const info = conn.toInfo();
    expect(info.profile).toBe('test');
    expect(info.host).toBe(SSH_HOST);
    expect(info.port).toBe(SSH_PORT);
    expect(info.status).toBe('connected');
  });

  it('reconnects after disconnection', async () => {
    const conn2 = new SSHConnection(
      testProfile,
      await resolveCredentials(testProfile),
      knownHosts,
      'insecure' as HostKeyMode,
    );
    await conn2.ensureConnected();
    expect(conn2.isConnected()).toBe(true);

    await conn2.close();
    expect(conn2.isConnected()).toBe(false);

    await new Promise((r) => setTimeout(r, 500));
    await conn2.ensureConnected();
    expect(conn2.isConnected()).toBe(true);
    await conn2.close();
  });
});
