import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { SftpClient } from '../../src/ssh/sftp.js';
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
  role: 'admin',
  readOnly: false,
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60000,
};

let conn: SSHConnection;
let sftp: SftpClient;
let savedEnv: NodeJS.ProcessEnv;
const SSH_AVAILABLE = sshAvailable();

beforeAll(async () => {
  if (!(await SSH_AVAILABLE)) return;
  savedEnv = { ...process.env };
  process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';
  const creds = await resolveCredentials(testProfile);
  conn = new SSHConnection(testProfile, creds, knownHosts, 'insecure' as HostKeyMode);
  await conn.ensureConnected();
  sftp = new SftpClient(conn);
});

afterAll(async () => {
  await conn?.close();
  if (savedEnv) process.env = savedEnv;
});

describe.skipIf(await SSH_AVAILABLE === false)('SFTP operations', () => {
  it('uploads and downloads a file', async () => {
    const content = 'Hello SFTP v2!';
    const remotePath = '/tmp/ssh-mcp-test-upload.txt';

    await sftp.upload({ remotePath, content });
    const downloaded = await sftp.download({ remotePath });
    expect(downloaded.toString()).toBe(content);

    await conn.exec(`rm -f ${remotePath}`);
  });

  it('stats a file', async () => {
    const remotePath = '/tmp/ssh-mcp-stat-test.txt';
    await sftp.upload({ remotePath, content: 'stat test' });

    const stats = await sftp.stat(remotePath);
    expect(stats.path).toBe(remotePath);
    expect(stats.isFile).toBe(true);
    expect(stats.size).toBeGreaterThan(0);

    await conn.exec(`rm -f ${remotePath}`);
  });

  it('lists a directory with valid entries', async () => {
    const markerPath = '/tmp/ssh-mcp-list-marker.txt';
    await sftp.upload({ remotePath: markerPath, content: 'list marker' });

    const entries = await sftp.list('/tmp');
    expect(Array.isArray(entries)).toBe(true);
    const marker = entries.find((e) => e.path.endsWith('ssh-mcp-list-marker.txt'));
    expect(marker).toBeTruthy();
    expect(marker!.isFile).toBe(true);
    expect(typeof marker!.size).toBe('number');

    await conn.exec(`rm -f ${markerPath}`);
  });

  it('rejects nonexistent path for stat', async () => {
    await expect(sftp.stat('/tmp/nonexistent-ssh-mcp-test-12345')).rejects.toThrow();
  });

  it('handles binary content', async () => {
    const remotePath = '/tmp/ssh-mcp-binary-test.bin';
    const binary = Buffer.from([0, 1, 2, 3, 255, 254]);

    await sftp.upload({ remotePath, content: binary });
    const downloaded = await sftp.download({ remotePath });
    expect(downloaded).toEqual(binary);

    await conn.exec(`rm -f ${remotePath}`);
  });
});
