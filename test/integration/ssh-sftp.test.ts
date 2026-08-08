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
  maxOutputBytes: 1048576,
  role: 'admin',
  readOnly: false,
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60000,
  sessionBackgroundMaxMs: 3600000,
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

  // exec output has always been capped; SFTP download was not, so one tool call
  // could buffer an arbitrarily large remote file, decode it to a string and
  // entropy-scan it — multi-GB RSS and a long event-loop stall for the server.
  it('refuses to download a file larger than the cap', async () => {
    const remotePath = '/tmp/ssh-mcp-big.txt';
    await conn.exec(`head -c 20000 /dev/zero | tr '\\0' 'a' > ${remotePath}`);

    await expect(sftp.download({ remotePath, maxBytes: 1024 })).rejects.toThrow(/exceeds the 1024 byte limit/);

    // Under the cap the same file downloads normally.
    const ok = await sftp.download({ remotePath, maxBytes: 100_000 });
    expect(ok.length).toBe(20000);

    await conn.exec(`rm -f ${remotePath}`);
  }, 20000);

  // Regression: withSftp used to open a channel per operation and never end() it,
  // so past ~MaxSessions (OpenSSH default 10) no further channel could be opened
  // on the connection — SFTP, exec or shell alike.
  it('does not exhaust channels across many operations', async () => {
    const remotePath = '/tmp/ssh-mcp-channel-limit.txt';

    for (let i = 0; i < 15; i++) {
      await sftp.upload({ remotePath, content: `iteration ${i}` });
      const downloaded = await sftp.download({ remotePath });
      expect(downloaded.toString()).toBe(`iteration ${i}`);
    }

    // exec shares the same channel budget — it must still work afterwards.
    const result = await conn.exec('echo channels-ok');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('channels-ok');

    await conn.exec(`rm -f ${remotePath}`);
  }, 30000);
});
