import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
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
  commandQuotaPerDay: 0,
};

let conn: SSHConnection;
let sftp: SftpClient;
let local: string;
let savedEnv: NodeJS.ProcessEnv;
const SSH_AVAILABLE = sshAvailable();

const OPTS = { maxBytes: 1_048_576, idleTimeoutMs: 10_000 };

beforeAll(async () => {
  if (!(await SSH_AVAILABLE)) return;
  savedEnv = { ...process.env };
  process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';
  const creds = await resolveCredentials(testProfile);
  conn = new SSHConnection(testProfile, creds, knownHosts, 'insecure' as HostKeyMode);
  await conn.ensureConnected();
  sftp = new SftpClient(conn);
  local = await mkdtemp(join(tmpdir(), 'ssh-mcp-transfer-it-'));
});

afterAll(async () => {
  await conn?.close();
  if (local) await rm(local, { recursive: true, force: true });
  if (savedEnv) process.env = savedEnv;
});

/**
 * Staging files left behind in a remote directory, which must always be none.
 *
 * Matched on uploadFile's own naming rather than any `*.part`: /tmp is shared
 * with every other test and with whatever a previous run left there, and a
 * count that picks those up reports a leak that is not ours.
 */
async function stalePartFiles(dir: string): Promise<string> {
  const { stdout } = await conn.exec(
    `ls -a ${dir} | grep -c '^\\.ssh-mcp-upload-.*\\.part$' || true`,
  );
  return stdout.trim();
}

describe.skipIf(await SSH_AVAILABLE === false)('streaming SFTP file transfer', () => {
  describe('uploadFile', () => {
    it('streams a local file to the remote side', async () => {
      const source = join(local, 'payload.bin');
      const body = Buffer.alloc(64 * 1024, 0xab);
      await writeFile(source, body);
      const remotePath = '/tmp/ssh-mcp-uf-basic.bin';
      await conn.exec(`rm -f ${remotePath}`);

      const bytes = await sftp.uploadFile(createReadStream(source), remotePath, OPTS);

      expect(bytes).toBe(body.length);
      const back = await sftp.download({ remotePath });
      expect(back.equals(body)).toBe(true);
      expect(await stalePartFiles('/tmp')).toBe('0');

      await conn.exec(`rm -f ${remotePath}`);
    });

    it('refuses an existing remote file unless overwrite is requested', async () => {
      const source = join(local, 'small.txt');
      await writeFile(source, 'new content');
      const remotePath = '/tmp/ssh-mcp-uf-exists.txt';
      await sftp.upload({ remotePath, content: 'already here' });

      await expect(
        sftp.uploadFile(createReadStream(source), remotePath, OPTS),
      ).rejects.toThrow(/Refusing to overwrite an existing remote file/);

      // Untouched, and nothing staged alongside it.
      const back = await sftp.download({ remotePath });
      expect(back.toString()).toBe('already here');
      expect(await stalePartFiles('/tmp')).toBe('0');

      const bytes = await sftp.uploadFile(createReadStream(source), remotePath, {
        ...OPTS,
        overwrite: true,
      });
      expect(bytes).toBe('new content'.length);
      expect((await sftp.download({ remotePath })).toString()).toBe('new content');

      await conn.exec(`rm -f ${remotePath}`);
    });

    // The point of staging: a transfer that dies must leave neither a
    // half-written destination nor a `.part` behind.
    it('leaves no partial file and no .part when the cap is exceeded', async () => {
      const source = join(local, 'oversized.bin');
      await writeFile(source, Buffer.alloc(32 * 1024, 7));
      const remotePath = '/tmp/ssh-mcp-uf-capped.bin';
      await conn.exec(`rm -f ${remotePath}`);

      await expect(
        sftp.uploadFile(createReadStream(source), remotePath, { ...OPTS, maxBytes: 1024 }),
      ).rejects.toThrow(/exceeds the 1024 byte transfer limit/);

      const { stdout } = await conn.exec(`test -e ${remotePath} && echo present || echo absent`);
      expect(stdout.trim()).toBe('absent');
      expect(await stalePartFiles('/tmp')).toBe('0');
    });

    it('reports the byte count it actually wrote', async () => {
      const source = join(local, 'sized.bin');
      await writeFile(source, Buffer.alloc(4096, 1));
      const remotePath = '/tmp/ssh-mcp-uf-count.bin';
      await conn.exec(`rm -f ${remotePath}`);

      const bytes = await sftp.uploadFile(createReadStream(source), remotePath, OPTS);
      const { stdout } = await conn.exec(`wc -c < ${remotePath}`);
      expect(bytes).toBe(4096);
      expect(Number(stdout.trim())).toBe(4096);

      await conn.exec(`rm -f ${remotePath}`);
    });
  });

  describe('downloadFile', () => {
    it('streams a remote file into a local destination', async () => {
      const remotePath = '/tmp/ssh-mcp-df-basic.txt';
      const body = 'x'.repeat(50_000);
      await sftp.upload({ remotePath, content: body });
      const destination = join(local, 'downloaded.txt');

      const bytes = await sftp.downloadFile(remotePath, createWriteStream(destination), OPTS);

      expect(bytes).toBe(body.length);
      expect(await readFile(destination, 'utf8')).toBe(body);

      await conn.exec(`rm -f ${remotePath}`);
    });

    it('refuses up front when the remote size already exceeds the cap', async () => {
      const remotePath = '/tmp/ssh-mcp-df-big.txt';
      await sftp.upload({ remotePath, content: 'y'.repeat(8192) });
      const destination = join(local, 'never-written.txt');

      await expect(
        sftp.downloadFile(remotePath, createWriteStream(destination), { ...OPTS, maxBytes: 1024 }),
      ).rejects.toThrow(/exceeds the 1024 byte transfer limit \(8192 bytes\)/);

      await conn.exec(`rm -f ${remotePath}`);
    });
  });

  // These two are the pair that distinguishes an idle deadline from a
  // wall-clock one. Under a single budget for the whole transfer, the first
  // would fail; under an idle deadline it must pass, and the second must still
  // fail promptly.
  describe('the idle deadline', () => {
    it('lets a slow but progressing transfer run past its own idle window', async () => {
      const remotePath = '/tmp/ssh-mcp-idle-slow.bin';
      await conn.exec(`rm -f ${remotePath}`);
      const chunk = Buffer.alloc(1024, 3);
      const slow = Readable.from((async function* () {
        for (let i = 0; i < 6; i++) {
          await new Promise((resolve) => setTimeout(resolve, 120));
          yield chunk;
        }
      })());

      const started = Date.now();
      const bytes = await sftp.uploadFile(slow, remotePath, {
        ...OPTS,
        idleTimeoutMs: 400,
      });
      const elapsed = Date.now() - started;

      expect(bytes).toBe(6 * 1024);
      // The whole transfer outlived a single 400ms budget; each gap did not.
      expect(elapsed).toBeGreaterThan(400);

      await conn.exec(`rm -f ${remotePath}`);
    });

    it('fails a transfer whose source stops producing', async () => {
      const remotePath = '/tmp/ssh-mcp-idle-stalled.bin';
      await conn.exec(`rm -f ${remotePath}`);
      // Emits one chunk, then never again and never ends.
      const stalled = new Readable({ read() {} });
      stalled.push(Buffer.alloc(512, 9));

      await expect(
        sftp.uploadFile(stalled, remotePath, { ...OPTS, idleTimeoutMs: 300 }),
      ).rejects.toThrow(/stalled: no progress for 300ms/);

      expect(await stalePartFiles('/tmp')).toBe('0');
      const { stdout } = await conn.exec(`test -e ${remotePath} && echo present || echo absent`);
      expect(stdout.trim()).toBe('absent');
    });
  });
});
