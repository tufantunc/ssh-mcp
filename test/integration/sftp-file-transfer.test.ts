import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createReadStream, createWriteStream } from 'node:fs';
import { chmod, mkdtemp, open, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { SSHConnection } from '../../src/ssh/connection.js';
import { SftpClient } from '../../src/ssh/sftp.js';
import { createLocalDownload } from '../../src/tools/local-path.js';
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
  await chmod(local, 0o700);

  // Positive control. The staging probe below is the only check on `.part`
  // cleanup, and a probe that silently reports "none" whether or not it looked
  // would leave that whole path unasserted — which is what the previous
  // `ls | grep -c || true` shape did.
  const canary = '/tmp/ssh-mcp-canary';
  await conn.exec(`mkdir -p ${canary} && touch ${canary}/.ssh-mcp-upload-canary.part`);
  const seen = await stagingFiles(canary);
  if (seen !== 1) throw new Error(`staging probe is not live: expected 1 canary, saw ${seen}`);
  await conn.exec(`rm -rf ${canary}`);
});

afterAll(async () => {
  try {
    await conn?.close();
  } finally {
    if (local) await rm(local, { recursive: true, force: true });
    if (savedEnv) process.env = savedEnv;
  }
});

/**
 * Staging files left behind in one remote directory, which must always be none.
 *
 * `find` rather than `ls | grep`: it exits 0 for a readable directory with no
 * matches and non-zero when it could not look, so "nothing there" and "could
 * not tell" stop being the same answer. Every caller passes its own directory,
 * so a leak is attributed to the test that caused it rather than to whichever
 * test asserts next.
 */
async function stagingFiles(dir: string): Promise<number> {
  const { stdout, exitCode } = await conn.exec(
    `find ${dir} -maxdepth 1 -name '.ssh-mcp-upload-*.part' | wc -l`,
  );
  if (exitCode !== 0) {
    throw new Error(`staging-file probe could not read ${dir} (exit ${exitCode})`);
  }
  return Number(stdout.trim());
}

/** A remote directory of this test's own, so /tmp is never shared state. */
async function remoteDir(name: string): Promise<string> {
  const dir = `/tmp/ssh-mcp-t-${name}`;
  await conn.exec(`rm -rf ${dir} && mkdir -p ${dir}`);
  return dir;
}

async function remoteMode(path: string): Promise<string> {
  const { stdout } = await conn.exec(`stat -c %a ${path}`);
  return stdout.trim();
}

describe.skipIf(await SSH_AVAILABLE === false)('streaming SFTP file transfer', () => {
  describe('uploadFile', () => {
    it('streams a local file to the remote side', async () => {
      const dir = await remoteDir('uf-basic');
      const source = join(local, 'payload.bin');
      const body = Buffer.alloc(64 * 1024, 0xab);
      await writeFile(source, body);
      const remotePath = `${dir}/payload.bin`;

      const bytes = await sftp.uploadFile(createReadStream(source), remotePath, OPTS);

      expect(bytes).toBe(body.length);
      expect((await sftp.download({ remotePath })).equals(body)).toBe(true);
      expect(await stagingFiles(dir)).toBe(0);

      await conn.exec(`rm -rf ${dir}`);
    });

    it('refuses an existing remote file unless overwrite is requested', async () => {
      const dir = await remoteDir('uf-exists');
      const source = join(local, 'small.txt');
      await writeFile(source, 'new content');
      const remotePath = `${dir}/taken.txt`;
      await sftp.upload({ remotePath, content: 'already here' });

      await expect(
        sftp.uploadFile(createReadStream(source), remotePath, OPTS),
      ).rejects.toThrow(/Refusing to overwrite an existing remote file/);
      expect((await sftp.download({ remotePath })).toString()).toBe('already here');
      expect(await stagingFiles(dir)).toBe(0);

      const bytes = await sftp.uploadFile(createReadStream(source), remotePath, {
        ...OPTS,
        overwrite: true,
      });
      expect(bytes).toBe('new content'.length);
      expect((await sftp.download({ remotePath })).toString()).toBe('new content');
      // The overwrite publish takes the rename branch, which does not leave a
      // second link — asserted here rather than inherited from the next test.
      expect(await stagingFiles(dir)).toBe(0);

      await conn.exec(`rm -rf ${dir}`);
    });

    it('leaves no partial file and no staging file when the cap is exceeded', async () => {
      const dir = await remoteDir('uf-capped');
      const source = join(local, 'oversized.bin');
      await writeFile(source, Buffer.alloc(32 * 1024, 7));
      const remotePath = `${dir}/capped.bin`;

      await expect(
        sftp.uploadFile(createReadStream(source), remotePath, { ...OPTS, maxBytes: 1024 }),
      ).rejects.toThrow(/exceeds the 1024 byte transfer limit/);

      const { stdout } = await conn.exec(`test -e ${remotePath} && echo present || echo absent`);
      expect(stdout.trim()).toBe('absent');
      expect(await stagingFiles(dir)).toBe(0);

      await conn.exec(`rm -rf ${dir}`);
    });

    it('reports the byte count it actually wrote', async () => {
      const dir = await remoteDir('uf-count');
      const source = join(local, 'sized.bin');
      await writeFile(source, Buffer.alloc(4096, 1));
      const remotePath = `${dir}/sized.bin`;

      const bytes = await sftp.uploadFile(createReadStream(source), remotePath, OPTS);
      const { stdout } = await conn.exec(`wc -c < ${remotePath}`);
      expect(bytes).toBe(4096);
      expect(Number(stdout.trim())).toBe(4096);

      await conn.exec(`rm -rf ${dir}`);
    });

    // The second stat is the whole reason the existence check runs twice, and
    // nothing exercised the window it guards.
    it('refuses to publish over a file that appeared during the transfer', async () => {
      const dir = await remoteDir('uf-race');
      const remotePath = `${dir}/racy.txt`;
      let squatted = false;
      const slow = Readable.from((async function* () {
        for (let i = 0; i < 4; i++) {
          await new Promise((resolve) => setTimeout(resolve, 80));
          if (i === 1 && !squatted) {
            squatted = true;
            await conn.exec(`printf squatter > ${remotePath}`);
          }
          yield Buffer.alloc(256, 5);
        }
      })());

      await expect(sftp.uploadFile(slow, remotePath, OPTS)).rejects.toThrow(
        /Refusing to overwrite a remote file created during transfer/,
      );
      expect((await sftp.download({ remotePath })).toString()).toBe('squatter');
      expect(await stagingFiles(dir)).toBe(0);

      await conn.exec(`rm -rf ${dir}`);
    }, 15000);

    // A publish the server refuses is not ambiguous, and must not be reported
    // as "the destination now exists; it may already hold this upload" — that
    // message exists only for a bound that expired with the request in flight.
    // A directory target refuses definitively while `exists()` still says yes,
    // which is exactly the shape that would trip a too-broad check.
    it('keeps a definite publish failure distinct from an unconfirmed one', async () => {
      const dir = await remoteDir('uf-definite');
      const target = `${dir}/a-directory`;
      await conn.exec(`mkdir -p ${target}`);
      const source = join(local, 'definite.txt');
      await writeFile(source, 'payload');

      const message = await sftp
        .uploadFile(createReadStream(source), target, { ...OPTS, overwrite: true })
        .then(() => '')
        .catch((err: Error) => err.message);

      expect(message).not.toMatch(/may already hold this upload/);
      expect(message).not.toMatch(/did not confirm/);
      expect(message).toBeTruthy();
      expect(await stagingFiles(dir)).toBe(0);

      await conn.exec(`rm -rf ${dir}`);
    });

    // upload()'s mode contract is pinned by three tests; this one's was not, so
    // the deliberate divergence could be "harmonised" away unnoticed.
    it('publishes 0600 by default and honours an explicit mode', async () => {
      const dir = await remoteDir('uf-mode');
      const source = join(local, 'moded.txt');
      await writeFile(source, 'mode test');

      await sftp.uploadFile(createReadStream(source), `${dir}/default.txt`, OPTS);
      expect(await remoteMode(`${dir}/default.txt`)).toBe('600');

      await sftp.uploadFile(createReadStream(source), `${dir}/explicit.txt`, {
        ...OPTS,
        mode: 0o640,
      });
      expect(await remoteMode(`${dir}/explicit.txt`)).toBe('640');

      // `||`, matching upload(): 0 is never what a caller means, and honouring
      // it would publish a file its own owner cannot read.
      await sftp.uploadFile(createReadStream(source), `${dir}/zero.txt`, { ...OPTS, mode: 0 });
      expect(await remoteMode(`${dir}/zero.txt`)).toBe('600');

      await conn.exec(`rm -rf ${dir}`);
    });

    // Publishing by rename replaces the inode, so without carrying the mode
    // across, overwriting a 0644 service config silently makes it unreadable to
    // everyone but the SSH user.
    it('preserves the destination mode when overwriting without an explicit mode', async () => {
      const dir = await remoteDir('uf-inherit');
      const remotePath = `${dir}/service.conf`;
      await conn.exec(`printf old > ${remotePath} && chmod 644 ${remotePath}`);
      const source = join(local, 'newconf.txt');
      await writeFile(source, 'new');

      await sftp.uploadFile(createReadStream(source), remotePath, { ...OPTS, overwrite: true });

      expect(await remoteMode(remotePath)).toBe('644');
      expect((await sftp.download({ remotePath })).toString()).toBe('new');

      // An explicit mode still wins over the destination's.
      await sftp.uploadFile(createReadStream(source), remotePath, {
        ...OPTS,
        overwrite: true,
        mode: 0o600,
      });
      expect(await remoteMode(remotePath)).toBe('600');

      await conn.exec(`rm -rf ${dir}`);
    });
  });

  describe('downloadFile', () => {
    it('streams a remote file into a local destination', async () => {
      const dir = await remoteDir('df-basic');
      const remotePath = `${dir}/body.txt`;
      const body = 'x'.repeat(50_000);
      await sftp.upload({ remotePath, content: body });
      const destination = join(local, 'downloaded.txt');

      const bytes = await sftp.downloadFile(remotePath, createWriteStream(destination), OPTS);

      expect(bytes).toBe(body.length);
      expect(await readFile(destination, 'utf8')).toBe(body);

      await conn.exec(`rm -rf ${dir}`);
    });

    it('refuses up front when the remote size already exceeds the cap', async () => {
      const dir = await remoteDir('df-big');
      const remotePath = `${dir}/big.txt`;
      await sftp.upload({ remotePath, content: 'y'.repeat(8192) });

      await expect(
        sftp.downloadFile(remotePath, createWriteStream(join(local, 'never.txt')), {
          ...OPTS,
          maxBytes: 1024,
        }),
      ).rejects.toThrow(/exceeds the 1024 byte transfer limit \(8192 bytes\)/);

      await conn.exec(`rm -rf ${dir}`);
    });

    // The doc says the stream-level cap exists because "a remote size can be
    // stale, unavailable, or a lie". procfs is the lie: it reports size 0, so
    // the up-front check passes and only the mid-stream cap can refuse.
    it('enforces the cap mid-stream when the reported size is a lie', async () => {
      const destination = join(local, 'proc.txt');

      await expect(
        sftp.downloadFile('/proc/self/status', createWriteStream(destination), {
          ...OPTS,
          maxBytes: 64,
        }),
      ).rejects.toThrow(/exceeds the 64 byte transfer limit/);

      // Reading actually stopped rather than the error arriving after the fact.
      const written = await stat(destination).then((s) => s.size).catch(() => 0);
      expect(written).toBeLessThanOrEqual(64 * 4);
    });

    // The wiring these primitives exist for: createLocalDownload hands out a
    // FileHandle, transfer() ends the stream over it, and publish() then has to
    // be able to sync that handle. With a default-constructed stream the handle
    // is closed by end(), sync() fails EBADF, and cleanup() deletes a file that
    // transferred completely — a successful download reported as a failure.
    it('completes through createLocalDownload and publishes the file', async () => {
      const dir = await remoteDir('df-publish');
      const remotePath = `${dir}/published.txt`;
      const body = 'z'.repeat(20_000);
      await sftp.upload({ remotePath, content: body });

      const download = await createLocalDownload({ transferRoot: local }, 'result.txt', false);
      try {
        const bytes = await sftp.downloadFile(remotePath, download.createStream(), OPTS);
        expect(bytes).toBe(body.length);
        await download.publish();
      } finally {
        await download.cleanup();
      }

      expect(await readFile(join(local, 'result.txt'), 'utf8')).toBe(body);

      await conn.exec(`rm -rf ${dir}`);
      await rm(join(local, 'result.txt'), { force: true });
    });

    it('leaves a raw FileHandle usable, so the caller can still sync it', async () => {
      const dir = await remoteDir('df-handle');
      const remotePath = `${dir}/handle.txt`;
      await sftp.upload({ remotePath, content: 'handle body' });
      const path = join(local, 'handle-out.txt');
      const handle = await open(path, 'w');

      const stream = handle.createWriteStream({ autoClose: false });
      try {
        await sftp.downloadFile(remotePath, stream, OPTS);
        // The assertion is that this does not throw EBADF: the transfer ended
        // the stream but did not close what it wraps.
        await handle.sync();
      } finally {
        // And the reason createLocalDownload owns the stream rather than
        // handing the job to each caller: a finished `autoClose: false` stream
        // that is never destroyed makes handle.close() hang forever, and
        // destroying it closes the handle — so sync() has to come first and
        // teardown has to come last, in that order, every time.
        stream.destroy();
        await handle.close().catch(() => {});
      }
      expect(await readFile(path, 'utf8')).toBe('handle body');

      await conn.exec(`rm -rf ${dir}`);
    });
  });

  // The pair that distinguishes an idle deadline from a wall-clock one. Under a
  // single budget for the whole transfer the first would fail; under an idle
  // deadline it must pass, and the second must still fail inside one window.
  describe('the idle deadline', () => {
    const CHUNKS = 12;
    const GAP_MS = 100;
    const IDLE_MS = 800;

    it('lets a slow but progressing transfer run past its own idle window', async () => {
      // The invariant, asserted without a clock: the transfer necessarily
      // outlives one idle window, and no single gap comes close to it. A
      // wall-clock deadline fails on the first; an idle one survives both.
      expect(CHUNKS * GAP_MS).toBeGreaterThan(IDLE_MS);
      expect(GAP_MS * 4).toBeLessThan(IDLE_MS);

      const dir = await remoteDir('idle-slow');
      const remotePath = `${dir}/slow.bin`;
      const slow = Readable.from((async function* () {
        for (let i = 0; i < CHUNKS; i++) {
          await new Promise((resolve) => setTimeout(resolve, GAP_MS));
          yield Buffer.alloc(1024, 3);
        }
      })());

      const bytes = await sftp.uploadFile(slow, remotePath, { ...OPTS, idleTimeoutMs: IDLE_MS });

      expect(bytes).toBe(CHUNKS * 1024);
      expect(Number((await conn.exec(`wc -c < ${remotePath}`)).stdout.trim())).toBe(CHUNKS * 1024);

      await conn.exec(`rm -rf ${dir}`);
    }, 20000);

    it('fails a transfer whose source stops producing, and fails promptly', async () => {
      const dir = await remoteDir('idle-stalled');
      const remotePath = `${dir}/stalled.bin`;
      // Emits one chunk, then never again and never ends.
      const stalled = new Readable({ read() {} });
      stalled.push(Buffer.alloc(512, 9));

      // 1000ms rather than the tightest value that works: removeTemporary
      // derives its own bound from this one via Math.min(_, 1000), so shrinking
      // it to make the stall fire sooner also shrinks the cleanup round-trip
      // that the staging assertion below depends on.
      const started = Date.now();
      await expect(
        sftp.uploadFile(stalled, remotePath, { ...OPTS, idleTimeoutMs: 1000 }),
      ).rejects.toThrow(/stalled: no progress for 1000ms/);
      const elapsed = Date.now() - started;

      // The message interpolates the configured value, so it would read the
      // same however long the timer was really set for. This is what pins that
      // it actually fired on time.
      expect(elapsed).toBeLessThan(6000);

      expect(await stagingFiles(dir)).toBe(0);
      const { stdout } = await conn.exec(`test -e ${remotePath} && echo present || echo absent`);
      expect(stdout.trim()).toBe('absent');

      await conn.exec(`rm -rf ${dir}`);
    }, 20000);

    it('refuses a bound that cannot do its job', async () => {
      const source = join(local, 'bounds.txt');
      await writeFile(source, 'bounds');

      await expect(
        sftp.uploadFile(createReadStream(source), '/tmp/x', { ...OPTS, idleTimeoutMs: 0 }),
      ).rejects.toThrow(/does not mean "unlimited"/);
      await expect(
        sftp.uploadFile(createReadStream(source), '/tmp/x', { ...OPTS, idleTimeoutMs: Infinity }),
      ).rejects.toThrow(/must be an integer between 1 and/);
      await expect(
        sftp.uploadFile(createReadStream(source), '/tmp/x', { ...OPTS, maxBytes: 0 }),
      ).rejects.toThrow(/byte budget must be a positive safe integer/);
    });
  });

  describe('cancellation', () => {
    it('aborts a transfer in flight and leaves nothing behind', async () => {
      const dir = await remoteDir('abort-mid');
      const remotePath = `${dir}/aborted.bin`;
      const controller = new AbortController();
      const reason = new Error('cancelled by test');
      const slow = Readable.from((async function* () {
        for (let i = 0; i < 20; i++) {
          await new Promise((resolve) => setTimeout(resolve, 60));
          if (i === 2) controller.abort(reason);
          yield Buffer.alloc(512, 4);
        }
      })());

      await expect(
        sftp.uploadFile(slow, remotePath, { ...OPTS, abortSignal: controller.signal }),
      ).rejects.toThrow(/cancelled by test/);

      expect(await stagingFiles(dir)).toBe(0);
      const { stdout } = await conn.exec(`test -e ${remotePath} && echo present || echo absent`);
      expect(stdout.trim()).toBe('absent');

      await conn.exec(`rm -rf ${dir}`);
    }, 20000);

    it('refuses an already-aborted signal without creating a staging file', async () => {
      const dir = await remoteDir('abort-pre');
      const source = join(local, 'pre.txt');
      await writeFile(source, 'pre');
      const controller = new AbortController();
      controller.abort(new Error('cancelled before start'));

      await expect(
        sftp.uploadFile(createReadStream(source), `${dir}/pre.txt`, {
          ...OPTS,
          abortSignal: controller.signal,
        }),
      ).rejects.toThrow(/cancelled before start/);

      expect(await stagingFiles(dir)).toBe(0);

      await conn.exec(`rm -rf ${dir}`);
    });
  });

  it('does not exhaust channels across the streaming methods', async () => {
    const dir = await remoteDir('channels');
    const source = join(local, 'chan.txt');
    await writeFile(source, 'channel probe');

    for (let i = 0; i < 12; i++) {
      const remotePath = `${dir}/f${i}.txt`;
      await sftp.uploadFile(createReadStream(source), remotePath, OPTS);
      await sftp.downloadFile(remotePath, createWriteStream(join(local, `chan-${i}.txt`)), OPTS);
      await sftp.list(dir, { maxEntries: 100, maxResponseBytes: 1_048_576, idleTimeoutMs: 10_000 });
    }

    const result = await conn.exec('echo channels-ok');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('channels-ok');

    await conn.exec(`rm -rf ${dir}`);
  }, 40000);
});
