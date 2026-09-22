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
  announceAgent: true,
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60000,
  sessionBackgroundMaxMs: 3600000,
  commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
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

  const listOpts = (over: Partial<{ maxEntries: number; maxResponseBytes: number }> = {}) => ({
    maxEntries: 1000,
    maxResponseBytes: 1_048_576,
    idleTimeoutMs: 10_000,
    ...over,
  });

  it('lists a directory with valid entries', async () => {
    const dir = '/tmp/ssh-mcp-list-marker';
    const markerPath = `${dir}/marker.txt`;
    await conn.exec(`rm -rf ${dir} && mkdir -p ${dir}`);
    await sftp.upload({ remotePath: markerPath, content: 'list marker' });

    const result = await sftp.list(dir, listOpts());
    // `truncated` asserted so a cut listing fails here rather than further down
    // as a mysteriously missing marker.
    expect(result.truncated).toBe(false);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].path).toBe(markerPath);
    expect(result.entries[0].isFile).toBe(true);
    expect(typeof result.entries[0].size).toBe('number');

    await conn.exec(`rm -rf ${dir}`);
  });

  // The bound is what stops a directory with a million entries becoming a
  // million-object array in the MCP process. `truncated` has to be honest
  // without a second round-trip, which is why one entry past the limit is read.
  it('caps the entries it returns and says so', async () => {
    const dir = '/tmp/ssh-mcp-list-many';
    await conn.exec(`rm -rf ${dir} && mkdir -p ${dir} && for i in $(seq 1 12); do touch ${dir}/f$i; done`);

    const capped = await sftp.list(dir, listOpts({ maxEntries: 5 }));
    expect(capped.entries).toHaveLength(5);
    expect(capped.truncated).toBe(true);

    // Exactly 12, not 14: ssh2 removes `.` and `..` before the callback unless
    // readdir is given `{ full: true }`, and list() filters them itself. An
    // earlier version of this test asserted `>= 12`, which passed under either
    // belief and so pinned neither.
    const full = await sftp.list(dir, listOpts());
    expect(full.entries).toHaveLength(12);
    expect(full.truncated).toBe(false);

    await conn.exec(`rm -rf ${dir}`);
  });

  // Exactly at the limit is not truncation. Off by one here would either
  // report a complete listing as partial or hide a real cut.
  it('does not report truncation when the count lands exactly on the cap', async () => {
    const dir = '/tmp/ssh-mcp-list-exact';
    await conn.exec(`rm -rf ${dir} && mkdir -p ${dir} && for i in 1 2 3; do touch ${dir}/f$i; done`);

    const exact = await sftp.list(dir, listOpts({ maxEntries: 3 }));
    expect(exact.entries).toHaveLength(3);
    expect(exact.truncated).toBe(false);

    await conn.exec(`rm -rf ${dir}`);
  });

  // The budget bills filename + longname + 256 per retained entry, so the
  // admitted count is arithmetic rather than a range. Asserting an exact count
  // is what makes an accounting change fail here instead of passing quietly.
  //
  // Measured against this server: a two-character name carries a 58-byte
  // longname, so one entry costs 316. The budgets below sit inside their bands
  // (316..631 admits exactly 1; 1264..1579 admits exactly 4) rather than on an
  // edge, so a small change in the server's `ls -l` width does not flip them.
  it('truncates on the response budget, admitting exactly what fits', async () => {
    const dir = '/tmp/ssh-mcp-list-bytes';
    await conn.exec(`rm -rf ${dir} && mkdir -p ${dir} && for i in $(seq 1 10); do touch ${dir}/f$i; done`);

    const one = await sftp.list(dir, listOpts({ maxResponseBytes: 400 }));
    expect(one.entries).toHaveLength(1);
    expect(one.truncated).toBe(true);

    const several = await sftp.list(dir, listOpts({ maxResponseBytes: 1300 }));
    expect(several.entries).toHaveLength(4);
    expect(several.truncated).toBe(true);

    // A budget below the cost of a single entry admits none, and must still say
    // it truncated rather than reporting an empty directory.
    const none = await sftp.list(dir, listOpts({ maxResponseBytes: 100 }));
    expect(none.entries).toHaveLength(0);
    expect(none.truncated).toBe(true);

    await conn.exec(`rm -rf ${dir}`);
  });

  // The name is part of the bill. Charging only a flat per-entry constant is
  // what let a server with huge `longname` values retain far more than the
  // budget claimed, so a long name has to buy fewer entries.
  it('bills the entry name, so long names admit fewer entries', async () => {
    const dir = '/tmp/ssh-mcp-list-longnames';
    const long = 'n'.repeat(200);
    await conn.exec(
      `rm -rf ${dir} && mkdir -p ${dir} && cd ${dir} && ` +
      `touch ${long}1 ${long}2 ${long}3 s1 s2 s3`,
    );

    // 1300 admitted four two-character names above; here every entry costs at
    // least 200 more, so the same budget cannot admit four of the long ones.
    const budgeted = await sftp.list(dir, listOpts({ maxResponseBytes: 1300 }));
    const longAdmitted = budgeted.entries.filter((e) => e.path.includes(long)).length;
    expect(longAdmitted).toBeLessThan(4);
    expect(budgeted.truncated).toBe(true);

    await conn.exec(`rm -rf ${dir}`);
  });

  it('refuses a bound that cannot do its job', async () => {
    await expect(sftp.list('/tmp', listOpts({ maxEntries: 0 }))).rejects.toThrow(
      /maxEntries must be a positive integer/,
    );
    // 0 means "no limit" elsewhere in this codebase, so it has to be refused
    // here rather than silently clamped to an immediate failure.
    await expect(
      sftp.list('/tmp', { ...listOpts(), idleTimeoutMs: 0 }),
    ).rejects.toThrow(/does not mean "unlimited"/);
    await expect(
      sftp.list('/tmp', { ...listOpts(), idleTimeoutMs: Infinity }),
    ).rejects.toThrow(/must be an integer between 1 and/);
  });

  it('reports a nonexistent directory rather than an empty listing', async () => {
    await expect(
      sftp.list('/tmp/ssh-mcp-no-such-dir-9f3a', listOpts()),
    ).rejects.toThrow(/SFTP list error/);
  });

  // The names the accounting and the path construction are least safe with are
  // exactly the ones no fixture used.
  it('handles names with spaces, quotes, leading dots and multi-byte characters', async () => {
    const dir = '/tmp/ssh-mcp-list-odd';
    await conn.exec(
      `rm -rf ${dir} && mkdir -p ${dir} && cd ${dir} && ` +
      `touch -- 'a b' 'x'"'"'y' '..z' 'привет'`,
    );

    const result = await sftp.list(dir, listOpts());
    const names = result.entries.map((e) => e.path).sort();
    expect(names).toEqual([
      `${dir}/..z`,
      `${dir}/a b`,
      `${dir}/привет`,
      `${dir}/x'y`,
    ].sort());
    // `..z` is a real entry, not a parent reference — only exact `.` and `..`
    // are filtered.
    expect(result.truncated).toBe(false);

    await conn.exec(`rm -rf ${dir}`);
  });

  // sftp-upload reports Buffer.byteLength(content, 'utf8'), which is only the
  // right number because upload() writes Buffer.from(content) — utf8. Pin that
  // with a string whose UTF-16 length differs from its utf8 byte length; the
  // tool used to report content.length and under-reported every such upload.
  it('writes utf8 bytes, not UTF-16 code units', async () => {
    const remotePath = '/tmp/ssh-mcp-utf8-size.txt';
    const content = 'привет мир';
    expect(Buffer.byteLength(content, 'utf8')).not.toBe(content.length);

    await sftp.upload({ remotePath, content });
    const stats = await sftp.stat(remotePath);
    expect(stats.size).toBe(Buffer.byteLength(content, 'utf8'));

    await conn.exec(`rm -f ${remotePath}`);
  });

  // ─── sftp-upload's contract ──────────────────────────────────────────
  //
  // These three pin behaviour that `sftp-upload` has always had and that
  // nothing else asserts. They exist because a proposed change to the
  // streaming file tools (#186) rewrote `upload()` to stage a `.part` file and
  // publish it with rename, at mode 0600 and with `??` instead of `||` — which
  // silently changed all three for the pre-existing tool. #185 asked for the
  // text-based tools to stay unchanged. If a future port reintroduces any of
  // it, one of these fails instead of the change shipping quietly.

  it('creates a remote file 0644 by default, not owner-only', async () => {
    const remotePath = '/tmp/ssh-mcp-mode-default.txt';
    await conn.exec(`rm -f ${remotePath}`);

    await sftp.upload({ remotePath, content: 'mode test' });

    const { stdout } = await conn.exec(`stat -c %a ${remotePath}`);
    expect(stdout.trim()).toBe('644');

    await conn.exec(`rm -f ${remotePath}`);
  });

  // `mode: 0` is "no permissions", which is never what a caller means. `||`
  // treats it as unset and falls back; `??` would honour it and produce a file
  // its own owner cannot read.
  it('treats mode 0 as unset rather than writing a 0000 file', async () => {
    const remotePath = '/tmp/ssh-mcp-mode-zero.txt';
    await conn.exec(`rm -f ${remotePath}`);

    await sftp.upload({ remotePath, content: 'zero mode', mode: 0 });

    const { stdout } = await conn.exec(`stat -c %a ${remotePath}`);
    expect(stdout.trim()).toBe('644');

    await conn.exec(`rm -f ${remotePath}`);
  });

  // A direct write needs write permission on the *file*; staging a sibling
  // `.part` and renaming needs it on the *directory*. Updating a writable file
  // in a directory you cannot write is exactly the case that distinguishes
  // them — and a common shape for service configs.
  it('writes the target directly, so a read-only directory is no obstacle', async () => {
    const dir = '/tmp/ssh-mcp-ro-dir';
    const remotePath = `${dir}/existing.conf`;
    await conn.exec(
      `rm -rf ${dir} && mkdir -p ${dir} && printf old > ${remotePath} ` +
      `&& chmod 644 ${remotePath} && chmod 555 ${dir}`,
    );

    await sftp.upload({ remotePath, content: 'rewritten' });

    const downloaded = await sftp.download({ remotePath });
    expect(downloaded.toString()).toBe('rewritten');

    await conn.exec(`chmod 755 ${dir} && rm -rf ${dir}`);
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
