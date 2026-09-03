import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { SftpClient } from '../../src/ssh/sftp.js';
import type { Profile } from '../../src/types.js';
import type { BackgroundSession } from '../../src/ssh/session.js';

/**
 * Windows OpenSSH — the one host class Docker cannot provide.
 *
 * Opt-in: set SSH_MCP_WIN_HOST / _USER / _PASSWORD to run it (a UTM or Hyper-V
 * guest with `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` is
 * enough). Skipped otherwise, so the suite stays runnable without a VM.
 *
 * The README claimed Windows support without qualification. Measured against a
 * real Windows 11 host (build 26200), the support is real but partial, and this
 * file is what pins down which half:
 *
 *   works        exec tools, background sessions, SFTP, exit codes
 *   cannot work  interactive sessions — the session protocol brackets commands
 *                with `printf` and reads `$?`/`$PWD`, none of which exist in
 *                cmd.exe (the default Windows OpenSSH shell)
 */
const HOST = process.env.SSH_MCP_WIN_HOST;
const USER = process.env.SSH_MCP_WIN_USER;
const PASSWORD = process.env.SSH_MCP_WIN_PASSWORD;
const configured = Boolean(HOST && USER && PASSWORD);

const winProfile: Profile = {
  name: 'windows',
  host: HOST ?? '',
  port: Number(process.env.SSH_MCP_WIN_PORT ?? 22),
  user: USER ?? '',
  auth: 'password',
  group: 'dev',
  tty: false,
  timeout: 30000,
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

beforeAll(async () => {
  if (!configured) return;
  conn = new SSHConnection(winProfile, { password: PASSWORD }, new Map(), 'insecure');
  await conn.ensureConnected();
}, 60000);

afterAll(async () => { await conn?.close(); });

describe.skipIf(!configured)('Windows OpenSSH compatibility', () => {
  it('negotiates the frozen algorithm set', () => {
    // Reaching this point means FROZEN_ALGORITHMS negotiated with a non-Linux,
    // non-OpenSSH-on-Unix server.
    expect(conn.isConnected()).toBe(true);
  });

  it('runs commands and reports their exit codes', async () => {
    const who = await conn.exec('whoami');
    expect(who.exitCode).toBe(0);
    expect(who.stdout.toLowerCase()).toContain(USER!.toLowerCase());

    const failed = await conn.exec('cmd /c exit 3');
    expect(failed.exitCode).toBe(3);
  }, 30000);

  it('transfers files over SFTP', async () => {
    const sftp = new SftpClient(conn);
    const remotePath = `C:/Users/${USER}/ssh-mcp-compat.txt`;
    const content = 'windows sftp round-trip';

    await sftp.upload({ remotePath, content });
    expect((await sftp.download({ remotePath })).toString()).toBe(content);

    await conn.exec(`del "C:\\Users\\${USER}\\ssh-mcp-compat.txt"`);
  }, 30000);

  it('runs background sessions, which use exec rather than a shell', async () => {
    const session = await conn.openSession({
      name: 'win-bg', type: 'background', command: 'ping -n 3 127.0.0.1',
    }) as BackgroundSession;

    await new Promise((r) => setTimeout(r, 2500));
    expect(session.readOutput(20)).toContain('127.0.0.1');

    await conn.closeSession('win-bg').catch(() => {});
  }, 30000);

  // The documented limitation. cmd.exe accepts the channel and even shows a
  // ">" prompt, so this used to look like a successful open — and then every
  // command sat until the 60s timeout saying only "timed out". The handshake
  // now fails the open immediately and says why.
  it('refuses interactive sessions quickly and explains why', async () => {
    const started = Date.now();
    await expect(conn.openSession({ name: 'win-shell', type: 'interactive' }))
      .rejects.toThrow(/not supported|POSIX shell/i);

    expect(Date.now() - started).toBeLessThan(10000);
    // The failed open must not leave a session behind.
    expect(conn.getSession('win-shell')).toBeUndefined();
  }, 30000);

  it('stays usable after an interactive session was refused', async () => {
    const result = await conn.exec('whoami');
    expect(result.exitCode).toBe(0);
  }, 30000);
});
