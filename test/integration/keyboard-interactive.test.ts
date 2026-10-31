import { describe, it, expect, afterEach } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';
import type { Profile, KeyboardInteractiveMode } from '../../src/types.js';
import type { HostKeyMode } from '../../src/ssh/host-key.js';

/**
 * `keyboardInteractive` against a real OpenSSH that takes passwords only through
 * keyboard-interactive (docker/kbdint-sshd: `PasswordAuthentication no`, PAM asks
 * "Password: "), which is how a hardened VMware ESXi behaves. The unit tests in
 * test/unit/ssh/two-step-login.test.ts cover the same modes against an in-process
 * ssh2 server; this is the check that a real sshd and a real PAM prompt agree.
 */
const PORT = 2228;
const USER = 'kbduser';
const PASSWORD = 'kbdpass';

const up = await isSshServerUp(SSH_HOST, PORT);
assertAvailable(up, `kbdint (${SSH_HOST}:${PORT})`);

function profileFor(mode: KeyboardInteractiveMode | undefined): Profile {
  return {
    name: 'kbdint',
    host: SSH_HOST,
    port: PORT,
    user: USER,
    auth: 'password',
    group: 'dev',
    tty: false,
    timeout: 15000,
    maxChars: 5000,
    maxOutputBytes: 1048576,
    outputTruncation: 'head',
    role: 'admin',
    readOnly: false,
    announceAgent: true,
    approvalPolicy: 'auto',
    cert: false,
    keyboardInteractive: mode,
    sessionMaxPerConnection: 5,
    sessionIdleTimeoutMs: 60000,
    sessionBackgroundMaxMs: 3600000,
    commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  };
}

let conn: SSHConnection | undefined;
afterEach(async () => {
  await conn?.close().catch(() => {});
  conn = undefined;
});

const connect = (mode: KeyboardInteractiveMode | undefined, password = PASSWORD) => {
  conn = new SSHConnection(profileFor(mode), { password }, new Map(), 'insecure' as HostKeyMode);
  return conn;
};

describe.skipIf(!up)('a server that takes passwords only through keyboard-interactive', () => {
  it("refuses a correct password when keyboardInteractive is unset, 'off' or 'empty'", async () => {
    for (const mode of [undefined, 'off', 'empty'] as const) {
      await expect(connect(mode).ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
      await conn!.close().catch(() => {});
    }
  }, 60000);

  it("logs in and runs a command with keyboardInteractive = 'password'", async () => {
    const c = connect('password');
    await c.ensureConnected();
    const r = await c.exec('id -un');
    expect(r.stdout.trim()).toBe(USER);
  }, 30000);

  it("fails on a wrong password with keyboardInteractive = 'password'", async () => {
    await expect(connect('password', 'wrong').ensureConnected()).rejects.toThrow(/All configured authentication methods failed/);
  }, 60000);
});
