import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm, readFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';
import { PORTS, profiles } from './fixtures.js';
import type { Profile } from '../../src/types.js';

const run = promisify(execFile);

// Ask compose for the container rather than hard-coding a name: the project
// prefix comes from the checkout directory, which is not the same everywhere
// the suite runs.
async function adminContainerId(): Promise<string> {
  const { stdout } = await run('docker', ['compose', 'ps', '-q', 'ssh-admin']);
  const id = stdout.trim().split('\n')[0];
  if (!id) throw new Error('ssh-admin container not found via docker compose ps');
  return id;
}

/**
 * Two capabilities that shipped without a test behind them, both of them the
 * answer to a reported problem:
 *
 *   tty         #31, "the input device is not a TTY" — a command that needs a
 *               terminal failed with no way to ask for one.
 *   passphrase  #25, an encrypted private key could not be used at all.
 *
 * Both are configuration paths that fail at connect time on a real server, so
 * nothing short of a real server proves they work.
 */
const up = await isSshServerUp(SSH_HOST, PORTS.admin);
assertAvailable(up, `admin (${SSH_HOST}:${PORTS.admin})`);

describe.skipIf(!up)('PTY allocation', () => {
  let conn: SSHConnection;
  let savedEnv: NodeJS.ProcessEnv;

  beforeAll(async () => {
    savedEnv = { ...process.env };
    process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';
    conn = new SSHConnection(profiles.admin, await resolveCredentials(profiles.admin), new Map(), 'insecure');
    await conn.ensureConnected();
  }, 30000);

  afterAll(async () => {
    await conn?.close();
    if (savedEnv) process.env = savedEnv;
  });

  it('reports no terminal without a PTY', async () => {
    const result = await conn.exec('tty');
    expect(result.stdout + result.stderr).toMatch(/not a tty/i);
  });

  it('allocates one when asked, so terminal-only commands work', async () => {
    const result = await conn.exec('tty', { tty: true });
    // A real terminal device rather than the "not a tty" complaint.
    expect(result.stdout).toMatch(/\/dev\/(pts|tty)/);
  });
});

describe.skipIf(!up)('encrypted private key', () => {
  let dir: string;
  let conn: SSHConnection | undefined;
  let savedEnv: NodeJS.ProcessEnv;
  const PASSPHRASE = 'test-passphrase-2026';

  beforeAll(async () => {
    savedEnv = { ...process.env };
    dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-passphrase-'));
    const keyPath = join(dir, 'id_ed25519');

    // An encrypted key: the whole point is that reading it is not enough.
    await run('ssh-keygen', ['-t', 'ed25519', '-N', PASSPHRASE, '-f', keyPath, '-C', 'ssh-mcp-test', '-q']);
    const pub = (await readFile(`${keyPath}.pub`, 'utf8')).trim();

    // The admin account's home is /config in this image, and sshd refuses a
    // key file it does not own.
    await run('docker', [
      'exec', await adminContainerId(), 'sh', '-c',
      `mkdir -p /config/.ssh && echo '${pub}' >> /config/.ssh/authorized_keys ` +
      `&& chown -R admin /config/.ssh && chmod 700 /config/.ssh ` +
      `&& chmod 600 /config/.ssh/authorized_keys`,
    ]);

    process.env.SSH_MCP_ADMIN_KEY = keyPath;
    process.env.SSH_MCP_ADMIN_PASSPHRASE = PASSPHRASE;
    delete process.env.SSH_MCP_ADMIN_PASSWORD;
  }, 60000);

  afterAll(async () => {
    await conn?.close();
    if (dir) await rm(dir, { recursive: true, force: true });
    if (savedEnv) process.env = savedEnv;
  });

  it('authenticates with the passphrase supplied out of band', async () => {
    const profile: Profile = { ...profiles.admin, auth: 'key' };
    const creds = await resolveCredentials(profile);

    expect(creds.privateKey).toBeTruthy();
    expect(creds.passphrase).toBe(PASSPHRASE);

    conn = new SSHConnection(profile, creds, new Map(), 'insecure');
    await conn.ensureConnected();

    const result = await conn.exec('id -un');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('admin');
  }, 30000);

  it('fails without the passphrase rather than connecting anyway', async () => {
    const profile: Profile = { ...profiles.admin, auth: 'key' };
    delete process.env.SSH_MCP_ADMIN_PASSPHRASE;
    delete process.env.SSH_MCP_PASSPHRASE;

    const creds = await resolveCredentials(profile);
    expect(creds.passphrase).toBeUndefined();

    const bare = new SSHConnection(profile, creds, new Map(), 'insecure');
    await expect(bare.ensureConnected()).rejects.toThrow();
    await bare.close().catch(() => {});

    process.env.SSH_MCP_ADMIN_PASSPHRASE = PASSPHRASE;
  }, 30000);
});
