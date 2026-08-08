import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import { isSshServerUp, SSH_HOST } from './helpers.js';
import type { Profile } from '../../src/types.js';
import type { BackgroundSession } from '../../src/ssh/session.js';

/**
 * The session protocol against a different shell and sshd.
 *
 * Every other integration target is the same linuxserver image: Debian userland
 * with bash. This one is Alpine with busybox `ash`, where the shell priming
 * relies on things that simply do not exist — `bind` is a bash builtin and
 * `set -o history` is unsupported — and the sentinel trailer depends on `$?`
 * and `$PWD` behaving the same way.
 *
 * The README claims broad host support; without this, "works on every host"
 * rested on a single image.
 */
const ALPINE_PORT = 2226;

const alpineProfile: Profile = {
  name: 'alpine',
  host: SSH_HOST,
  port: ALPINE_PORT,
  user: 'alpineuser',
  auth: 'password',
  group: 'dev',
  tty: false,
  timeout: 15000,
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
let savedEnv: NodeJS.ProcessEnv;
const alpineUp = await isSshServerUp(SSH_HOST, ALPINE_PORT);

beforeAll(async () => {
  if (!alpineUp) return;
  savedEnv = { ...process.env };
  process.env.SSH_MCP_ALPINE_PASSWORD = 'alpinepass';
  const creds = await resolveCredentials(alpineProfile);
  conn = new SSHConnection(alpineProfile, creds, new Map(), 'insecure');
  await conn.ensureConnected();
}, 30000);

afterAll(async () => {
  await conn?.close();
  if (savedEnv) process.env = savedEnv;
});

describe.skipIf(!alpineUp)('Shell compatibility — Alpine / busybox ash', () => {
  it('runs a plain exec', async () => {
    const result = await conn.exec('whoami');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('alpineuser');
  });

  it('reports a non-zero exit code', async () => {
    const result = await conn.exec('sh -c "exit 5"');
    expect(result.exitCode).toBe(5);
  });

  it('keeps CWD across commands in an interactive session', async () => {
    const session = await conn.openSession({ name: 'ash-cwd', type: 'interactive' });

    await session.run('cd /tmp');
    const pwd = await session.run('pwd');
    expect(pwd.stdout.trim()).toBe('/tmp');
    // The trailer carries $PWD, which ash must expand the same way bash does.
    expect(pwd.cwd).toBe('/tmp');

    await conn.closeSession('ash-cwd');
  }, 20000);

  it('keeps environment across commands in an interactive session', async () => {
    const session = await conn.openSession({ name: 'ash-env', type: 'interactive' });

    await session.run('ASH_VAR=persisted; export ASH_VAR');
    const echoed = await session.run('echo $ASH_VAR');
    expect(echoed.stdout.trim()).toBe('persisted');

    await conn.closeSession('ash-env');
  }, 20000);

  // The priming writes `bind ...` and `set +o history`, neither of which exists
  // in ash. Both are redirected to /dev/null; if that ever regressed, the
  // shell's "not found" complaints would surface as command output.
  it('does not leak shell-priming errors into command output', async () => {
    const session = await conn.openSession({ name: 'ash-clean', type: 'interactive' });

    const result = await session.run('echo clean-output');
    expect(result.stdout.trim()).toBe('clean-output');
    expect(result.stdout).not.toMatch(/not found|bind|history/i);

    await conn.closeSession('ash-clean');
  }, 20000);

  it('reports the exit code of a failing command in a session', async () => {
    const session = await conn.openSession({ name: 'ash-exit', type: 'interactive' });

    const ok = await session.run('true');
    expect(ok.exitCode).toBe(0);

    const failed = await session.run('sh -c "exit 9"');
    expect(failed.exitCode).toBe(9);

    await conn.closeSession('ash-exit');
  }, 20000);

  it('keeps multi-line output intact', async () => {
    const session = await conn.openSession({ name: 'ash-multi', type: 'interactive' });

    const result = await session.run("printf 'one\\ntwo\\nthree\\n'");
    expect(result.stdout.split('\n').map((l) => l.trim()).filter(Boolean))
      .toEqual(['one', 'two', 'three']);

    await conn.closeSession('ash-multi');
  }, 20000);

  it('runs a background session and buffers its output', async () => {
    const session = await conn.openSession({
      name: 'ash-bg',
      type: 'background',
      command: "sh -c 'for i in 1 2 3; do echo bg-line-$i; sleep 0.2; done'",
    }) as BackgroundSession;

    await new Promise((r) => setTimeout(r, 1500));
    const out = session.readOutput(10);
    expect(out).toContain('bg-line-1');
    expect(out).toContain('bg-line-3');

    await conn.closeSession('ash-bg').catch(() => {});
  }, 20000);

  // Session open must not fall back to the priming ceiling on this shell.
  // busybox ash emits a cursor-position query after its prompt, which used to
  // defeat prompt detection and cost 3 seconds on every interactive open.
  it('opens an interactive session promptly, without waiting out the priming ceiling', async () => {
    const started = Date.now();
    await conn.openSession({ name: 'ash-fast', type: 'interactive' });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(2000);
    await conn.closeSession('ash-fast');
  }, 20000);
});
