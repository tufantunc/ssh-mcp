import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { SftpClient } from '../../src/ssh/sftp.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';
import type { Profile } from '../../src/types.js';
import type { BackgroundSession } from '../../src/ssh/session.js';

/**
 * The session protocol against hosts that are not the standard test image.
 *
 * Every other integration target is the same linuxserver container: Debian
 * userland, bash, OpenSSH. The protocol talks to whatever shell the host runs
 * and negotiates with whatever sshd answers, so "works everywhere" rested on a
 * single data point. Two axes are covered here:
 *
 *   alpine    Alpine + OpenSSH, busybox `ash` login shell — a different SHELL.
 *             `bind` and `set -o history` do not exist; the prompt is followed
 *             by a cursor-position query.
 *   dropbear  Alpine + Dropbear — a different SSHD. Supports a much narrower
 *             algorithm set, which is the only real test of FROZEN_ALGORITHMS
 *             outside the OpenSSH family.
 */
interface Target {
  name: string;
  port: number;
  user: string;
  password: string;
}

const TARGETS: Target[] = [
  { name: 'alpine', port: 2226, user: 'alpineuser', password: 'alpinepass' },
  { name: 'dropbear', port: 2227, user: 'dropuser', password: 'droppass' },
];

function profileFor(t: Target): Profile {
  return {
    name: t.name,
    host: SSH_HOST,
    port: t.port,
    user: t.user,
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
}

const availability = new Map<string, boolean>();
for (const t of TARGETS) {
  const up = await isSshServerUp(SSH_HOST, t.port);
  // These targets are the reason the ANSI prompt bug and the Dropbear channel
  // flakiness were found at all. Skipping them silently in CI would leave a
  // green build that never exercised either.
  assertAvailable(up, `${t.name} (${SSH_HOST}:${t.port})`);
  availability.set(t.name, up);
}

for (const target of TARGETS) {
  const up = availability.get(target.name)!;
  let conn: SSHConnection;
  let savedEnv: NodeJS.ProcessEnv;

  describe.skipIf(!up)(`Host compatibility — ${target.name}`, () => {
    beforeAll(async () => {
      savedEnv = { ...process.env };
      process.env[`SSH_MCP_${target.name.toUpperCase()}_PASSWORD`] = target.password;
      const profile = profileFor(target);
      conn = new SSHConnection(profile, await resolveCredentials(profile), new Map(), 'insecure');
      // Reaching 'ready' at all means FROZEN_ALGORITHMS negotiated with this
      // server — the assertion is the connection itself.
      await conn.ensureConnected();
    }, 30000);

    afterAll(async () => {
      await conn?.close();
      if (savedEnv) process.env = savedEnv;
    });

    it('negotiates the frozen algorithm set and runs a command', async () => {
      expect(conn.isConnected()).toBe(true);
      const result = await conn.exec('id -un');
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe(target.user);
    });

    it('reports a non-zero exit code', async () => {
      const result = await conn.exec('sh -c "exit 5"');
      expect(result.exitCode).toBe(5);
    });

    it('keeps CWD across commands in an interactive session', async () => {
      const session = await conn.openSession({ name: `${target.name}-cwd`, type: 'interactive' });

      await session.run('cd /tmp');
      const pwd = await session.run('pwd');
      expect(pwd.stdout.trim()).toBe('/tmp');
      // The trailer carries $PWD; this shell has to expand it the same way.
      expect(pwd.cwd).toBe('/tmp');

      await conn.closeSession(`${target.name}-cwd`);
    }, 20000);

    it('keeps environment across commands in an interactive session', async () => {
      const session = await conn.openSession({ name: `${target.name}-env`, type: 'interactive' });

      await session.run('COMPAT_VAR=persisted; export COMPAT_VAR');
      const echoed = await session.run('echo $COMPAT_VAR');
      expect(echoed.stdout.trim()).toBe('persisted');

      await conn.closeSession(`${target.name}-env`);
    }, 20000);

    // Priming writes `bind ...` and `set +o history`, neither of which exists
    // in ash. Both are redirected; if that regressed, the shell's "not found"
    // complaints would surface as command output.
    it('does not leak shell-priming errors into command output', async () => {
      const session = await conn.openSession({ name: `${target.name}-clean`, type: 'interactive' });

      const result = await session.run('echo clean-output');
      expect(result.stdout.trim()).toBe('clean-output');
      expect(result.stdout).not.toMatch(/not found|bind|history/i);

      await conn.closeSession(`${target.name}-clean`);
    }, 20000);

    it('reports the exit code of a failing command in a session', async () => {
      const session = await conn.openSession({ name: `${target.name}-exit`, type: 'interactive' });

      expect((await session.run('true')).exitCode).toBe(0);
      expect((await session.run('sh -c "exit 9"')).exitCode).toBe(9);

      await conn.closeSession(`${target.name}-exit`);
    }, 20000);

    it('keeps multi-line output intact', async () => {
      const session = await conn.openSession({ name: `${target.name}-multi`, type: 'interactive' });

      const result = await session.run("printf 'one\\ntwo\\nthree\\n'");
      expect(result.stdout.split('\n').map((l) => l.trim()).filter(Boolean))
        .toEqual(['one', 'two', 'three']);

      await conn.closeSession(`${target.name}-multi`);
    }, 20000);

    // Regression: prompt detection tested the raw buffer, but busybox ash
    // follows its prompt with a cursor-position query (ESC[6n), so the match
    // never succeeded and every open waited out the 3s priming ceiling.
    it('opens an interactive session without waiting out the priming ceiling', async () => {
      const started = Date.now();
      await conn.openSession({ name: `${target.name}-fast`, type: 'interactive' });
      expect(Date.now() - started).toBeLessThan(2000);
      await conn.closeSession(`${target.name}-fast`);
    }, 20000);

    it('runs a background session and buffers its output', async () => {
      const session = await conn.openSession({
        name: `${target.name}-bg`,
        type: 'background',
        command: "sh -c 'for i in 1 2 3; do echo bg-line-$i; sleep 0.2; done'",
      }) as BackgroundSession;

      await new Promise((r) => setTimeout(r, 1500));
      const out = session.readOutput(10);
      expect(out).toContain('bg-line-1');
      expect(out).toContain('bg-line-3');

      await conn.closeSession(`${target.name}-bg`).catch(() => {});
    }, 20000);

    it('transfers a file over SFTP', async () => {
      // Dropbear ships no SFTP subsystem of its own; the image supplies
      // openssh-sftp-server. If that ever stopped being wired up, the SFTP
      // tools would be silently unavailable on this whole class of host.
      const sftp = new SftpClient(conn);
      const remotePath = `/tmp/compat-${target.name}.txt`;
      const content = `written to ${target.name}`;

      await sftp.upload({ remotePath, content });
      const downloaded = await sftp.download({ remotePath });
      expect(downloaded.toString()).toBe(content);

      await conn.exec(`rm -f ${remotePath}`);
    }, 20000);
  });
}
