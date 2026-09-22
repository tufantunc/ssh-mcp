import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { Profile } from '../../../src/types.js';

/**
 * Every channel `SSHConnection` opens for a command announces the tool as
 * `AI_AGENT=ssh-mcp`, and none does when the profile clears `announceAgent`.
 *
 * There are three such sites — `exec()`, `openExec` (background sessions) and
 * `openShell` (interactive sessions) — and the first version of this feature
 * covered two while the README claimed all three. So the cases below are written
 * per site rather than per tool: a site is exactly the unit that can be forgotten.
 *
 * Stubbed `ssh2.Client` rather than a container. The integration form, which
 * proves the variable actually arrives in the session, lives in
 * `test/integration/shell-compat.test.ts` against a host configured with
 * `AcceptEnv AI_AGENT`; this is the cheap guard that runs with no Docker.
 */

/** What reached `client.exec`, per call, in order. */
let execOpts: Array<Record<string, unknown> | undefined>;
/** What reached `client.shell`, per call: the window options and the options object. */
let shellCalls: Array<{ window: unknown; options: Record<string, unknown> | undefined }>;

/** A channel that completes immediately with exit code 0. */
function fakeStream() {
  const stream = Object.assign(new EventEmitter(), {
    stderr: new EventEmitter(),
    write: vi.fn(), end: vi.fn(), close: vi.fn(), signal: vi.fn(),
  });
  setTimeout(() => stream.emit('close', 0, null), 0);
  return stream;
}

/**
 * A channel that behaves enough like a POSIX shell to complete the session
 * handshake: `primeShell` writes `printf '%s%s\n' 'A' 'B'` and waits to read
 * `AB` back, with a random marker it builds per session. Without this the
 * interactive cases below would time out rather than assert anything.
 */
function fakeShellStream() {
  const stream = Object.assign(new EventEmitter(), {
    stderr: new EventEmitter(),
    write: vi.fn((chunk: unknown) => {
      // Anchored on the format string, not a lazy gap: `printf '%s%s\n' 'A' 'B'`
      // has THREE quoted runs, and a loose pattern matches the format and the
      // first argument instead of the two the shell would concatenate.
      const m = /printf '%s%s\\n' '([^']+)' '([^']+)'/.exec(String(chunk));
      if (m) setTimeout(() => stream.emit('data', Buffer.from(`${m[1]}${m[2]}\n`)), 0);
      return true;
    }),
    end: vi.fn(), close: vi.fn(), signal: vi.fn(),
  });
  return stream;
}

const profile = {
  name: 'p', host: 'h', port: 22, user: 'u', role: 'admin', auth: 'password', group: 'dev',
  // Long enough that no scheduler delay can reach it. The fakes settle on the next
  // tick, so nothing here is slowed down — but `exec` arms a real timer against
  // this value, and a 500ms bound turned a loaded runner into a false failure on a
  // test with no timing semantics to verify.
  tty: false, timeout: 30_000, maxChars: 100, maxOutputBytes: 1000, readOnly: false,
  announceAgent: true,
  approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 10_000,
  sessionBackgroundMaxMs: 10_000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
} as unknown as Profile;

beforeEach(() => {
  execOpts = [];
  shellCalls = [];
  vi.resetModules();
  vi.doMock('ssh2', () => {
    class FakeClient extends EventEmitter {
      connect() { setTimeout(() => this.emit('ready'), 0); return this; }
      exec(
        _cmd: string,
        optsOrCb: Record<string, unknown> | ((err: Error | undefined, stream: unknown) => void),
        maybeCb?: (err: Error | undefined, stream: unknown) => void,
      ) {
        // ssh2 allows exec(cmd, cb) as well as exec(cmd, opts, cb); recording the
        // two-argument form as `undefined` is what makes a missing declaration visible.
        const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb!;
        execOpts.push(typeof optsOrCb === 'function' ? undefined : optsOrCb);
        setTimeout(() => cb(undefined, fakeStream()), 0);
      }
      shell(
        windowOrOpts: Record<string, unknown> | ((err: Error | undefined, stream: unknown) => void),
        optsOrCb?: Record<string, unknown> | ((err: Error | undefined, stream: unknown) => void),
        maybeCb?: (err: Error | undefined, stream: unknown) => void,
      ) {
        const cb = (typeof windowOrOpts === 'function' ? windowOrOpts
          : typeof optsOrCb === 'function' ? optsOrCb : maybeCb!) as
          (err: Error | undefined, stream: unknown) => void;
        let window = typeof windowOrOpts === 'function' ? undefined : windowOrOpts;
        let options = typeof optsOrCb === 'function' || optsOrCb === undefined ? undefined : optsOrCb;
        // Reproduces ssh2's own argument shifting (lib/client.js:1260): a window
        // object carrying `env` or `x11` IS the options object, and the window
        // request is then dropped. Without this the fake would accept a merged
        // object that the real client silently strips the pty dimensions from.
        if (window && (window.env !== undefined || window.x11 !== undefined)) {
          options = window;
          window = undefined;
        }
        shellCalls.push({ window, options });
        setTimeout(() => cb(undefined, fakeShellStream()), 0);
      }
      end() { /* nothing to tear down */ }
    }
    return { Client: FakeClient, default: { Client: FakeClient } };
  });
});

afterEach(() => {
  vi.doUnmock('ssh2');
  vi.resetModules();
});

async function connect(overrides: Partial<Profile> = {}) {
  const { SSHConnection } = await import('../../../src/ssh/connection.js');
  return new SSHConnection({ ...profile, ...overrides }, { password: 'x' } as never, new Map(), 'insecure');
}

const ANNOUNCEMENT = { AI_AGENT: 'ssh-mcp' };

describe('every channel opened for a command announces the tool', () => {
  it('exec(): the one-shot command path', async () => {
    const conn = await connect();
    await conn.exec('id -un', { timeoutMs: 30_000 });
    expect(execOpts).toHaveLength(1);
    expect(execOpts[0]?.env).toEqual(ANNOUNCEMENT);
  });

  it('exec(): still sends it when the profile asks for a pty', async () => {
    // The pty branch builds on the same options object; a future edit that rebuilds it
    // for the tty case would silently drop the declaration on exactly the sessions an
    // operator is most likely to be watching.
    const conn = await connect({ tty: true } as Partial<Profile>);
    await conn.exec('id -un', { timeoutMs: 30_000 });
    expect(execOpts[0]?.env).toEqual(ANNOUNCEMENT);
    expect(execOpts[0]?.pty, 'the pty request must survive alongside it').toBeTruthy();
  });

  it('openExec(): a background session', async () => {
    // Its own case because it is its own call site. Measured: with the field
    // deleted here and left in place at the other two, the entire unit suite
    // stayed green before this test existed.
    const conn = await connect();
    await conn.openSession({ name: 'bg', type: 'background', command: 'sleep 1' });
    expect(execOpts).toHaveLength(1);
    expect(execOpts[0]?.env).toEqual(ANNOUNCEMENT);
  });

  it('openShell(): an interactive session, without losing the window request', async () => {
    // The site the first version of this feature missed. The second assertion is
    // not decoration: ssh2 treats a window object carrying `env` AS the options
    // object and drops the pty dimensions, so passing the announcement the
    // obvious way would announce correctly and break every interactive session.
    const conn = await connect();
    await conn.openSession({ name: 'sh', type: 'interactive' });
    expect(shellCalls).toHaveLength(1);
    expect(shellCalls[0].options?.env).toEqual(ANNOUNCEMENT);
    expect(shellCalls[0].window, 'term/cols/rows must still be requested')
      .toEqual({ term: 'xterm-256color', cols: 200, rows: 50 });
  });
});

describe('a profile that clears announceAgent tells the host nothing', () => {
  it('sends no env on any of the three channel sites', async () => {
    const conn = await connect({ announceAgent: false } as Partial<Profile>);

    await conn.exec('id -un', { timeoutMs: 30_000 });
    await conn.openSession({ name: 'bg', type: 'background', command: 'sleep 1' });
    await conn.openSession({ name: 'sh', type: 'interactive' });

    expect(execOpts, 'exec() and openExec()').toHaveLength(2);
    for (const opts of execOpts) expect(opts?.env).toBeUndefined();
    expect(shellCalls[0].options?.env, 'openShell()').toBeUndefined();
    expect(shellCalls[0].window, 'the window request is unaffected by the opt-out')
      .toEqual({ term: 'xterm-256color', cols: 200, rows: 50 });
  });
});
