import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { Profile } from '../../../src/types.js';

/**
 * Every exec channel this server opens announces the tool as `AI_AGENT=ssh-mcp`.
 *
 * The point of the declaration is that an operator reading their own sshd logs can tell
 * an agent's session from a person's. That only works if the request is on the channel,
 * so this asserts the options object that reaches `client.exec` — delete the field in
 * `connection.ts` and both paths below fail.
 *
 * Stubbed `ssh2.Client` rather than a container: the integration form, which proves the
 * variable actually arrives in the session, lives in `test/integration/shell-compat.test.ts`
 * against a host configured with `AcceptEnv AI_AGENT`. This one is the cheap guard that
 * runs in `npm run test:unit` with no Docker.
 */

/** The options `client.exec` was called with, per call, in order. */
let execOpts: Array<Record<string, unknown> | undefined>;

/** A channel that completes immediately with exit code 0. */
function fakeStream() {
  const stream = Object.assign(new EventEmitter(), {
    stderr: new EventEmitter(),
    write: vi.fn(),
    end: vi.fn(),
    close: vi.fn(),
    signal: vi.fn(),
  });
  setTimeout(() => stream.emit('close', 0, null), 0);
  return stream;
}

const profile = {
  name: 'p', host: 'h', port: 22, user: 'u', role: 'admin', auth: 'password', group: 'dev',
  tty: false, timeout: 500, maxChars: 100, maxOutputBytes: 1000, readOnly: false,
  approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 1000,
  sessionBackgroundMaxMs: 1000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
} as unknown as Profile;

beforeEach(() => {
  execOpts = [];
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

describe('the exec channel announces the tool', () => {
  it('sends AI_AGENT=ssh-mcp when running a command', async () => {
    const conn = await connect();
    await conn.exec('id -un', { timeoutMs: 500 });
    expect(execOpts).toHaveLength(1);
    expect(execOpts[0]?.env).toEqual({ AI_AGENT: 'ssh-mcp' });
  });

  it('still sends it when the profile asks for a pty', async () => {
    // The pty branch builds on the same options object; a future edit that rebuilds it
    // for the tty case would silently drop the declaration on exactly the sessions an
    // operator is most likely to be watching.
    const conn = await connect({ tty: true } as Partial<Profile>);
    await conn.exec('id -un', { timeoutMs: 500 });
    expect(execOpts[0]?.env).toEqual({ AI_AGENT: 'ssh-mcp' });
    expect(execOpts[0]?.pty, 'the pty request must survive alongside it').toBeTruthy();
  });

  it('sends no version, only the name', async () => {
    // A version tells a host that may be hostile which build is talking to it.
    const conn = await connect();
    await conn.exec('id -un', { timeoutMs: 500 });
    const env = execOpts[0]?.env as Record<string, string>;
    expect(env.AI_AGENT).toBe('ssh-mcp');
    expect(env.AI_AGENT, 'no version suffix').not.toMatch(/@/);
  });
});
