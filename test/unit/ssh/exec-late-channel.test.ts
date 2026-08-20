import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { Profile } from '../../../src/types.js';

/**
 * A timeout can fire before the exec channel exists.
 *
 * ssh2 invokes `client.exec`'s callback when the server replies CHANNEL_SUCCESS, and
 * OpenSSH sends that *after* forking the command — and `openWithRetry` can spend three
 * attempts plus backoff before that. So "no channel yet" never meant "nothing is running
 * on the host", though a comment in `exec()` used to assert it did. The command started,
 * ran to completion, held a channel and had its output discarded, while the caller had
 * already been told it timed out: #146 in the one path the first fix did not cover.
 *
 * Driven through a stubbed ssh2 `Client` because the window cannot be produced against a
 * real server on demand — the whole point is that it depends on the server's timing.
 */

interface Signalled { id: number; name: string }

/**
 * A channel in the state ssh2 hands to `client.exec`'s callback: writable, outgoing state
 * `'open'`.
 *
 * The first version of this fake used the post-`stream.end()` shape (`writable: false`,
 * state `'eof'`) copied from the other test file — but the late-channel path returns
 * *before* `stream.end()` runs, so production takes ssh2's **public** `signal()` there.
 * The fake had no `signal` method at all, so the assertions were riding the `_protocol`
 * fallback: a branch this path does not use. Measured against a real server:
 *
 *   at the exec callback: writable=true  outgoing.state=open
 *   after end():          writable=false outgoing.state=eof
 *
 * So `signal()` here reproduces ssh2's real gate and funnels into the same `signalled`
 * array, which makes that array mean "the request left the client" by either route.
 */
function fakeStream(signalled: Signalled[]) {
  const stream = Object.assign(new EventEmitter(), {
    type: 'session',
    writable: true,
    outgoing: { id: 42, state: 'open' },
    _client: {
      _sock: { writable: true, _readableState: { ended: false } },
      _protocol: { signal: (id: number, name: string) => { signalled.push({ id, name }); } },
    },
    signal(name: string) {
      const self = stream as unknown as { type: string; writable: boolean; outgoing: { id: number; state: string } };
      if (self.type === 'session' && self.writable && self.outgoing.state === 'open') {
        signalled.push({ id: self.outgoing.id, name });
      }
    },
    close: vi.fn(),
    stderr: new EventEmitter(),
    write: vi.fn(),
    // `end()` performs the real transition, so a test that lets the channel arrive in time
    // exercises the post-EOF shape rather than a hardcoded guess at it.
    end: vi.fn(() => {
      (stream as { writable: boolean }).writable = false;
      (stream as { outgoing: { state: string } }).outgoing.state = 'eof';
    }),
  });
  return stream;
}

const profile = {
  name: 'p', host: 'h', port: 22, user: 'u', role: 'admin', auth: 'password', group: 'dev',
  tty: false, timeout: 50, maxChars: 100, maxOutputBytes: 1000, readOnly: false,
  approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 1000,
  sessionBackgroundMaxMs: 1000, commandQuotaPerDay: 0,
} as unknown as Profile;

let signalled: Signalled[];
/** How long the stubbed server takes to answer the exec request. */
let execDelayMs: number;

beforeEach(() => {
  signalled = [];
  execDelayMs = 300;
  vi.resetModules();
  vi.doMock('ssh2', () => {
    class FakeClient extends EventEmitter {
      connect() { setTimeout(() => this.emit('ready'), 0); return this; }
      exec(_cmd: string, _opts: unknown, cb: (err: Error | undefined, stream: unknown) => void) {
        setTimeout(() => cb(undefined, fakeStream(signalled)), execDelayMs);
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

async function connect() {
  const { SSHConnection } = await import('../../../src/ssh/connection.js');
  return new SSHConnection(profile, { password: 'x' } as never, new Map(), 'insecure');
}

describe('a channel that arrives after the promise settled', () => {
  it('is stopped rather than left running on the host', async () => {
    const conn = await connect();
    await expect(conn.exec('sleep 30', { timeoutMs: 50 })).rejects.toThrow(/timed out/i);
    expect(signalled, 'the late channel was never signalled').toEqual([]);

    // The channel arrives 250ms after the rejection.
    await new Promise((r) => setTimeout(r, 400));
    expect(signalled.map((s) => s.name), 'the late channel must be signalled on arrival').toEqual(['INT']);
  });

  it('does not count the late channel as an open one', async () => {
    // It never becomes `activeStream`, so nothing would ever decrement it.
    const conn = await connect();
    await conn.exec('sleep 30', { timeoutMs: 50 }).catch(() => {});
    await new Promise((r) => setTimeout(r, 400));
    expect(conn.toInfo().activeChannels).toBe(0);
  });

  it('does not warn about a stop it never attempted', async () => {
    // The rejection is settled before the channel exists, so there is nothing to ask.
    // Warning here would put "may still be running" on every timeout that races a slow
    // channel open, and a warning that fires when nothing is wrong stops being read.
    const conn = await connect();
    const err = await conn.exec('sleep 30', { timeoutMs: 50 }).then(() => null, (e: Error) => e);
    expect(err?.message).toBe('Command timed out after 50ms');
  });

  it('still stops a channel that arrived in time', async () => {
    // The ordinary path, so the guard above cannot pass by refusing everything.
    execDelayMs = 0;
    const conn = await connect();
    await expect(conn.exec('sleep 30', { timeoutMs: 80 })).rejects.toThrow(/timed out/i);
    expect(signalled.map((s) => s.name)).toEqual(['INT']);
  });
});
