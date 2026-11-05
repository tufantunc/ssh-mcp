import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { Profile } from '../../../src/types.js';
import { fakeSsh2Channel, type WireEntry, type FakeChannelOptions } from '../../helpers/fake-channel.js';
import { COULD_NOT_SIGNAL } from '../../../src/ssh/channel-signal.js';
import { recordingTracer, type RecordedSpan } from '../../helpers/spans.js';

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

/**
 * The stubbed server hands out a channel in the state ssh2 hands to `client.exec`'s
 * callback: writable, outgoing state `'open'`. The late-channel path returns *before*
 * `stream.end()` runs, so production takes ssh2's **public** `signal()` there — measured
 * against a real server:
 *
 *   at the exec callback: writable=true  outgoing.state=open
 *   after end():          writable=false outgoing.state=eof
 *
 * `fakeSsh2Channel` starts in the first shape and its `end()` performs the transition, and
 * every route a request can take ends in its `wire`.
 */

const profile = {
  name: 'p', host: 'h', port: 22, user: 'u', role: 'admin', auth: 'password', group: 'dev',
  tty: false, timeout: 50, maxChars: 100, maxOutputBytes: 1000, readOnly: false,
  approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 1000,
  sessionBackgroundMaxMs: 1000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
} as unknown as Profile;

let signalled: WireEntry[];
let spans: RecordedSpan[];
/** How long the stubbed server takes to answer the exec request. */
let execDelayMs: number;
/** How the channel it answers with differs from a signallable one. */
let lateChannel: FakeChannelOptions;

beforeEach(() => {
  signalled = [];
  execDelayMs = 300;
  lateChannel = {};
  vi.resetModules();
  const recording = recordingTracer();
  spans = recording.spans;
  vi.doMock('../../../src/observability/tracer.js', () => ({ tracer: recording.tracer }));
  vi.doMock('ssh2', () => {
    class FakeClient extends EventEmitter {
      connect() { setTimeout(() => this.emit('ready'), 0); return this; }
      exec(_cmd: string, _opts: unknown, cb: (err: Error | undefined, stream: unknown) => void) {
        // Bound now, not when the timer fires: a test that returns before its late channel
        // arrives must not have that channel write into the next test's array.
        const options = { ...lateChannel, id: 42, wire: signalled };
        setTimeout(() => cb(undefined, fakeSsh2Channel({}, options).channel), execDelayMs);
      }
      end() { /* nothing to tear down */ }
    }
    return { Client: FakeClient, default: { Client: FakeClient } };
  });
});

afterEach(() => {
  vi.doUnmock('ssh2');
  vi.doUnmock('../../../src/observability/tracer.js');
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

    // On a span of its own: the exec span ended with the rejection, and an attribute set on
    // an ended span is dropped. The exec span says the stop was deferred, this one how it went.
    expect(spans.find((sp) => sp.name === 'ssh.exec')?.attributes).toMatchObject({ 'ssh.stopDeferred': true });
    const late = spans.find((sp) => sp.name === 'ssh.exec.lateStop');
    expect(late?.attributes).toEqual({ 'ssh.host': 'h', 'ssh.unstopped': false });
    expect(late?.ended).toBe(true);
  });

  it('records a late channel it could not signal as unstopped', async () => {
    // The other side of the lateStop span, which is the only record this outcome gets: the
    // caller was told "timed out" before the channel existed.
    lateChannel = { client: false };
    const conn = await connect();
    await conn.exec('sleep 30', { timeoutMs: 50 }).catch(() => {});
    await new Promise((r) => setTimeout(r, 400));
    expect(signalled).toEqual([]);
    expect(spans.find((sp) => sp.name === 'ssh.exec.lateStop')?.attributes)
      .toEqual({ 'ssh.host': 'h', 'ssh.unstopped': true });
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
    expect(err?.message).toMatch(/timed out/i);
    expect(err?.message).not.toContain(COULD_NOT_SIGNAL.trim());
  });

  it('still stops a channel that arrived in time', async () => {
    // The ordinary path, so the guard above cannot pass by refusing everything.
    execDelayMs = 0;
    const conn = await connect();
    await expect(conn.exec('sleep 30', { timeoutMs: 80 })).rejects.toThrow(/timed out/i);
    expect(signalled.map((s) => s.name)).toEqual(['INT']);
  });
});
