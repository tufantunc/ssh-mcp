import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ClientChannel } from 'ssh2';
import { signalChannel, terminateChannel } from '../../../src/ssh/channel-signal.js';

/**
 * #146: every signal ssh-mcp sent to stop a timed-out command was a silent no-op,
 * so the command ran to completion on the host while the caller was told it had
 * timed out.
 *
 * The fake channel below mirrors ssh2 1.17's `Channel.signal()` *including its
 * silence* — the real method checks `type === 'session' && writable &&
 * outgoing.state === 'open'` and, when that fails, returns without writing
 * anything. A fake that recorded the call instead would pass on the broken code:
 * we did call `signal()`, and that was exactly the problem. So there is one
 * observation point here, `wire`, and it means "this actually left the client".
 */

interface WireEntry { id: number; name: string }


function fakeChannel(overrides: Record<string, unknown> = {}) {
  const wire: WireEntry[] = [];
  const closeHandlers: Array<() => void> = [];
  const channel = {
    type: 'session',
    writable: true,
    outgoing: { id: 7, state: 'open' },
    // The transport, in the shape a live connection has. `onTheWire` fails closed on an
    // unreadable one, so every fake has to carry it — which is the point: a guard that
    // assumed the best when it could not see the socket was the earlier defect.
    _client: {
      _sock: { writable: true, _readableState: { ended: false } },
      _protocol: { signal: (id: number, name: string) => { wire.push({ id, name }); } },
    },
    // The real gate, reproduced.
    signal(name: string) {
      const self = channel as unknown as { type: string; writable: boolean; outgoing: { id: number; state: string } };
      if (self.type === 'session' && self.writable && self.outgoing.state === 'open') {
        channel._client._protocol.signal(self.outgoing.id, name);
      }
    },
    close: vi.fn(() => { (channel.outgoing as { state: string }).state = 'closing'; }),
    on: vi.fn((event: string, cb: () => void) => { if (event === 'close') closeHandlers.push(cb); return channel; }),
    once: vi.fn((event: string, cb: () => void) => { if (event === 'close') closeHandlers.push(cb); return channel; }),
    removeListener: vi.fn(),
    ...overrides,
  };
  return { channel: channel as unknown as ClientChannel, wire, fireClose: () => closeHandlers.forEach((h) => h()) };
}

/**
 * The state ssh2 leaves a channel in after `stream.end()`: EOF sent, no longer writable.
 *
 * A factory, not a constant. As a shared literal its `outgoing` object was shared by
 * every fake that spread it, so the first ladder's `close()` moved *every later
 * fake* to `'closing'` and three tests silently stopped testing anything.
 */
const afterStdinClosed = () => ({ writable: false, outgoing: { id: 7, state: 'eof' } });

describe('signalChannel', () => {
  it('uses ssh2\'s own method while it will still send', () => {
    const { channel, wire } = fakeChannel();
    const spy = vi.spyOn(channel, 'signal');
    expect(signalChannel(channel, 'INT')).toBe(true);
    expect(spy).toHaveBeenCalledWith('INT');
    expect(wire).toEqual([{ id: 7, name: 'INT' }]);
  });

  // The defect itself. This is the state exec() puts every channel into, one line
  // after dispatching the command.
  it('still reaches the wire after stdin has been closed', () => {
    const { channel, wire } = fakeChannel(afterStdinClosed());
    expect(signalChannel(channel, 'TERM')).toBe(true);
    expect(wire).toEqual([{ id: 7, name: 'TERM' }]);
  });

  it('does not call ssh2\'s method when calling it would send nothing', () => {
    // Not cosmetic: a call that silently does nothing, reported as success, is the
    // bug. If the public method is unusable we must know it and route around it.
    const { channel } = fakeChannel(afterStdinClosed());
    const spy = vi.spyOn(channel, 'signal');
    signalChannel(channel, 'TERM');
    expect(spy).not.toHaveBeenCalled();
  });

  it.each(['closing', 'closed'])('sends nothing on a %s channel', (state) => {
    const { channel, wire } = fakeChannel({ writable: false, outgoing: { id: 7, state } });
    expect(signalChannel(channel, 'KILL')).toBe(false);
    expect(wire).toEqual([]);
  });

  it('sends nothing on a channel that is not a session', () => {
    // ssh2 gates on this too: a forwarded-tcpip channel has no process to signal.
    const { channel, wire } = fakeChannel({ type: 'direct-tcpip' });
    expect(signalChannel(channel, 'INT')).toBe(false);
    expect(wire).toEqual([]);
  });

  it('reports failure rather than throwing when the internals are not there', () => {
    // The cost of routing around ssh2's public API: a future version may not
    // expose this shape. Then the answer has to be "could not signal", not a crash
    // and not a false success.
    const { channel } = fakeChannel({ ...afterStdinClosed(), _client: undefined });
    expect(signalChannel(channel, 'INT')).toBe(false);
  });

  it('reports failure when the protocol call throws', () => {
    // `afterStdinClosed()`, called. Spread as a bare function it contributes no own
    // properties, so this channel stayed writable-and-open, the *public* path ran, and
    // the fallback's catch — the only line in this module that depends on ssh2 internals
    // — had no coverage while a test claimed otherwise.
    const { channel, wire } = fakeChannel({
      ...afterStdinClosed(),
      _client: {
        _sock: { writable: true, _readableState: { ended: false } },
        _protocol: { signal: () => { throw new Error('closed'); } },
      },
    });
    const spy = vi.spyOn(channel, 'signal');
    expect(signalChannel(channel, 'INT')).toBe(false);
    expect(spy, 'the fallback branch must be the one under test here').not.toHaveBeenCalled();
    expect(wire).toEqual([]);
  });

  it('reports failure when the socket will no longer carry a packet', () => {
    // ssh2 hands packets to `onWrite`, which is `if (isWritable(sock)) sock.write(data)`
    // (lib/client.js:303) — an unwritable socket drops the packet with no error and no
    // return value. Measured against 1.17.0: immediately after `client.end()`,
    // `sock.writable` is false while `outgoing.state` is still `'eof'`, so every guard
    // below passed and `signalChannel` reported delivery of a packet ssh2 threw away.
    // Reachable via `SSHConnection.close()` or the idle reaper closing a connection
    // under a running command.
    const { channel, wire } = fakeChannel({
      ...afterStdinClosed(),
      _client: {
        _sock: { writable: false, _readableState: { ended: true } },
        _protocol: { signal: (id: number, name: string) => { wire.push({ id, name }); } },
      },
    });
    expect(signalChannel(channel, 'TERM')).toBe(false);
    expect(wire, 'nothing may be claimed as sent through a dead socket').toEqual([]);
  });

  it('refuses a half-open socket ssh2 would not write to', () => {
    // The ProxyJump shape, and the case the first version of this guard missed: the peer
    // closed its side, so `writable` is still true while ssh2's `isWritable` — which also
    // requires `_readableState.ended === false` — is false. Measured: a socket with
    // allowHalfOpen sits in that state indefinitely, and ssh2's transport for a `via`
    // profile is a forwarded channel, which defaults to allowHalfOpen.
    const { channel, wire } = fakeChannel({
      ...afterStdinClosed(),
      _client: {
        _sock: { writable: true, _readableState: { ended: true } },
        _protocol: { signal: (id: number, name: string) => { wire.push({ id, name }); } },
      },
    });
    expect(signalChannel(channel, 'TERM')).toBe(false);
    expect(wire).toEqual([]);
  });

  it('refuses when the transport cannot be read at all', () => {
    // Fail closed, matching every other unknown-shape branch in the module.
    const { channel, wire } = fakeChannel({ ...afterStdinClosed(), _client: { _protocol: { signal: () => {} } } });
    expect(signalChannel(channel, 'TERM')).toBe(false);
    expect(wire).toEqual([]);
  });

  it('sends through a socket that is still writable', () => {
    // The other half, so the guard cannot be satisfied by refusing everything.
    const { channel, wire } = fakeChannel({
      ...afterStdinClosed(),
      _client: {
        _sock: { writable: true, _readableState: { ended: false } },
        _protocol: { signal: (id: number, name: string) => { wire.push({ id, name }); } },
      },
    });
    expect(signalChannel(channel, 'TERM')).toBe(true);
    expect(wire).toEqual([{ id: 7, name: 'TERM' }]);
  });

  it('reports failure when ssh2\'s own method throws', () => {
    const { channel } = fakeChannel({ signal: () => { throw new Error('server mode'); } });
    expect(signalChannel(channel, 'INT')).toBe(false);
  });
});

describe('terminateChannel', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('escalates INT, TERM, KILL and then drops the channel', () => {
    const { channel, wire } = fakeChannel(afterStdinClosed());
    terminateChannel(channel);
    expect(wire.map((w) => w.name)).toEqual(['INT']);
    vi.advanceTimersByTime(1000);
    expect(wire.map((w) => w.name)).toEqual(['INT', 'TERM']);
    vi.advanceTimersByTime(1000);
    expect(wire.map((w) => w.name)).toEqual(['INT', 'TERM', 'KILL']);
    expect(channel.close).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('reports whether the first signal left the client', () => {
    expect(terminateChannel(fakeChannel(afterStdinClosed()).channel)).toBe(true);
    expect(terminateChannel(fakeChannel({ ...afterStdinClosed(), _client: undefined }).channel)).toBe(false);
  });

  it('stops escalating once the channel closes', () => {
    // KILL costs the command its chance to clean up, so it is only for a process
    // that ignored the gentler two. Sending it after the process is already gone
    // also races a channel id that ssh2 may have reused.
    const { channel, wire, fireClose } = fakeChannel(afterStdinClosed());
    terminateChannel(channel);
    fireClose();
    vi.advanceTimersByTime(5000);
    expect(wire.map((w) => w.name)).toEqual(['INT']);
    expect(channel.close).not.toHaveBeenCalled();
  });

  it('does not hold the process open while it waits', () => {
    // The ladder outlives the promise it settled by up to three seconds. Left
    // referenced, that is three seconds added to every `--version`-style exit and
    // to every vitest file that timed a command out.
    vi.useRealTimers();
    const handles: Array<{ hasRef?: () => boolean }> = [];
    const real = globalThis.setTimeout;
    const spy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: never, ms: never) => {
      const h = real(fn, ms);
      handles.push(h as unknown as { hasRef?: () => boolean });
      return h;
    }) as never);
    try {
      terminateChannel(fakeChannel(afterStdinClosed()).channel);
    } finally {
      spy.mockRestore();
    }
    expect(handles.length).toBeGreaterThan(0);
    expect(handles.every((h) => h.hasRef?.() === false)).toBe(true);
    handles.forEach((h) => clearTimeout(h as never));
  });
});

describe('the ssh2 internals this depends on', () => {
  /**
   * A tripwire, not a test of our code. `signalChannel` falls back to
   * `channel._client._protocol.signal(id, name)` because ssh2's public method
   * refuses to send after EOF (mscdex/ssh2#1510). If a future ssh2 renames or
   * removes that path, the failure should say so here rather than surface as a
   * mysterious integration test about a `sleep` that would not die.
   */
  it('still exposes Protocol.prototype.signal', async () => {
    // Loaded through createRequire: this is a deep path into ssh2 that its typings
    // do not describe, which is itself part of what makes the fallback a liability
    // worth a tripwire.
    const { createRequire } = await import('module');
    const Protocol = createRequire(import.meta.url)('ssh2/lib/protocol/Protocol.js');
    expect(typeof Protocol.prototype.signal).toBe('function');
  });

  it('still exposes the socket onTheWire reads', async () => {
    // `_sock` is as undocumented as `_protocol`, and if ssh2 renames it `onTheWire` would
    // fail closed on every signal — every stop would start warning instead of working.
    const { createRequire } = await import('module');
    const { Client } = createRequire(import.meta.url)('ssh2');
    expect(
      '_sock' in new Client(),
      'ssh2 renamed _sock: onTheWire in channel-signal.ts now refuses every signal',
    ).toBe(true);
  });

  it('still refuses to signal a channel whose stdin is closed', async () => {
    // Behavioural, not textual. The previous version grepped Channel.js for
    // `this.writable` and `outgoing.state === 'open'` — and mscdex/ssh2#1510, the very
    // upgrade this tripwire exists to announce, relaxes the gate to
    // `(state === 'open' || state === 'eof')` while dropping the `writable` check. The
    // first substring disappears, the second survives, and a text probe could pass
    // straight through the change. Calling the real method cannot.
    const { createRequire } = await import('module');
    const { Channel } = createRequire(import.meta.url)('ssh2/lib/Channel.js');
    expect(
      typeof Channel.prototype.signal,
      'ssh2 moved Channel.prototype.signal: re-derive ssh2WillSend in channel-signal.ts',
    ).toBe('function');

    let sent = 0;
    const afterEnd = {
      server: false,
      type: 'session',
      writable: false,
      outgoing: { id: 7, state: 'eof' },
      _client: { _protocol: { signal: () => { sent++; } } },
    };
    Channel.prototype.signal.call(afterEnd, 'TERM');
    expect(
      sent,
      'ssh2 now signals after EOF: widen ssh2WillSend in channel-signal.ts and delete the _protocol fallback',
    ).toBe(0);

    // And the state the public path is still good for, so the tripwire cannot pass by
    // ssh2 having stopped signalling altogether.
    let sentWhileOpen = 0;
    Channel.prototype.signal.call(
      { ...afterEnd, writable: true, outgoing: { id: 7, state: 'open' },
        _client: { _protocol: { signal: () => { sentWhileOpen++; } } } },
      'TERM',
    );
    expect(sentWhileOpen, 'ssh2 stopped signalling even on an open channel').toBe(1);
  });
});
