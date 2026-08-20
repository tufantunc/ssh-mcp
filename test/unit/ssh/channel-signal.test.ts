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
    _client: { _protocol: { signal: (id: number, name: string) => { wire.push({ id, name }); } } },
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
    const { channel } = fakeChannel({
      ...afterStdinClosed,
      _client: { _protocol: { signal: () => { throw new Error('closed'); } } },
    });
    expect(signalChannel(channel, 'INT')).toBe(false);
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

  it('still refuses to signal a channel whose stdin is closed', async () => {
    // The reason the fallback exists, read out of ssh2 rather than assumed. If
    // this stops being true, the fallback is dead weight and can go.
    const { readFile } = await import('fs/promises');
    const source = await readFile(
      new URL('../../../node_modules/ssh2/lib/Channel.js', import.meta.url),
      'utf8',
    );
    const signalMethod = source.slice(source.indexOf('  signal(signalName) {'));
    expect(signalMethod).toContain('this.writable');
    expect(signalMethod.slice(0, signalMethod.indexOf('}'))).toContain("outgoing.state === 'open'");
  });
});
