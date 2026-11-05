import { EventEmitter } from 'events';
import { vi } from 'vitest';
import type { ClientChannel } from 'ssh2';

/** A signal request that left the client, by either route. */
export interface WireEntry { id: number; name: string }

/**
 * An ssh2 1.17 exec channel, in the state ssh2 hands to `client.exec`'s callback:
 * writable, outgoing state `'open'`, over a socket that will still carry a packet.
 *
 * `signal()` reproduces ssh2's real gate (lib/Channel.js:241-243) *including its
 * silence*: it writes the request only while `type === 'session' && writable &&
 * outgoing.state === 'open'`, and otherwise returns having sent nothing. A fake that
 * recorded the call instead would pass on the broken code — calling `signal()` was
 * exactly the problem in #146. So there is one observation point, `wire`, and it means
 * "this actually left the client": the public method and the `_protocol` fallback both
 * end there.
 *
 * `end()` and `close()` perform the transitions ssh2 does, so a test that drives the
 * channel through them exercises the resulting shape rather than a hardcoded guess at
 * it. `overrides` replaces fields wholesale; `afterStdinClosed()` is the usual one. Pass
 * `wire` to collect the requests of several channels in one array.
 *
 * Two test files used to carry their own copies of this, and the copy in
 * exec-late-channel once used the post-`end()` shape where production takes the public
 * path, so its assertions were riding a branch that path does not use.
 */
export function fakeSsh2Channel(
  overrides: Record<string, unknown> = {},
  { id = 7, wire = [] as WireEntry[] }: { id?: number; wire?: WireEntry[] } = {},
) {
  const channel = Object.assign(new EventEmitter(), {
    type: 'session',
    writable: true,
    outgoing: { id, state: 'open' },
    _client: {
      _sock: { writable: true, _readableState: { ended: false } },
      _protocol: { signal: (to: number, name: string) => { wire.push({ id: to, name }); } },
    },
    signal(name: string) {
      const self = channel as unknown as ChannelShape;
      if (self.type === 'session' && self.writable && self.outgoing.state === 'open') {
        self._client._protocol.signal(self.outgoing.id, name);
      }
    },
    close: vi.fn(() => { (channel as unknown as ChannelShape).outgoing.state = 'closing'; }),
    end: vi.fn(() => {
      const self = channel as unknown as ChannelShape;
      self.writable = false;
      self.outgoing.state = 'eof';
    }),
    write: vi.fn(),
    stderr: new EventEmitter(),
    ...overrides,
  });
  return { channel: channel as unknown as ClientChannel, wire };
}

interface ChannelShape {
  type: string;
  writable: boolean;
  outgoing: { id: number; state: string };
  _client: { _protocol: { signal: (id: number, name: string) => void } };
}

/**
 * The state ssh2 leaves a channel in after `stream.end()`: EOF sent, no longer writable.
 *
 * A factory, not a constant. As a shared literal its `outgoing` object was shared by
 * every fake that spread it, so the first ladder's `close()` moved *every later fake* to
 * `'closing'` and three tests silently stopped testing anything.
 */
export const afterStdinClosed = (id = 7) => ({ writable: false, outgoing: { id, state: 'eof' } });

/** A channel that completes on the next tick with exit code 0 and no output. */
export function completedChannel() {
  const stream = Object.assign(new EventEmitter(), {
    stderr: new EventEmitter(),
    write: vi.fn(), end: vi.fn(), close: vi.fn(), signal: vi.fn(),
  });
  setTimeout(() => stream.emit('close', 0, null), 0);
  return stream;
}
