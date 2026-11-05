import { EventEmitter } from 'events';
import { vi } from 'vitest';
import type { ClientChannel } from 'ssh2';

/** A signal request that left the client, by either route. */
export interface WireEntry { id: number; name: string }

export interface FakeChannelOptions {
  /** The channel id the requests carry. */
  id?: number;
  /** Where requests are recorded; pass one array to collect several channels. */
  wire?: WireEntry[];
  /** Run the channel's own `end()` first: the state `exec()` leaves every channel in. */
  stdinClosed?: boolean;
  /** The transport under the channel, or `null` for one that cannot be read at all. */
  sock?: { writable: boolean; ended: boolean } | null;
  /**
   * What `_client._protocol.signal` does: record to `wire` (the default), throw, or not
   * exist. With `client: false` there is no `_client` at all.
   */
  protocol?: 'records' | 'throws' | 'absent';
  client?: boolean;
  /** Called after each request reaches `wire`, e.g. to close the channel in response. */
  onWire?: (entry: WireEntry) => void;
}

interface ChannelState {
  type: string;
  writable: boolean;
  outgoing: { id: number; state: string };
  _client?: {
    _sock?: { writable: boolean; _readableState: { ended: boolean } };
    _protocol?: { signal: (id: number, name: string) => void };
  };
}

/**
 * An ssh2 1.17 exec channel, in the state ssh2 hands to `client.exec`'s callback:
 * writable, outgoing state `'open'`, over a socket that will still carry a packet.
 *
 * `signal()` reproduces ssh2's real gate (lib/Channel.js:241-243) *including its
 * silence*: it writes the request only while `type === 'session' && writable &&
 * outgoing.state === 'open'`, and otherwise returns having sent nothing. A fake that
 * recorded the call instead would pass on the broken code — calling `signal()` was
 * exactly the problem in #146. So there is one observation point, `wire`, and it means
 * "this actually left the client": the public method and the `_protocol` fallback both end
 * there whatever the options, because the transport and protocol are options rather than
 * fields a test replaces.
 *
 * `end()` and `close()` perform the transitions ssh2 does, and `stdinClosed` goes through
 * `end()`, so a test exercises the resulting shape rather than a hardcoded guess at it.
 * `overrides` is for fields outside that, such as `type`, a replaced `signal`, or the
 * `incoming`/`destroyed` a session reads.
 */
export function fakeSsh2Channel(overrides: Record<string, unknown> = {}, options: FakeChannelOptions = {}) {
  const {
    id = 7, wire = [], stdinClosed = false, sock = { writable: true, ended: false },
    protocol = 'records', client = true, onWire,
  } = options;
  const record = (to: number, name: string) => {
    const entry = { id: to, name };
    wire.push(entry);
    onWire?.(entry);
  };
  const state: ChannelState = {
    type: 'session',
    writable: true,
    outgoing: { id, state: 'open' },
    _client: client ? {
      ...(sock && { _sock: { writable: sock.writable, _readableState: { ended: sock.ended } } }),
      ...(protocol === 'records' && { _protocol: { signal: record } }),
      ...(protocol === 'throws' && { _protocol: { signal: () => { throw new Error('closed'); } } }),
    } : undefined,
  };
  const channel = Object.assign(new EventEmitter(), state, {
    signal(name: string) {
      if (channel.type === 'session' && channel.writable && channel.outgoing.state === 'open') {
        channel._client?._protocol?.signal(channel.outgoing.id, name);
      }
    },
    close: vi.fn(() => { channel.outgoing.state = 'closing'; }),
    end: vi.fn(() => {
      channel.writable = false;
      channel.outgoing.state = 'eof';
    }),
    write: vi.fn(),
    stderr: new EventEmitter(),
  }, overrides);
  if (stdinClosed) {
    channel.end();
    channel.end.mockClear();
  }
  return { channel: channel as unknown as ClientChannel, wire };
}

/**
 * A channel that completes on the next tick with exit code 0 and no output, for tests of
 * what reaches `client.exec` rather than of how a command is stopped.
 */
export function completedChannel(): ClientChannel {
  const { channel } = fakeSsh2Channel();
  setTimeout(() => channel.emit('close', 0, null), 0);
  return channel;
}
