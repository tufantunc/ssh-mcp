import { describe, it, expect, vi } from 'vitest';
import type { ClientChannel } from 'ssh2';
import { BackgroundSession } from '../../../src/ssh/session.js';
import { fakeSsh2Channel } from '../../helpers/fake-channel.js';

/**
 * What `BackgroundSession.close()` reports, pinned at the implementation.
 *
 * The tool-layer tests drive this through a stubbed connection, so they pin the *sentence*
 * for a given outcome but not the mapping that produces it. Measured: hardcoding
 * `close()` to return `'closed'` left 49 of those tests green — the whole point of the
 * outcome is that `close-session` must not answer "closed." for a command the ladder
 * failed to stop, and that mapping had no test at all.
 */

/**
 * A channel in the state ssh2 hands back from `openExec` — writable, outgoing open — that
 * closes once a signal reaches the wire, unless `closes` is false.
 */
function fakeStream(opts: { transportWritable?: boolean; closes?: boolean } = {}) {
  const { transportWritable = true, closes = true } = opts;
  const { channel, wire } = fakeSsh2Channel(
    {
      incoming: { state: 'open' },
      destroyed: false,
      close: vi.fn(() => { if (closes) channel.emit('close'); }),
    },
    {
      id: 11,
      sock: { writable: transportWritable, ended: false },
      onWire: () => { if (closes) setTimeout(() => channel.emit('close'), 5); },
    },
  );
  return { stream: channel, wire };
}

const session = (stream: ClientChannel) => new BackgroundSession('id', 'bg', 'p', stream, 60_000);

describe('BackgroundSession.close', () => {
  it('reports a confirmed close when the channel closes', async () => {
    const { stream, wire } = fakeStream();
    expect(await session(stream).close()).toBe('closed');
    expect(wire[0]?.name).toBe('INT');
  });

  it('reports stop-unconfirmed when the ladder ran and the channel stayed open', async () => {
    // The strongest evidence available that the command survived INT, TERM *and* KILL: a
    // process in uninterruptible sleep, or a server that refuses signal requests at all.
    // Budget shortened via the session's own ladder rather than waited out in real time.
    const { stream, wire } = fakeStream({ closes: false });
    const s = session(stream);
    const outcome = await Promise.race([
      s.close(),
      new Promise((r) => setTimeout(() => r('timed-out-in-test'), 6000)),
    ]);
    expect(outcome).toBe('stop-unconfirmed');
    expect(wire[0]?.name, 'the ladder must still have been dispatched').toBe('INT');
  }, 20000);

  it('reports unsignalled, and does not wait, when nothing could be dispatched', async () => {
    // A transport ssh2 will not write to. No later rung can be delivered either, so waiting
    // for a close that can never arrive was measured burning the full 3.5s budget.
    const { stream, wire } = fakeStream({ transportWritable: false, closes: false });
    const started = Date.now();
    expect(await session(stream).close()).toBe('unsignalled');
    expect(wire, 'nothing should have reached the wire').toEqual([]);
    expect(Date.now() - started, 'waited for a close that could never arrive').toBeLessThan(500);
  });
});
