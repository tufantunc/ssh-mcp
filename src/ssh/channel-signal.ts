import type { ClientChannel } from 'ssh2';

/**
 * Stop a command running behind an exec channel — reliably, which ssh2's own
 * `signal()` is not once stdin has been closed.
 *
 * `SSHConnection.exec()` closes stdin the moment the command is dispatched, because
 * a command that reads stdin would otherwise wait for input nobody is going to send.
 * ssh2 1.17's `Channel.signal()` (lib/Channel.js) writes the request only while
 *
 *     this.type === 'session' && this.writable && this.outgoing.state === 'open'
 *
 * and `end()` clears the last two: `_final` calls `eof()`, moving the outgoing state
 * to `'eof'`, and sets `writable = false`. It does not throw or report anything — it
 * simply returns. So every signal sent to stop a timed-out command was discarded
 * inside ssh2, and the command ran to completion on the host while the caller was
 * told it had timed out (#146).
 *
 * Measured against OpenSSH 10.3p1, one channel per row, a 30s `sleep` as the victim:
 *
 *   end() then INT/TERM/close()          alive at +4s, alive at +9s
 *   no end(), INT/TERM                   gone by +4s
 *   end() then close() alone             alive at +9s
 *   eof() then INT/TERM                  alive at +9s
 *   end() then the protocol call below   gone by +4s
 *
 * Two things follow. A delivered signal is the *only* thing that stops a non-tty
 * command — closing the channel does not, which is the same reason killing a local
 * `ssh host 'sleep 30'` leaves the sleep running. And the reporter's proposed
 * `end()` → `eof()` change does nothing on its own, because `'eof'` fails ssh2's
 * gate exactly as `writable === false` does; it only works together with
 * mscdex/ssh2#1510, which relaxes the gate to accept `'eof'`.
 *
 * Rather than wait for that (ssh2 releases roughly annually — 1.16.0 to 1.17.0 was
 * eleven months), this sends the request through the protocol object ssh2's own
 * method would have used. The SSH protocol allows a channel request after EOF: EOF
 * ends the data stream, not the channel. Only ssh2's bookkeeping objected.
 *
 * When ssh2 relaxes the gate the public path starts covering the `'eof'` case by
 * itself, this fallback stops being reached, and it can be deleted — the tests in
 * channel-signal.test.ts pin the ssh2 shape this depends on, so the upgrade that
 * makes it unnecessary announces itself.
 */

/** The parts of a channel ssh2 does not put in its public typings. */
type ChannelInternals = {
  type?: string;
  writable?: boolean;
  outgoing?: { id?: number; state?: string };
  _client?: { _protocol?: { signal?: (id: number, name: string) => void } };
};

/** Outgoing states in which the far end still has a channel to receive a request. */
const OPEN_STATES = new Set(['open', 'eof']);

/**
 * Send `name` to the process behind `channel`.
 *
 * Returns whether the request left the client. That answer is the point: a signal
 * that goes nowhere while reporting success is the defect this module exists to
 * remove, so "I could not signal it" has to be sayable.
 */
export function signalChannel(channel: ClientChannel, name: string): boolean {
  const ch = channel as ClientChannel & ChannelInternals;
  const state = ch.outgoing?.state;

  // Only session channels carry a process. ssh2 gates on this too, and a
  // forwarded-tcpip channel has nothing to signal.
  if (ch.type !== undefined && ch.type !== 'session') return false;
  // Already closing or closed: the request would have no channel to arrive on, and
  // ssh2 may have handed the id to a new channel.
  if (state !== undefined && !OPEN_STATES.has(state)) return false;

  // The supported path, taken whenever ssh2 will actually write the request. This is
  // also the path that grows once ssh2 accepts `'eof'`.
  if (ch.writable === true && state === 'open') {
    try {
      channel.signal(name);
      return true;
    } catch {
      return false;
    }
  }

  const id = ch.outgoing?.id;
  const protocol = ch._client?._protocol;
  if (typeof id === 'number' && typeof protocol?.signal === 'function') {
    try {
      protocol.signal(id, name);
      return true;
    } catch {
      return false;
    }
  }

  // A shape we do not recognise. Ask ssh2 and report failure anyway: we cannot tell
  // whether it sent anything, and claiming delivery we cannot verify is what made
  // this bug invisible for so long. An unnecessary "may still be running" warning is
  // the better way to be wrong.
  try { channel.signal(name); } catch { /* nothing left to try */ }
  return false;
}

/** How long each signal is given to work before the next one is tried. */
const ESCALATION_MS = 1000;

/**
 * Escalate until the command is gone: INT, then TERM, then KILL, then drop the
 * channel.
 *
 * KILL is last because it denies the command any chance to clean up; it exists
 * because the rung below it used to be `close()`, and closing a channel was measured
 * not to stop anything. A command that ignores INT and TERM used to run forever.
 *
 * Returns whether the *first* signal left the client — known synchronously, so the
 * caller can say "and it may still be running" in the same breath as the timeout it
 * is already reporting.
 */
export function terminateChannel(channel: ClientChannel): boolean {
  const delivered = signalChannel(channel, 'INT');

  const pending: NodeJS.Timeout[] = [];
  const later = (fn: () => void, ms: number) => {
    // Unreferenced: this ladder outlives the promise it settled by up to three
    // seconds, and a referenced timer would add that to the exit of any process
    // whose last act was a timed-out command.
    pending.push(setTimeout(fn, ms).unref());
  };

  const stop = () => { for (const t of pending) clearTimeout(t); pending.length = 0; };
  // Nothing more to send once the channel is gone, and the id may be reused.
  channel.once('close', stop);

  later(() => { signalChannel(channel, 'TERM'); }, ESCALATION_MS);
  later(() => { signalChannel(channel, 'KILL'); }, ESCALATION_MS * 2);
  later(() => { try { channel.close(); } catch { /* already gone */ } }, ESCALATION_MS * 3);

  return delivered;
}
