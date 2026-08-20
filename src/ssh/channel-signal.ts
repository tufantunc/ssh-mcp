import type { ClientChannel } from 'ssh2';

/**
 * Stop a command running behind an exec channel — reliably, which ssh2's own
 * `signal()` is not once stdin has been closed.
 *
 * `SSHConnection.exec()` closes stdin the moment the command is dispatched, because
 * a command that reads stdin would otherwise wait for input nobody is going to send.
 * ssh2 1.17's `Channel.signal()` (lib/Channel.js:237) writes the request only while
 *
 *     this.type === 'session' && this.writable && this.outgoing.state === 'open'
 *
 * and `end()` clears the last two: it fires `prefinish`/`finish`, and ssh2's `onFinish`
 * listener (lib/Channel.js:268) calls `eof()` — moving the outgoing state to `'eof'` —
 * and sets `writable = false`. It does not throw or report anything — it simply
 * returns. So every signal sent to stop a timed-out command was discarded
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
 * Retiring this fallback is a code change, not something that happens by itself. The
 * public path is gated by `ssh2WillSend` below, which is a deliberate copy of ssh2
 * 1.17's condition — so even with mscdex/ssh2#1510 released, our own copy still refuses
 * and the fallback stays on the hot path until someone widens it. `ssh2WillSend` is the
 * one place to change, and the behavioural tripwire in channel-signal.test.ts fails the
 * moment ssh2 starts signalling after EOF, which is the signal to change it. An earlier
 * version of this comment claimed the fallback would stop being reached on its own; it
 * could not, and a plan that cannot fire is worse than no plan.
 *
 * What this does NOT achieve, measured: the request reaches the command's *session
 * leader*, not its process group. `sh -c 'trap "" INT TERM; sleep 30'` loses the shell
 * to KILL and leaves the `sleep` orphaned. So a stopped command can still leave
 * children behind, and no rung of the ladder changes that — which is why nothing here
 * claims the process is gone. See `signalChannel`'s return value.
 */

/** The parts of a channel ssh2 does not put in its public typings. */
type ChannelInternals = {
  type?: string;
  writable?: boolean;
  outgoing?: { id?: number; state?: string };
  _client?: {
    _protocol?: { signal?: (id: number, name: string) => void };
    /** ssh2 drops any write to this silently once it is unwritable; see `onTheWire`. */
    _sock?: { writable?: boolean };
  };
};

/** The signals this module sends. Typed so a name ssh2 rejects is a compile error. */
export type SignalName = 'INT' | 'TERM' | 'KILL';

/** Outgoing states in which the far end still has a channel to receive a request. */
const OPEN_STATES = new Set(['open', 'eof']);

/**
 * Whether ssh2's own `Channel.signal()` would put this request on the wire.
 *
 * A deliberate copy of lib/Channel.js:241-243 in ssh2 1.17, and the single place to
 * update when that changes. Copying it is what lets us tell "ssh2 will handle this"
 * from "ssh2 will silently discard it" — the distinction the whole module exists for.
 */
function ssh2WillSend(ch: ClientChannel & ChannelInternals): boolean {
  return ch.type === 'session' && ch.writable === true && ch.outgoing?.state === 'open';
}

/**
 * Whether the transport can still carry a packet.
 *
 * ssh2 hands every packet to `onWrite`, which is `if (isWritable(sock)) sock.write(data)`
 * (lib/client.js:303) — an unwritable socket means the packet is dropped with no error
 * and no return value. Measured against 1.17.0: immediately after `client.end()`,
 * `sock.writable` is false while `outgoing.state` is still `'eof'`, so the state guard
 * below passes and the signal call returns without throwing. Reporting that as delivery
 * is #146 one layer down, and it is reachable whenever a connection is closed under a
 * running command — `SSHConnection.close()`, or the idle reaper, which does not consult
 * `activeChannels`.
 */
function onTheWire(ch: ClientChannel & ChannelInternals): boolean {
  const writable = ch._client?._sock?.writable;
  return writable === undefined || writable === true;
}

/**
 * Send `name` to the process behind `channel`.
 *
 * Returns whether the request was **dispatched to the wire** — not whether the command
 * stopped. Nothing in SSH acknowledges a signal request, the signal reaches the session
 * leader rather than the process group, and a target may refuse it outright, so
 * "the process is gone" is not a fact this function can produce. What it can produce
 * honestly is "I could not even ask", which is what the caller warns about, because a
 * signal that goes nowhere while reporting success is the defect this module exists to
 * remove.
 */
export function signalChannel(channel: ClientChannel, name: SignalName): boolean {
  const ch = channel as ClientChannel & ChannelInternals;
  const state = ch.outgoing?.state;

  // Only session channels carry a process. ssh2 gates on this too, and a
  // forwarded-tcpip channel has nothing to signal.
  if (ch.type !== undefined && ch.type !== 'session') return false;
  // Already closing or closed: the request would have no channel to arrive on, and
  // ssh2 may have handed the id to a new channel.
  if (state !== undefined && !OPEN_STATES.has(state)) return false;
  // Nothing can be dispatched through a socket ssh2 will not write to, and it will not
  // tell us — so this has to be asked before either path claims success.
  if (!onTheWire(ch)) return false;

  // The supported path, taken whenever ssh2 will actually write the request.
  if (ssh2WillSend(ch)) {
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
 * Returns whether the *first* signal was dispatched — known synchronously, so the
 * caller can say "I could not even ask" in the same breath as the timeout it is already
 * reporting. It is not a claim that the command stopped, and callers must not read it
 * as one: the later rungs have not run yet, no rung is acknowledged, and the signal
 * does not reach the process group.
 */
export function terminateChannel(channel: ClientChannel): boolean {
  const dispatched = signalChannel(channel, 'INT');

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

  return dispatched;
}
