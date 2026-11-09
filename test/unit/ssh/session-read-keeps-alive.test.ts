import { describe, it, expect, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import type { ClientChannel } from 'ssh2';
import { BackgroundSession } from '../../../src/ssh/session.js';

/**
 * Reading a live session must count as activity.
 *
 * A background command whose output is redirected to a file — the normal way to
 * run a long job — emits nothing on the channel, so `lastActivity` only ever
 * moved on `stream.on('data')` and froze at creation. A caller polling the
 * session every minute therefore looked exactly like a caller that had walked
 * away, and the idle reaper closed the session under it at the idle timeout.
 *
 * This was measured against a real host before the fix: two jobs, both with the
 * default 10-minute idle TTL, died at 10m22s and 10m56s while one of them was
 * polled every 90 seconds.
 */

function fakeChannel(): ClientChannel {
  return new EventEmitter() as unknown as ClientChannel;
}

function makeSession(ttlMs: number): BackgroundSession {
  return new BackgroundSession('id', 'job', 'prof', fakeChannel(), ttlMs);
}

/** Push lastActivity back without waiting, so the test does not sleep. */
function idleFor(session: BackgroundSession, ms: number): void {
  session.lastActivity = new Date(Date.now() - ms);
}

describe('readOutput counts as activity', () => {
  it('a read refreshes the idle clock', () => {
    const session = makeSession(1_000);
    idleFor(session, 2_000);
    expect(session.isExpired(), 'precondition: the session is already idle-expired').toBe(true);

    session.readOutput();

    expect(session.isExpired()).toBe(false);
  });

  it('polling keeps a silent job alive past its TTL', () => {
    // On a fake clock, so the session's age really accumulates: four polls 600ms apart
    // span 2.4s against a 1s TTL. Without the touch, the second poll already lands on a
    // session the reaper would have closed. (Resetting lastActivity before each poll,
    // as idleFor does, would pass without the fix.)
    vi.useFakeTimers();
    try {
      const session = makeSession(1_000);
      for (let i = 0; i < 4; i++) {
        vi.advanceTimersByTime(600);
        session.readOutput();
        expect(session.isExpired(), `expired at poll ${i + 1}`).toBe(false);
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it('leaves a session without a reader on the ordinary expiry path', () => {
    const session = makeSession(1_000);
    idleFor(session, 2_000);
    expect(session.isExpired()).toBe(true);
  });

  it('still returns the requested number of lines', () => {
    const channel = fakeChannel();
    const session = new BackgroundSession('id', 'job', 'prof', channel, 0);
    // Through the stream, the way output actually arrives: the ring buffer is private
    // and a test that reached into it would not exercise the same code path.
    channel.emit('data', Buffer.from('a\nb\nc\n'));
    expect(session.readOutput(2)).toBe('b\nc');
  });
});
