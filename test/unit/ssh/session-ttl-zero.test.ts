import { describe, it, expect } from 'vitest';
import { EventEmitter } from 'node:events';
import type { ClientChannel } from 'ssh2';
import { BackgroundSession } from '../../../src/ssh/session.js';
import { SessionManager } from '../../../src/ssh/session-manager.js';
import { makeProfile } from '../../fixtures/profile.js';

/**
 * `0` means "no cap", for both the idle TTL and the absolute lifetime cap.
 *
 * The comparisons used to be bare `>`, so a literal 0 reaching them read as
 * "expire immediately" — the opposite of what a caller asking for no cap means.
 * The project already spells "unlimited" as 0 in `commandMaxChars` and
 * `commandQuotaPerDay`; these pin the same meaning here, at the point where it
 * decides whether a session is reaped.
 */

function fakeChannel(): ClientChannel {
  return new EventEmitter() as unknown as ClientChannel;
}

function makeSession(ttlMs: number, maxLifetimeMs?: number): BackgroundSession {
  return new BackgroundSession('id', 'job', 'prof', fakeChannel(), ttlMs, maxLifetimeMs);
}

/** Push lastActivity back without waiting, so the test does not sleep. */
function idleFor(session: BackgroundSession, ms: number): void {
  session.lastActivity = new Date(Date.now() - ms);
}

describe('ttlMs = 0 means no idle expiry', () => {
  it('never expires a session that has been idle for a year', () => {
    const session = makeSession(0);
    idleFor(session, 365 * 24 * 60 * 60 * 1_000);
    expect(session.isExpired()).toBe(false);
  });

  it('a positive TTL still expires an idle session', () => {
    const session = makeSession(1_000);
    idleFor(session, 2_000);
    expect(session.isExpired()).toBe(true);
  });

  it('a positive TTL does not expire a fresh session', () => {
    expect(makeSession(1_000).isExpired()).toBe(false);
  });
});

describe('maxLifetimeMs = 0 means no absolute cap', () => {
  it('never expires a session by age', () => {
    const session = makeSession(0, 0);
    session.createdAt.setFullYear(session.createdAt.getFullYear() - 1);
    expect(session.isExpired()).toBe(false);
  });

  it('a positive cap still bounds the session', () => {
    const session = makeSession(0, 1_000);
    session.createdAt.setTime(Date.now() - 2_000);
    expect(session.isExpired()).toBe(true);
  });
});

/**
 * The manager is where a per-call ttlMs and the profile default meet. `open()`'s
 * `opts.ttlMs ?? profile.sessionIdleTimeoutMs` is one line, but a test that only
 * built a Session by hand would not notice it being dropped.
 */
describe('SessionManager.open ttlMs', () => {
  function managerFor(sessionIdleTimeoutMs: number): SessionManager {
    return new SessionManager({
      profile: () => makeProfile({ sessionIdleTimeoutMs }),
      openShell: async () => fakeChannel(),
      openExec: async () => fakeChannel(),
      onChannelOpened: () => {},
      onChannelClosed: () => {},
    });
  }

  it('uses the per-call value when one is given', async () => {
    const session = await managerFor(1_000).open({
      name: 'job', type: 'background', command: 'sleep 1', ttlMs: 0,
    });

    expect(session.ttlMs).toBe(0);
    idleFor(session as BackgroundSession, 60_000);
    expect(session.isExpired()).toBe(false);
  });

  it('falls back to the profile default when the call omits it', async () => {
    const session = await managerFor(1_000).open({ name: 'job', type: 'background', command: 'sleep 1' });

    expect(session.ttlMs).toBe(1_000);
    idleFor(session as BackgroundSession, 2_000);
    expect(session.isExpired()).toBe(true);
  });
});
