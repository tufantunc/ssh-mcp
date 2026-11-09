import { describe, it, expect } from 'vitest';
import { EventEmitter } from 'node:events';
import type { ClientChannel } from 'ssh2';
import { BackgroundSession } from '../../../src/ssh/session.js';
import { SessionManager, boundedTtl } from '../../../src/ssh/session-manager.js';
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
 *
 * It is also where the per-call value is bounded. The idle timeout is the operator's
 * control and `ttlMs` comes from the agent, whose arguments this server treats as
 * possibly attacker-influenced: a call may shorten the timeout freely, lengthen it only
 * up to a ceiling the operator set — the absolute cap for a background session, the
 * profile's own idle timeout for an interactive one, which has no cap — and never ask
 * for "no idle limit", which only the profile can grant.
 */
describe('SessionManager.open ttlMs', () => {
  let opened: number;
  function managerFor(overrides: { sessionIdleTimeoutMs: number; sessionBackgroundMaxMs?: number }): SessionManager {
    opened = 0;
    return new SessionManager({
      profile: () => makeProfile(overrides),
      openShell: async () => { opened++; return fakeChannel(); },
      openExec: async () => { opened++; return fakeChannel(); },
      onChannelOpened: () => {},
      onChannelClosed: () => {},
    });
  }
  const background = (ttlMs?: number) => ({ name: 'job', type: 'background' as const, command: 'sleep 1', ttlMs });
  const interactive = (ttlMs?: number) => ({ name: 'sh', type: 'interactive' as const, ttlMs });

  it('falls back to the profile default when the call omits it', async () => {
    const session = await managerFor({ sessionIdleTimeoutMs: 1_000 }).open(background());

    expect(session.ttlMs).toBe(1_000);
    idleFor(session as BackgroundSession, 2_000);
    expect(session.isExpired()).toBe(true);
  });

  it('lets a call shorten the idle timeout', async () => {
    const session = await managerFor({ sessionIdleTimeoutMs: 600_000 }).open(background(1_000));
    expect(session.ttlMs).toBe(1_000);
  });

  it('lets a background session run idle up to its absolute cap, and no further', async () => {
    const manager = managerFor({ sessionIdleTimeoutMs: 600_000, sessionBackgroundMaxMs: 3_600_000 });
    expect((await manager.open(background(3_600_000))).ttlMs).toBe(3_600_000);

    const over = managerFor({ sessionIdleTimeoutMs: 600_000, sessionBackgroundMaxMs: 3_600_000 });
    await expect(over.open(background(3_600_001))).rejects.toThrow(/3600000/);
    expect(opened, 'a refused session must not open a channel').toBe(0);
  });

  it('holds an interactive session to the profile idle timeout, since it has no absolute cap', async () => {
    const manager = managerFor({ sessionIdleTimeoutMs: 600_000, sessionBackgroundMaxMs: 3_600_000 });
    await expect(manager.open(interactive(600_001))).rejects.toThrow(/600000/);
    expect(opened).toBe(0);
  });

  it('falls back to the idle timeout as the ceiling when the background cap is off', async () => {
    // Turning the absolute cap off does not turn the idle timeout off: without this, a
    // huge ttlMs against "no cap" was "no idle limit" by another spelling.
    const capOff = managerFor({ sessionIdleTimeoutMs: 600_000, sessionBackgroundMaxMs: 0 });
    await expect(capOff.open(background(Number.MAX_SAFE_INTEGER))).rejects.toThrow(/600000/);
    expect(opened).toBe(0);
    expect((await capOff.open(background(600_000))).ttlMs).toBe(600_000);
  });

  it('has no ceiling where the operator turned the ceiling it lands on off', async () => {
    const noLimits = managerFor({ sessionIdleTimeoutMs: 0, sessionBackgroundMaxMs: 0 });
    expect((await noLimits.open(background(86_400_000))).ttlMs).toBe(86_400_000);
    // Interactive, through the bound itself: opening one needs a shell handshake this
    // fake channel cannot answer.
    expect(boundedTtl(86_400_000, 'interactive', makeProfile({ sessionIdleTimeoutMs: 0 }))).toBe(86_400_000);
  });

  it.each([0, -1])('refuses ttlMs %d from a call: "no idle limit" is the profile\'s to grant', async (ttlMs) => {
    const manager = managerFor({ sessionIdleTimeoutMs: 600_000 });
    await expect(manager.open(background(ttlMs))).rejects.toThrow(/positive/);
    expect(opened).toBe(0);
  });
});
