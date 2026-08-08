import { describe, it, expect } from 'vitest';
import { CommandQuota } from '../../../src/policy/quota.js';

const HOUR = 60 * 60 * 1000;

describe('CommandQuota', () => {
  it('treats an absent or zero limit as unlimited', () => {
    const q = new CommandQuota();
    for (let i = 0; i < 100; i++) {
      expect(q.consume('dev', 0).allowed).toBe(true);
      expect(q.consume('dev', undefined).allowed).toBe(true);
    }
    // Unlimited calls are not recorded, so they cannot leak into a later limit.
    expect(q.used('dev')).toBe(0);
  });

  it('allows exactly `limit` commands then refuses', () => {
    const q = new CommandQuota();
    for (let i = 0; i < 3; i++) {
      const d = q.consume('dev', 3);
      expect(d.allowed).toBe(true);
      expect(d.remaining).toBe(2 - i);
    }
    const denied = q.consume('dev', 3);
    expect(denied.allowed).toBe(false);
    expect(denied.remaining).toBe(0);
    expect(denied.retryAt).toBeInstanceOf(Date);
  });

  it('counts each profile separately', () => {
    const q = new CommandQuota();
    q.consume('a', 1);
    expect(q.consume('a', 1).allowed).toBe(false);
    expect(q.consume('b', 1).allowed).toBe(true);
  });

  // A refusal that consumed budget would keep pushing the window forward, so a
  // blocked agent could never recover.
  it('does not consume budget on refusal', () => {
    const now = Date.now();
    const q = new CommandQuota();
    q.consume('dev', 1, now);

    const first = q.consume('dev', 1, now + 1000);
    const second = q.consume('dev', 1, now + 2000);
    expect(first.allowed).toBe(false);
    expect(second.allowed).toBe(false);
    // Both refusals report the same reset moment: the original hit ageing out.
    expect(second.retryAt!.getTime()).toBe(first.retryAt!.getTime());
  });

  it('frees budget as commands age out of the window', () => {
    const now = Date.now();
    const q = new CommandQuota();
    q.consume('dev', 2, now);
    q.consume('dev', 2, now + HOUR);
    expect(q.consume('dev', 2, now + 2 * HOUR).allowed).toBe(false);

    // 24h after the first hit, one slot is free again — but not two.
    expect(q.consume('dev', 2, now + 24 * HOUR + 1).allowed).toBe(true);
    expect(q.consume('dev', 2, now + 24 * HOUR + 2).allowed).toBe(false);
  });

  // A calendar-day reset would let an agent spend the full quota just before
  // midnight and the full quota again just after — twice the intended work.
  it('uses a sliding window, not a calendar day', () => {
    const now = Date.now();
    const q = new CommandQuota();
    for (let i = 0; i < 5; i++) q.consume('dev', 5, now + i);
    expect(q.consume('dev', 5, now + 23 * HOUR).allowed).toBe(false);
    expect(q.consume('dev', 5, now + 24 * HOUR + 10).allowed).toBe(true);
  });

  it('reports usage in the current window', () => {
    const now = Date.now();
    const q = new CommandQuota();
    q.consume('dev', 10, now);
    q.consume('dev', 10, now + HOUR);
    expect(q.used('dev', now + 2 * HOUR)).toBe(2);
    expect(q.used('dev', now + 25 * HOUR)).toBe(0);
  });
});
