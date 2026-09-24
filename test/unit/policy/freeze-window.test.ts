import { describe, expect, it } from 'vitest';
import { DEFAULT_RULES, PolicyEngine, resolvePolicyRules } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

const profile: Profile = {
  name: 'prod-trading', group: 'prod', host: 'localhost', port: 22, user: 'ops', auth: 'agent',
  tty: false, timeout: 60_000, maxChars: 5_000, maxOutputBytes: 1_048_576,
  role: 'admin', readOnly: false, announceAgent: true, approvalPolicy: 'auto', cert: false,
  sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
  sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
};

function engine(at: string, start = '09:00', end = '15:30'): PolicyEngine {
  return new PolicyEngine({
    ...DEFAULT_RULES,
    freezeWindows: [{ groups: ['prod'], timezone: 'Asia/Shanghai', weekdays: [1, 2, 3, 4, 5], start, end }],
  }, () => new Date(at));
}

describe('deterministic operation freeze windows', () => {
  it('denies non-read-only prod operations inside the window before review', () => {
    const result = engine('2026-09-23T02:00:00Z').evaluate('touch /tmp/x', profile, 'run-command');
    expect(result).toMatchObject({ decision: 'deny', ruleId: 'freeze-window', commandClass: 'safe' });
  });

  it('allows policy evaluation outside the window and for read-only commands', () => {
    expect(engine('2026-09-23T08:00:00Z').evaluate('touch /tmp/x', profile, 'run-command').decision).toBe('allow');
    expect(engine('2026-09-23T02:00:00Z').evaluate('ls -la', profile, 'read-command').decision).toBe('allow');
  });

  it('does not freeze dev/test-tier operations with a prod window', () => {
    for (const group of ['dev', 'test']) {
      const nonProd = { ...profile, name: `${group}-box`, group };
      expect(engine('2026-09-23T02:00:00Z')
        .evaluate('touch /tmp/x', nonProd, 'run-command').decision).toBe('allow');
    }
  });

  it('supports a cross-midnight window using the start-day weekday', () => {
    expect(engine('2026-09-21T14:00:00Z', '21:00', '02:30')
      .evaluate('touch /tmp/x', profile, 'run-command').decision).toBe('deny'); // Monday 22:00
    expect(engine('2026-09-21T17:00:00Z', '21:00', '02:30')
      .evaluate('touch /tmp/x', profile, 'run-command').decision).toBe('deny'); // Tuesday 01:00
    expect(engine('2026-09-21T19:00:00Z', '21:00', '02:30')
      .evaluate('touch /tmp/x', profile, 'run-command').decision).toBe('allow'); // Tuesday 03:00
  });

  it('refuses a configured freeze group that matches no profile', () => {
    expect(() => resolvePolicyRules([profile], {
      freezeWindows: [{
        groups: ['production'], timezone: 'Asia/Shanghai', weekdays: [1],
        start: '09:00', end: '15:30',
      }],
    })).toThrow(/group "production" matches no profile/);
  });
});
