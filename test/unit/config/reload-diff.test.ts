import { describe, it, expect } from 'vitest';
import {
  CONNECTION_FIELDS,
  SESSION_FIXED_FIELDS,
  POLICY_FIELDS,
  diffProfiles,
  disposition,
  policyRulesChanged,
} from '../../../src/config/reload-diff.js';
import type { AppConfig, Profile } from '../../../src/types.js';

function fullProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'p',
    host: 'h.example',
    port: 22,
    user: 'u',
    auth: 'key',
    keyRef: 'k',
    keychainEntry: 'kc',
    via: 'jump',
    group: 'prod',
    workdir: '/srv',
    trustedHostKey: 'SHA256:abc',
    tty: false,
    timeout: 1000,
    maxChars: 100,
    maxOutputBytes: 1000,
    role: 'operator',
    readOnly: false,
    approvalPolicy: 'auto',
    cert: false,
    announceAgent: true,
    sessionMaxPerConnection: 4,
    sessionIdleTimeoutMs: 1000,
    sessionBackgroundMaxMs: 1000,
    commandQuotaPerDay: 0,
    transferMaxBytes: 1000,
    transferTimeoutMs: 1000,
    ...overrides,
  };
}

describe('field classification', () => {
  it('puts every Profile key in exactly one list, or is name', () => {
    const lists = [CONNECTION_FIELDS, SESSION_FIXED_FIELDS, POLICY_FIELDS];
    for (const key of Object.keys(fullProfile()) as (keyof Profile)[]) {
      if (key === 'name') continue;
      const hits = lists.filter((l) => l.includes(key)).length;
      expect(hits, `field ${key}`).toBe(1);
    }
  });
});

describe('diffProfiles', () => {
  it('detects added, removed and changed, listing only differing keys', () => {
    const prev = [fullProfile({ name: 'a' }), fullProfile({ name: 'b' })];
    const next = [fullProfile({ name: 'b', role: 'admin', workdir: '/x' }), fullProfile({ name: 'c' })];
    const d = diffProfiles(prev, next);
    expect(d.added).toEqual(['c']);
    expect(d.removed).toEqual(['a']);
    expect(d.changed).toHaveLength(1);
    expect(d.changed[0]!.name).toBe('b');
    expect([...d.changed[0]!.fields].sort()).toEqual(['role', 'workdir']);
  });

  it('reports nothing for identical profiles', () => {
    const d = diffProfiles([fullProfile()], [fullProfile()]);
    expect(d).toEqual({ added: [], removed: [], changed: [] });
  });

  it('detects a field going from set to absent', () => {
    const next = fullProfile();
    delete next.via;
    const d = diffProfiles([fullProfile()], [next]);
    expect(d.changed[0]!.fields).toEqual(['via']);
  });
});

describe('disposition', () => {
  it('closes on connection fields, swaps otherwise', () => {
    expect(disposition({ name: 'p', fields: ['role'] })).toBe('swap');
    expect(disposition({ name: 'p', fields: ['user'] })).toBe('close');
    expect(disposition({ name: 'p', fields: ['workdir'] })).toBe('swap');
    expect(disposition({ name: 'p', fields: ['role', 'host'] })).toBe('close');
  });
});

describe('policyRulesChanged', () => {
  const base = (): AppConfig => ({
    defaults: {} as AppConfig['defaults'],
    profiles: [fullProfile()],
  });

  it('is false for identical config', () => {
    expect(policyRulesChanged(base(), base())).toBe(false);
  });

  it('is true when the policy override changes the rules', () => {
    const next = base();
    next.policy = { roleBindings: { operator: { prod: ['read-only'] } } };
    expect(policyRulesChanged(base(), next)).toBe(true);
  });
});
