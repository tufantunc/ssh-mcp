import { describe, it, expect } from 'vitest';
import {
  CONNECTION_FIELDS,
  SESSION_FIXED_FIELDS,
  POLICY_FIELDS,
  diffProfiles,
  disposition,
} from '../../../src/config/reload-diff.js';
import type { Profile } from '../../../src/types.js';

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

// A Record, not a sample object: a Record<keyof Profile, true> literal fails typecheck for
// any Profile key added without an entry here (optional ones included) and for any stale key,
// whereas the keys of a hand-written Profile literal silently miss a new optional field.
const ALL_PROFILE_KEYS: Record<keyof Profile, true> = {
  name: true,
  host: true,
  port: true,
  user: true,
  auth: true,
  keyRef: true,
  keychainEntry: true,
  via: true,
  group: true,
  workdir: true,
  trustedHostKey: true,
  tty: true,
  timeout: true,
  maxChars: true,
  maxOutputBytes: true,
  role: true,
  readOnly: true,
  approvalPolicy: true,
  cert: true,
  announceAgent: true,
  sessionMaxPerConnection: true,
  sessionIdleTimeoutMs: true,
  sessionBackgroundMaxMs: true,
  commandQuotaPerDay: true,
  transferMaxBytes: true,
  transferTimeoutMs: true,
};

describe('field classification', () => {
  it('puts every Profile key in exactly one list, or is name', () => {
    const lists = [CONNECTION_FIELDS, SESSION_FIXED_FIELDS, POLICY_FIELDS];
    const classified = lists.flat();
    expect(new Set(classified).size, 'a field is in two lists').toBe(classified.length);
    expect([...classified, 'name'].sort()).toEqual(Object.keys(ALL_PROFILE_KEYS).sort());
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

