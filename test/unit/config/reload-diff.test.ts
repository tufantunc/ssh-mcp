import { describe, it, expect } from 'vitest';
import {
  CONNECTION_FIELDS,
  SESSION_FIXED_FIELDS,
  POLICY_FIELDS,
  diffProfiles,
  disposition,
  planReload,
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
    outputTruncation: 'head',
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

type FieldClass = 'name' | 'connection' | 'session' | 'policy';

// What a reload does with each Profile field, decided here once and checked against the three
// lists below. A Record, not a sample object: a Record<keyof Profile, …> literal fails typecheck
// for any Profile key added without an entry here (optional ones included) and for any stale key,
// whereas the keys of a hand-written Profile literal silently miss a new optional field.
// `changed` differs from fullProfile()'s value for that field.
const FIELD_CLASS: Record<keyof Profile, { cls: FieldClass; changed: unknown }> = {
  name: { cls: 'name', changed: 'other' },
  host: { cls: 'connection', changed: 'moved.example' },
  port: { cls: 'connection', changed: 2222 },
  user: { cls: 'connection', changed: 'v' },
  auth: { cls: 'connection', changed: 'agent' },
  keyRef: { cls: 'connection', changed: 'k2' },
  keychainEntry: { cls: 'connection', changed: 'kc2' },
  cert: { cls: 'connection', changed: true },
  via: { cls: 'connection', changed: 'jump2' },
  trustedHostKey: { cls: 'connection', changed: 'SHA256:def' },
  workdir: { cls: 'session', changed: '/srv/app' },
  tty: { cls: 'session', changed: true },
  timeout: { cls: 'session', changed: 2000 },
  maxOutputBytes: { cls: 'session', changed: 2000 },
  outputTruncation: { cls: 'session', changed: 'tail' },
  announceAgent: { cls: 'session', changed: false },
  sessionMaxPerConnection: { cls: 'session', changed: 8 },
  sessionIdleTimeoutMs: { cls: 'session', changed: 2000 },
  sessionBackgroundMaxMs: { cls: 'session', changed: 2000 },
  role: { cls: 'policy', changed: 'viewer' },
  group: { cls: 'policy', changed: 'dev' },
  approvalPolicy: { cls: 'policy', changed: 'ask-all' },
  readOnly: { cls: 'policy', changed: true },
  commandQuotaPerDay: { cls: 'policy', changed: 10 },
  maxChars: { cls: 'policy', changed: 200 },
  transferMaxBytes: { cls: 'policy', changed: 2000 },
  transferTimeoutMs: { cls: 'policy', changed: 2000 },
};

const fieldsOf = (cls: FieldClass) =>
  (Object.keys(FIELD_CLASS) as (keyof Profile)[]).filter((k) => FIELD_CLASS[k].cls === cls).sort();

describe('field classification', () => {
  // Pins membership, not just coverage: moving a field from one list to another fails here.
  it.each([
    ['connection', CONNECTION_FIELDS],
    ['session', SESSION_FIXED_FIELDS],
    ['policy', POLICY_FIELDS],
  ] as const)('the %s list holds exactly the fields classed so', (cls, list) => {
    expect([...list].sort()).toEqual(fieldsOf(cls));
  });

  // What each class means to a reload with the profile live: the connection closes, or it
  // stays open and the report names the field, or it stays open and nothing is reported.
  it.each(
    (Object.keys(FIELD_CLASS) as (keyof Profile)[]).filter((k) => k !== 'name'),
  )('reloading a change to %s does what its class says', (field) => {
    const { cls, changed } = FIELD_CLASS[field];
    const next = fullProfile({ [field]: changed });
    const plan = planReload([fullProfile()], [next], ['p']);

    expect(plan.diff.changed).toEqual([{ name: 'p', fields: [field] }]);
    expect([...plan.closing]).toEqual(cls === 'connection' ? [['p', 'connection-field']] : []);
    expect(plan.sessionFieldsChanged).toEqual(
      cls === 'session' ? [{ name: 'p', fields: [field] }] : [],
    );
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

