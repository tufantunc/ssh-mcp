import { isDeepStrictEqual } from 'node:util';
import type { Profile } from '../types.js';

/** Changing any of these invalidates the live connection: close it and its sessions. */
export const CONNECTION_FIELDS: readonly (keyof Profile)[] = [
  'host',
  'port',
  'user',
  'auth',
  'keyRef',
  'keychainEntry',
  'cert',
  'via',
  'trustedHostKey',
];

/** Fixed when a session opens: the connection survives, the change is reported by name. */
export const SESSION_FIXED_FIELDS: readonly (keyof Profile)[] = [
  'workdir',
  'tty',
  'timeout',
  'maxOutputBytes',
  'announceAgent',
  'sessionMaxPerConnection',
  'sessionIdleTimeoutMs',
  'sessionBackgroundMaxMs',
];

/** Read per command: swapping the profile in place takes effect immediately. */
export const POLICY_FIELDS: readonly (keyof Profile)[] = [
  'role',
  'group',
  'approvalPolicy',
  'readOnly',
  'commandQuotaPerDay',
  'maxChars',
  'transferMaxBytes',
  'transferTimeoutMs',
];

export interface ProfileChange {
  name: string;
  fields: (keyof Profile)[];
}

export interface ProfileDiff {
  added: string[];
  removed: string[];
  changed: ProfileChange[];
}

export function diffProfiles(prev: Profile[], next: Profile[]): ProfileDiff {
  const prevByName = new Map(prev.map((p) => [p.name, p]));
  const nextByName = new Map(next.map((p) => [p.name, p]));
  const added = next.filter((p) => !prevByName.has(p.name)).map((p) => p.name);
  const removed = prev.filter((p) => !nextByName.has(p.name)).map((p) => p.name);
  const changed: ProfileChange[] = [];
  for (const after of next) {
    const before = prevByName.get(after.name);
    if (!before) continue;
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]) as Set<keyof Profile>;
    const fields = [...keys].filter(
      (k) => k !== 'name' && !isDeepStrictEqual(before[k], after[k]),
    );
    if (fields.length > 0) changed.push({ name: after.name, fields });
  }
  return { added, removed, changed };
}

export function disposition(change: ProfileChange): 'close' | 'swap' {
  return change.fields.some((f) => CONNECTION_FIELDS.includes(f)) ? 'close' : 'swap';
}
