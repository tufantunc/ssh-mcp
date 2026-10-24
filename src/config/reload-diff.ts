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

export type CloseReason = 'removed' | 'connection-field' | 'bastion-closed';

export interface ReloadPlan {
  diff: ProfileDiff;
  /** Names whose connection closes, each with why, in the order the registry hands them back. */
  closing: Map<string, CloseReason>;
  /** Names in `live`, kept open, whose session-fixed fields changed: only those fields named. */
  sessionFieldsChanged: ProfileChange[];
}

/**
 * What a reload from `prev` to `next` closes and reports, given the names that have a
 * connection open (`live`). Pure: ConnectionRegistry.applyConfig carries it out.
 */
export function planReload(prev: Profile[], next: Profile[], live: Iterable<string>): ReloadPlan {
  const diff = diffProfiles(prev, next);
  const nextNames = new Set(next.map((p) => p.name));
  const liveNames = new Set(live);

  const closing = new Map<string, CloseReason>();
  for (const name of diff.removed) closing.set(name, 'removed');
  for (const name of liveNames) {
    if (!nextNames.has(name)) closing.set(name, 'removed');
  }
  for (const change of diff.changed) {
    if (disposition(change) === 'close') closing.set(change.name, 'connection-field');
  }
  // What runs through a closing bastion closes with it, transitively, over the new via
  // (what a dependent would use). The old via (the hop a live channel runs over) is walked
  // too, as a safeguard: with today's CONNECTION_FIELDS (via among them) and unique names,
  // a profile whose via changed or that was removed is already closing, so it never adds a
  // closing profile beyond what the new via and the diff already close.
  const hops = [...prev, ...next].flatMap((p) => (p.via ? [[p.name, p.via] as const] : []));
  for (let grew = true; grew; ) {
    grew = false;
    for (const [name, via] of hops) {
      if (closing.has(via) && !closing.has(name)) {
        closing.set(name, 'bastion-closed');
        grew = true;
      }
    }
  }

  const sessionFieldsChanged: ProfileChange[] = [];
  for (const change of diff.changed) {
    // Only a profile with an open connection that stays open: a session-fixed change
    // matters only where a session could have fixed it.
    if (closing.has(change.name) || !liveNames.has(change.name)) continue;
    const fields = change.fields.filter((f) => SESSION_FIXED_FIELDS.includes(f));
    if (fields.length > 0) sessionFieldsChanged.push({ name: change.name, fields });
  }

  return { diff, closing, sessionFieldsChanged };
}
