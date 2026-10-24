import { describe, it, expect } from 'vitest';
import { ApprovalGrants } from '../../../src/guard/approval-grants.js';

describe('ApprovalGrants', () => {
  it('is disabled when the TTL is zero', () => {
    const g = new ApprovalGrants(() => 0, () => 0);
    expect(g.enabled).toBe(false);
    g.record('dev', 'rm -rf /tmp/x', 'destructive');
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive')).toBe(false);
  });

  it('grants an identical command until the TTL elapses', () => {
    const now = Date.now();
    const g = new ApprovalGrants(() => 5 * 60_000, () => 0);
    g.record('dev', 'rm -rf /tmp/x', 'destructive', { now });

    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 1000)).toBe(true);
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 5 * 60_000 - 1)).toBe(true);
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 5 * 60_000)).toBe(false);
  });

  // Bound to the exact text: a grant for one path must not cover a longer one
  // that merely starts the same way.
  it('does not widen to a similar command', () => {
    const g = new ApprovalGrants(() => 60_000, () => 0);
    g.record('dev', 'rm -rf /tmp/build', 'destructive');

    expect(g.has('dev', 'rm -rf /tmp/build', 'destructive')).toBe(true);
    expect(g.has('dev', 'rm -rf /tmp/build-prod', 'destructive')).toBe(false);
    expect(g.has('dev', 'rm -rf /tmp/', 'destructive')).toBe(false);
    expect(g.has('dev', 'rm -rf /tmp/build ', 'destructive')).toBe(false);
  });

  it('does not cross profiles', () => {
    const g = new ApprovalGrants(() => 60_000, () => 0);
    g.record('dev', 'rm -rf /tmp/x', 'destructive');
    expect(g.has('prod', 'rm -rf /tmp/x', 'destructive')).toBe(false);
  });

  // A command escalating from destructive to privileged is a different
  // decision and must be approved again.
  it('does not cross command classes', () => {
    const g = new ApprovalGrants(() => 60_000, () => 0);
    g.record('dev', 'systemctl restart nginx', 'destructive');
    expect(g.has('dev', 'systemctl restart nginx', 'privileged')).toBe(false);
  });

  // The key joins its three parts with a separator none of them can contain. With a
  // space, a profile name with a space in it and a command starting with a class word
  // join to the same text as a different triple.
  it('does not let one (profile, class, command) triple stand in for another', () => {
    const g = new ApprovalGrants(() => 60_000, () => 0);
    g.record('a', 'privileged ls', 'destructive');
    expect(g.has('a', 'privileged ls', 'destructive')).toBe(true);
    expect(g.has('a destructive', 'ls', 'privileged')).toBe(false);
  });

  // A reload bumps the generation. A grant given under the old rules must stop
  // counting at once, before anything gets round to clearing it.
  it('does not honour a grant from an older generation', () => {
    let generation = 0;
    const g = new ApprovalGrants(() => 60_000, () => generation);
    g.record('dev', 'rm -rf /tmp/x', 'destructive');
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive')).toBe(true);

    generation = 1;
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive')).toBe(false);

    // Recorded again under the new generation, it counts again.
    g.record('dev', 'rm -rf /tmp/x', 'destructive');
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive')).toBe(true);
  });

  // The pipeline tags a grant with the generation its decision was checked under, which
  // can be older than the current one if a reload lands in between.
  it('does not honour a grant recorded with an explicit older generation', () => {
    const now = Date.now();
    let generation = 1;
    const g = new ApprovalGrants(() => 60_000, () => generation);
    g.record('dev', 'rm -rf /tmp/x', 'destructive', { now, generation: 0 });
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 1)).toBe(false);

    g.record('dev', 'rm -rf /tmp/x', 'destructive', { now, generation: 1 });
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 1)).toBe(true);
    generation = 2;
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 1)).toBe(false);
  });

  // The TTL is read live, so a reload that turns grants on applies to the next record.
  it('reads the TTL at each record', () => {
    const now = Date.now();
    let ttl = 0;
    const g = new ApprovalGrants(() => ttl, () => 0);
    g.record('dev', 'rm -rf /tmp/a', 'destructive', { now });
    expect(g.has('dev', 'rm -rf /tmp/a', 'destructive', now + 1)).toBe(false);

    ttl = 1000;
    g.record('dev', 'rm -rf /tmp/b', 'destructive', { now });
    expect(g.has('dev', 'rm -rf /tmp/a', 'destructive', now + 1)).toBe(false);
    expect(g.has('dev', 'rm -rf /tmp/b', 'destructive', now + 999)).toBe(true);
    expect(g.has('dev', 'rm -rf /tmp/b', 'destructive', now + 1000)).toBe(false);
  });
});
