import { describe, it, expect } from 'vitest';
import { ApprovalGrants } from '../../../src/guard/approval-grants.js';

describe('ApprovalGrants', () => {
  it('is disabled when the TTL is zero', () => {
    const g = new ApprovalGrants(0);
    expect(g.enabled).toBe(false);
    g.record('dev', 'rm -rf /tmp/x', 'destructive');
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive')).toBe(false);
  });

  it('grants an identical command until the TTL elapses', () => {
    const now = Date.now();
    const g = new ApprovalGrants(5 * 60_000);
    g.record('dev', 'rm -rf /tmp/x', 'destructive', now);

    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 1000)).toBe(true);
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 5 * 60_000 - 1)).toBe(true);
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive', now + 5 * 60_000)).toBe(false);
  });

  // Bound to the exact text: a grant for one path must not cover a longer one
  // that merely starts the same way.
  it('does not widen to a similar command', () => {
    const g = new ApprovalGrants(60_000);
    g.record('dev', 'rm -rf /tmp/build', 'destructive');

    expect(g.has('dev', 'rm -rf /tmp/build', 'destructive')).toBe(true);
    expect(g.has('dev', 'rm -rf /tmp/build-prod', 'destructive')).toBe(false);
    expect(g.has('dev', 'rm -rf /tmp/', 'destructive')).toBe(false);
    expect(g.has('dev', 'rm -rf /tmp/build ', 'destructive')).toBe(false);
  });

  it('does not cross profiles', () => {
    const g = new ApprovalGrants(60_000);
    g.record('dev', 'rm -rf /tmp/x', 'destructive');
    expect(g.has('prod', 'rm -rf /tmp/x', 'destructive')).toBe(false);
  });

  // A command escalating from destructive to privileged is a different
  // decision and must be approved again.
  it('does not cross command classes', () => {
    const g = new ApprovalGrants(60_000);
    g.record('dev', 'systemctl restart nginx', 'destructive');
    expect(g.has('dev', 'systemctl restart nginx', 'privileged')).toBe(false);
  });

  it('clears every grant on demand', () => {
    const g = new ApprovalGrants(60_000);
    g.record('dev', 'rm -rf /tmp/x', 'destructive');
    g.clear();
    expect(g.has('dev', 'rm -rf /tmp/x', 'destructive')).toBe(false);
  });
});
