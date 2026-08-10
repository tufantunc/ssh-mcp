import { describe, it, expect } from 'vitest';
import { resolveHostGroup } from '../../src/index.js';
import { HOST_GROUPS } from '../../src/policy/engine.js';

/**
 * The flag added for #91, where a quick-start profile could never reach the
 * `privileged` class because it had no way to declare a host group.
 *
 * The packaging e2e test drives this through a spawned binary, which proves the
 * wiring but only covers the rejection path — and a spawned process is invisible
 * to coverage. The branching belongs in a unit test: the default decides how
 * safe an unconfigured host is, and the rejection decides whether a typo is
 * caught or silently downgraded.
 */
describe('resolveHostGroup', () => {
  it('defaults to the strictest tier when no group is given', () => {
    // Assuming an unknown host is production is the safe direction; the flag
    // exists to correct the guess, not to loosen the default.
    expect(resolveHostGroup({})).toBe('prod');
    expect(resolveHostGroup({ group: null })).toBe('prod');
  });

  it.each([...HOST_GROUPS])('accepts %s', (group) => {
    expect(resolveHostGroup({ group })).toBe(group);
  });

  // Falling through to the default would apply the prod bindings to a typo, and
  // the operator would read the resulting refusal as policy rather than as
  // their own slip — which is the confusion #91 was made of.
  it.each(['production', 'PROD', 'staging ', 'qa', ''])('rejects %o', (group) => {
    expect(() => resolveHostGroup({ group })).toThrow(/Invalid --group/);
  });

  it('names the valid values in the error, so the fix needs no docs lookup', () => {
    expect(() => resolveHostGroup({ group: 'production' }))
      .toThrow(/Expected one of: prod, staging, dev/);
  });
});
