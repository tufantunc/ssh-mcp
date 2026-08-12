import { describe, it, expect } from 'vitest';
import { flagEnabled, resolveHostKeyMode } from '../../src/index.js';

/**
 * Every documented boolean flag is written bare — `--disableApproval`, not
 * `--disableApproval=1`. `parseArgv` stores `null` for that form, and three
 * call sites tested it for truthiness, so the flags did nothing at all (#91).
 *
 * The reporter's words were "--disableApproval doesnt work for me". It did not
 * work for anyone. The two audit flags are the worse half: someone who turned
 * on hash-chained tamper-evident logging ran without it and had no signal.
 *
 * These tests exist because the failure was silent in both directions — the
 * flag produced no error and the feature produced no output.
 */
describe('flagEnabled', () => {
  it('treats a bare flag as on, which is how they are documented', () => {
    expect(flagEnabled({ disableApproval: null }, 'disableApproval')).toBe(true);
    expect(flagEnabled({ auditTamperEvident: null }, 'auditTamperEvident')).toBe(true);
  });

  it('is off when absent', () => {
    expect(flagEnabled({}, 'disableApproval')).toBe(false);
    expect(flagEnabled({ other: null }, 'disableApproval')).toBe(false);
  });

  it.each(['1', 'true', 'yes', 'on', 'anything'])('accepts =%s as on', (value) => {
    expect(flagEnabled({ f: value }, 'f')).toBe(true);
  });

  it.each(['false', 'FALSE', '0', 'no', 'off'])('accepts =%s as off', (value) => {
    // A flag baked into a wrapper script needs a way back off without editing
    // the script.
    expect(flagEnabled({ f: value }, 'f')).toBe(false);
  });

  it('treats an empty value as on', () => {
    // `--flag=` is a slip, not an intent to disable; on matches the bare form.
    expect(flagEnabled({ f: '' }, 'f')).toBe(true);
  });
});

describe('boolean flags reach their call sites', () => {
  /**
   * The regression that matters: not that flagEnabled is correct in isolation,
   * but that the flags are wired through it. A unit test of the helper alone
   * would have passed against the broken code.
   */
  it('--insecureHostKey selects insecure mode when written bare', () => {
    expect(resolveHostKeyMode({ insecureHostKey: null })).toBe('insecure');
    expect(resolveHostKeyMode({})).toBe('tofu');
    // And can be turned back off, unlike before.
    expect(resolveHostKeyMode({ insecureHostKey: 'false' })).toBe('tofu');
  });
});
