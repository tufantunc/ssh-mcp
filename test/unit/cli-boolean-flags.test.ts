import { describe, it, expect } from 'vitest';
import { flagEnabled, resolveHostKeyMode } from '../../src/cli.js';

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

/**
 * `--authFailureLimit` guards a control that is on by default, so a value it cannot read
 * has to be refused rather than quietly turning the control off — the trap `flagEnabled`
 * exists for, on a numeric flag.
 */
describe('parseFailureLimit', () => {
  it('accepts a non-negative whole number, and 0 as "off"', async () => {
    const { parseFailureLimit } = await import('../../src/cli.js');
    expect(parseFailureLimit('10')).toBe(10);
    expect(parseFailureLimit('0')).toBe(0);
    expect(parseFailureLimit(' 5 ')).toBe(5);
    expect(parseFailureLimit('007')).toBe(7);
    // Absent means "use the default", and nothing else may.
    expect(parseFailureLimit(undefined)).toBeUndefined();
  });

  it.each([null, '', 'abc', '-1', '+5', '1e3', '10.5', 'off', 'NaN'])(
    'refuses %j rather than disabling the check',
    async (raw) => {
      const { parseFailureLimit } = await import('../../src/cli.js');
      // `parseArgv` stores null for a flag written without `=`, and NaN survives `??`,
      // so the old code turned the throttle off for every one of these.
      expect(() => parseFailureLimit(raw as any)).toThrow(/authFailureLimit/);
    },
  );

  it.each(['10001', '99999999999999999999', '9007199254740993'])(
    'refuses %s, because an unbounded limit is the same fail-open',
    async (raw) => {
      // 1e20 is a bucket that never empties and a Retry-After of 1: configured on,
      // functionally absent.
      const { parseFailureLimit } = await import('../../src/cli.js');
      expect(() => parseFailureLimit(raw)).toThrow(/between 0 and/);
    },
  );
});

/**
 * `--opaUrl` was checked only for emptiness, so anything `fetch` cannot use reached the
 * engine and failed on every request — with `OPA sidecar enabled` on stdout and one stderr
 * line a minute as the only signal that the gate was never consulted.
 */
describe('parseOpaUrl', () => {
  it.each([
    ['http://localhost:8181', 'http://localhost:8181'],
    ['https://opa:8181/base', 'https://opa:8181/base'],
    // A trailing slash would make the request path `//v1/data/...`.
    ['http://opa:8181/', 'http://opa:8181'],
  ])('accepts %s', async (raw, expected) => {
    const { parseOpaUrl } = await import('../../src/cli.js');
    expect(parseOpaUrl(raw)).toBe(expected);
  });

  it.each(['opa.internal:8181', 'localhost:8181', 'not a url', '/v1/data', 'ftp://x', '', null])(
    'refuses %j at startup rather than at every request',
    async (raw) => {
      // `--opaUrl=localhost:8181` is a realistic slip: OPA's own `--addr` is `:8181`.
      const { parseOpaUrl } = await import('../../src/cli.js');
      expect(() => parseOpaUrl(raw as any)).toThrow(/opaUrl/);
    },
  );

  it('refuses credentials in the URL, which fetch cannot use at all', async () => {
    const { parseOpaUrl } = await import('../../src/cli.js');
    expect(() => parseOpaUrl('http://opa-admin:s3cr3t@opa.internal:8181'))
      .toThrow(/must not embed credentials/);
  });
});
