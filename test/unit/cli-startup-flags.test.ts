import { describe, it, expect } from 'vitest';
import { parseStartupFlags } from '../../src/cli.js';

/**
 * The flags `main()` checks before the config load, and the conditions they are checked
 * under. The ordering itself is asserted end to end in test/e2e/packaging.e2e.test.ts,
 * against a spawned server; this file covers what the function decides.
 */
describe('parseStartupFlags', () => {
  it('returns the host key mode and nothing else when no flag asks for more', () => {
    expect(parseStartupFlags({})).toEqual({ hostKeyMode: 'tofu', opa: undefined, http: undefined });
    expect(parseStartupFlags({ hostKeyMode: 'strict' }).hostKeyMode).toBe('strict');
  });

  it('refuses an invalid --hostKeyMode', () => {
    expect(() => parseStartupFlags({ hostKeyMode: 'strct' })).toThrow('Invalid --hostKeyMode=strct');
  });

  describe('OPA', () => {
    it('parses --opaUrl, --opaTimeoutMs and --opaFailClosed together', () => {
      expect(parseStartupFlags({
        opaUrl: 'http://localhost:8181/',
        opaTimeoutMs: '5000',
        opaFailClosed: null,
      }).opa).toEqual({ url: 'http://localhost:8181', failClosed: true, timeoutMs: 5000 });
    });

    it('refuses a --opaUrl fetch cannot use', () => {
      expect(() => parseStartupFlags({ opaUrl: 'localhost:8181' })).toThrow('--opaUrl must be http or https');
    });

    // A bare `--opaUrl` stores null; reading it for truthiness would drop the flag instead.
    it('refuses a --opaUrl with no value rather than ignoring it', () => {
      expect(() => parseStartupFlags({ opaUrl: null })).toThrow('--opaUrl needs a URL');
    });

    it('refuses an out-of-range --opaTimeoutMs when --opaUrl is set', () => {
      expect(() => parseStartupFlags({ opaUrl: 'http://localhost:8181', opaTimeoutMs: '5' }))
        .toThrow('--opaTimeoutMs must be a whole number');
    });

    it('still ignores --opaTimeoutMs without --opaUrl', () => {
      expect(parseStartupFlags({ opaTimeoutMs: '5' }).opa).toBeUndefined();
    });

    it('refuses --opaFailClosed without --opaUrl', () => {
      expect(() => parseStartupFlags({ opaFailClosed: null }))
        .toThrow('--opaFailClosed does nothing without --opaUrl.');
    });

    it('leaves fail-closed off unless asked', () => {
      expect(parseStartupFlags({ opaUrl: 'http://localhost:8181' }).opa?.failClosed).toBe(false);
    });
  });

  describe('HTTP', () => {
    it('parses --httpSessionTtl and --authFailureLimit under --transport=http', () => {
      expect(parseStartupFlags({ transport: 'http', httpSessionTtl: '60000', authFailureLimit: '0' }).http)
        .toEqual({ sessionIdleTtlMs: 60000, authFailureLimit: 0 });
      expect(parseStartupFlags({ transport: 'http' }).http)
        .toEqual({ sessionIdleTtlMs: undefined, authFailureLimit: undefined });
    });

    it('refuses an invalid --httpSessionTtl under --transport=http', () => {
      expect(() => parseStartupFlags({ transport: 'http', httpSessionTtl: '0' }))
        .toThrow('--httpSessionTtl must be a positive safe integer');
    });

    it('refuses an invalid --authFailureLimit under --transport=http', () => {
      expect(() => parseStartupFlags({ transport: 'http', authFailureLimit: 'off' }))
        .toThrow('--authFailureLimit needs a non-negative whole number');
    });

    // A stdio start never read these, so one left over from an HTTP setup must not stop it.
    it('still ignores the HTTP flags under stdio', () => {
      expect(parseStartupFlags({ httpSessionTtl: '0', authFailureLimit: 'off' }).http).toBeUndefined();
      expect(parseStartupFlags({ transport: 'stdio', httpSessionTtl: '0' }).http).toBeUndefined();
    });
  });
});
