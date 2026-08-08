import { describe, it, expect } from 'vitest';
import { checkRemovedFlags, parseMaxChars } from '../../src/index.js';

describe('checkRemovedFlags', () => {
  // Removed v1 credential flags used to be swallowed silently, so an upgraded
  // install failed later as an opaque auth error instead of at startup.
  it.each([
    ['password', /SSH_MCP_PASSWORD/],
    ['suPassword', /SSH_MCP_SUDO_PASSWORD/],
    ['sudoPassword', /SSH_MCP_SUDO_PASSWORD/],
    ['disableSudo', /privileged/],
  ])('rejects --%s with its replacement', (flag, hint) => {
    expect(() => checkRemovedFlags({ [flag]: 'x' })).toThrow(hint);
    expect(() => checkRemovedFlags({ [flag]: 'x' })).toThrow(/removed in v2/);
  });

  it('reports every removed flag at once', () => {
    try {
      checkRemovedFlags({ password: 'a', disableSudo: null });
      throw new Error('should have thrown');
    } catch (err) {
      expect(String(err)).toContain('--password');
      expect(String(err)).toContain('--disableSudo');
    }
  });

  it('accepts a v2-only flag set', () => {
    expect(() => checkRemovedFlags({ host: 'h', user: 'u', transport: 'stdio' })).not.toThrow();
  });
});

describe('parseMaxChars', () => {
  it('keeps v1 "no limit" semantics', () => {
    // v1 documented none/0/negative as unlimited; `parseInt(x) || 5000`
    // silently turned all three into a 5000-char cap.
    expect(parseMaxChars('none')).toBe(Number.MAX_SAFE_INTEGER);
    expect(parseMaxChars('NONE')).toBe(Number.MAX_SAFE_INTEGER);
    expect(parseMaxChars('0')).toBe(Number.MAX_SAFE_INTEGER);
    expect(parseMaxChars('-1')).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('honours an explicit positive limit', () => {
    expect(parseMaxChars('1234')).toBe(1234);
  });

  it('falls back to the default for absent or unparseable values', () => {
    expect(parseMaxChars(undefined)).toBe(5000);
    expect(parseMaxChars(null)).toBe(5000);
    expect(parseMaxChars('')).toBe(5000);
    expect(parseMaxChars('abc')).toBe(5000);
  });
});
