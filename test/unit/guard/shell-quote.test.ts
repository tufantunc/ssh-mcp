import { describe, it, expect } from 'vitest';
import { shellSingleQuote } from '../../../src/guard/sanitizer.js';

describe('shellSingleQuote', () => {
  it('wraps simple command in single quotes', () => {
    expect(shellSingleQuote('whoami')).toBe("'whoami'");
  });

  it('escapes single quotes in command', () => {
    expect(shellSingleQuote("echo 'hello'")).toBe("'echo '\\''hello'\\'''");
  });

  it('handles multiple single quotes', () => {
    const result = shellSingleQuote("echo 'a'; echo 'b'");
    expect(result).toContain("'\\''");
  });

  it('handles empty string', () => {
    expect(shellSingleQuote('')).toBe("''");
  });

  it('escapes injection attempt safely (single quotes neutralized)', () => {
    const malicious = "'; rm -rf /; echo '";
    const result = shellSingleQuote(malicious);
    // When used as sh -c '...', the escaped string is treated as a literal argument
    // Verify it has the expected escaped form
    expect(result).toMatch(/^'/);
    expect(result).toMatch(/'$/);
    // Single quotes in the original are replaced with '\'' 
    expect(result).toContain("'\\''");
  });

  it('safely wraps backticks inside quotes', () => {
    const malicious = '`whoami`';
    const result = shellSingleQuote(malicious);
    expect(result).toBe("'`whoami`'");
  });

  it('handles newlines safely', () => {
    const malicious = 'hello\nwhoami';
    const result = shellSingleQuote(malicious);
    expect(result).toContain("'hello");
  });
});
