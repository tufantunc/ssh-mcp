import { describe, it, expect } from 'vitest';
import { sanitizeCommand, sanitizeMetadata, sanitizeSessionName } from '../../../src/guard/sanitizer.js';

describe('sanitizeCommand', () => {
  it('trims whitespace', () => {
    expect(sanitizeCommand('  ls -la  ', 1000)).toBe('ls -la');
  });

  it('rejects empty command', () => {
    expect(() => sanitizeCommand('   ', 1000)).toThrow();
  });

  it('rejects command exceeding maxChars', () => {
    expect(() => sanitizeCommand('a'.repeat(1001), 1000)).toThrow();
  });

  it('rejects non-string input', () => {
    expect(() => sanitizeCommand(null as any, 1000)).toThrow();
  });
});

describe('sanitizeMetadata', () => {
  it('strips newlines (LF)', () => {
    expect(sanitizeMetadata('hello\nworld')).toBe('hello world');
  });

  it('strips carriage returns (CR)', () => {
    expect(sanitizeMetadata('hello\rworld')).toBe('hello world');
  });

  it('strips Unicode line separators', () => {
    expect(sanitizeMetadata('hello\u2028world')).toBe('hello world');
    expect(sanitizeMetadata('hello\u2029world')).toBe('hello world');
  });

  it('strips NUL bytes', () => {
    expect(sanitizeMetadata('hello\x00world')).toBe('hello world');
  });

  it('strips the exact Issue #44 PoC payload', () => {
    const payload = 'benign note\nid > /root/mcp_poc_vuln005.txt';
    const result = sanitizeMetadata(payload);
    expect(result).not.toContain('\n');
    expect(result).toBe('benign note id > /root/mcp_poc_vuln005.txt');
  });

  it('truncates to max length', () => {
    expect(sanitizeMetadata('a'.repeat(200), 100).length).toBe(100);
  });

  it('returns undefined for undefined input', () => {
    expect(sanitizeMetadata(undefined)).toBeUndefined();
  });
});

describe('sanitizeSessionName', () => {
  it('accepts valid names', () => {
    expect(sanitizeSessionName('deploy-1')).toBe('deploy-1');
    expect(sanitizeSessionName('my_session')).toBe('my_session');
  });

  it('rejects names with special characters', () => {
    expect(() => sanitizeSessionName('session;rm -rf')).toThrow();
    expect(() => sanitizeSessionName('session\nname')).toThrow();
  });

  it('rejects names exceeding 64 chars', () => {
    expect(() => sanitizeSessionName('a'.repeat(65))).toThrow();
  });
});
