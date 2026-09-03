import { describe, it, expect } from 'vitest';
import { sanitizeCommand, sanitizeRemotePath, sanitizeSessionName } from '../../../src/guard/sanitizer.js';

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

describe('sanitizeRemotePath', () => {
  it('preserves ordinary paths and shell metacharacters as literal SFTP operands', () => {
    expect(sanitizeRemotePath('/tmp/a; sudo id')).toBe('/tmp/a; sudo id');
  });

  it.each(['', '   ', '/tmp/a\nb', '/tmp/a\rb', '/tmp/a\0b'])('rejects unsafe path %j', (path) => {
    expect(() => sanitizeRemotePath(path)).toThrow();
  });
});
