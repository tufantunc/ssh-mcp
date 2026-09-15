import { describe, it, expect } from 'vitest';
import { sanitizeCommand, sanitizeSessionName } from '../../../src/guard/sanitizer.js';

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

  // A line break inside `command` used to be replaced with a space. The
  // replacement is what made it dangerous to be wrong about: two lines joined
  // silently, so `ls\necho x` ran `ls echo x`, and a `#` comment in a
  // `python3 -c` body commented out everything after it. Sometimes that raises;
  // sometimes it runs and quietly does half the work (#198).
  it.each([
    ['a newline', 'ls\necho hi'],
    ['a carriage return', 'ls\recho hi'],
    ['a line separator', 'ls\u2028echo hi'],
    ['a paragraph separator', 'ls\u2029echo hi'],
  ])('refuses %s inside the command rather than rewriting it', (_label, command) => {
    expect(() => sanitizeCommand(command, 1000)).toThrow(/line break/);
  });

  it('names something the caller can do instead', () => {
    expect(() => sanitizeCommand('a\nb', 1000)).toThrow(/sftp-upload/);
  });

  // Trailing and leading breaks are trimmed, not refused: a client that appends
  // a newline works today, and refusing that would break it for no safety gain.
  // Only a break *between* two pieces of command can smuggle a second command.
  it('still accepts a command whose only line break is trailing', () => {
    expect(sanitizeCommand('echo hi\n', 1000)).toBe('echo hi');
    expect(sanitizeCommand('\r\necho hi\r\n', 1000)).toBe('echo hi');
  });

  it('refuses a null byte', () => {
    expect(() => sanitizeCommand('ls\u0000-la', 1000)).toThrow(/null byte/);
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
