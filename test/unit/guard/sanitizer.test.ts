import { describe, it, expect } from 'vitest';
import { sanitizeCommand, sanitizeRemotePath, sanitizeSessionName } from '../../../src/guard/sanitizer.js';

const NUL = String.fromCharCode(0);
const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);
const LSEP = String.fromCharCode(0x2028);
const RLO = String.fromCharCode(0x202e);
const LRI = String.fromCharCode(0x2066);

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

describe('sanitizeRemotePath', () => {
  it('accepts the paths a remote host actually has', () => {
    expect(sanitizeRemotePath('/etc/nginx/nginx.conf')).toBe('/etc/nginx/nginx.conf');
    // Spaces inside a path are legitimate and must survive; only the ends trim.
    expect(sanitizeRemotePath('  /var/log/my app.log  ')).toBe('/var/log/my app.log');
    // Relative and Windows spellings are not refused: the remote side decides
    // what an absolute path is, and ssh-mcp drives Windows hosts too.
    expect(sanitizeRemotePath('logs/today.txt')).toBe('logs/today.txt');
    expect(sanitizeRemotePath('C:/Users/me/x.txt')).toBe('C:/Users/me/x.txt');
  });

  it('refuses a non-string, an empty path and a whitespace-only one', () => {
    expect(() => sanitizeRemotePath(42)).toThrow(/must be a string/);
    expect(() => sanitizeRemotePath('')).toThrow(/cannot be empty/);
    expect(() => sanitizeRemotePath('   ')).toThrow(/cannot be empty/);
  });

  it('refuses a null byte, which would truncate the path at the syscall', () => {
    expect(() => sanitizeRemotePath('/tmp/safe' + NUL + '/../../etc/shadow')).toThrow(/control or bidirectional/);
  });

  it('refuses a line break, which would forge a second line in the audit record', () => {
    expect(() => sanitizeRemotePath('/tmp/a' + LF + 'sudo id')).toThrow(/control or bidirectional/);
    expect(() => sanitizeRemotePath('/tmp/a' + CR + 'x')).toThrow(/control or bidirectional/);
    expect(() => sanitizeRemotePath('/tmp/a' + LSEP + 'x')).toThrow(/control or bidirectional/);
  });

  it('refuses a bidirectional override, so the prompt cannot show a different path', () => {
    // The classic trick: renders as "...cod.exe", opens "...exe.doc".
    expect(() => sanitizeRemotePath('/tmp/annual' + RLO + 'cod.exe')).toThrow(/control or bidirectional/);
    expect(() => sanitizeRemotePath('/tmp/x' + LRI + 'y')).toThrow(/control or bidirectional/);
  });

  it('refuses a path longer than any filesystem accepts', () => {
    expect(sanitizeRemotePath('/' + 'a'.repeat(4095))).toHaveLength(4096);
    expect(() => sanitizeRemotePath('/' + 'a'.repeat(4096))).toThrow(/too long/);
  });

  it('leaves shell metacharacters alone, because the classifier raises on them', () => {
    // Not an oversight: classifyCommand reads the synthetic string and takes
    // the higher of the outer and carried classes, so this reaches policy as
    // privileged and is refused there rather than passing as destructive.
    expect(sanitizeRemotePath('/tmp/x; sudo id')).toBe('/tmp/x; sudo id');
  });
});
