import { describe, it, expect } from 'vitest';
import {
  REJECTED_REMOTE_PATH,
  remotePathForAudit,
  sanitizeCommand,
  sanitizeRemotePath,
  sanitizeSessionName,
} from '../../../src/guard/sanitizer.js';

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

describe('the synthetic namespace is reserved', () => {
  it('refuses a caller-typed sftp: or session: command, in every spelling', () => {
    // `classifyOuter` cannot tell a string this server built from one a caller
    // typed — both arrive as text. So giving `sftp:list` a read-only class also
    // taught `read-command` to accept it: measured, a readOnly viewer could send
    // `read-command "sftp:list /tmp sudo id"` and it executed. The command word
    // is resolved the way the classifier resolves it, because the quoted
    // spelling slipped a check on the raw string.
    for (const command of [
      'sftp:list /tmp sudo id',
      "'sftp:list' /tmp",
      '"sftp:download" /etc/shadow',
      String.fromCharCode(92) + 'sftp:list /tmp',
      'session:open interactive s1',
      '  sftp:download /etc/shadow',
      // The prefixes `extractBinary` strips and a first-token helper did not.
      // The first version of this check used its own resolver, and every one of
      // these walked around it: measured, `read-command "-c sftp:download
      // /etc/shadow"` classified `read-only`, was allowed on a readOnly profile
      // that denies it on main, and reached `exec`. Two resolvers answering one
      // question was the bug.
      '-c sftp:list /tmp',
      '-c' + String.fromCharCode(9) + 'sftp:list /tmp',
      "-c 'sftp:list' /tmp",
      '-c "sftp:download" /etc/shadow',
      '; sftp:list /tmp',
      'sudo sftp:list /tmp',
    ]) {
      expect(() => sanitizeCommand(command, 5000), command).toThrow(/reserved/);
    }
  });

  it('leaves a command that merely mentions the namespace alone', () => {
    for (const command of [
      'echo "sftp:list is a string"',
      'grep sftp: /var/log/syslog',
      'ls /tmp',
      'cat /etc/hosts',
      // Words that merely begin with the namespace text, and a URL scheme as an
      // operand. None is a command word in the reserved namespace.
      'curl sftp://host/path',
      'sftp -b - host',
      'sftpx y',
      'sessionctl start',
      'rsync -a a b',
    ]) {
      expect(() => sanitizeCommand(command, 5000), command).not.toThrow();
    }
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
    // Spaces inside a path are legitimate and must survive untouched.
    expect(sanitizeRemotePath('/var/log/my app.log')).toBe('/var/log/my app.log');
    // Relative and Windows spellings are not refused: the remote side decides
    // what an absolute path is, and ssh-mcp drives Windows hosts too.
    expect(sanitizeRemotePath('logs/today.txt')).toBe('logs/today.txt');
    expect(sanitizeRemotePath('C:/Users/me/x.txt')).toBe('C:/Users/me/x.txt');
  });

  it('refuses a non-string and an empty path', () => {
    expect(() => sanitizeRemotePath(42)).toThrow(/must be a string/);
    expect(() => sanitizeRemotePath('')).toThrow(/cannot be empty/);
  });

  it('refuses edge whitespace rather than trimming it away', () => {
    // A POSIX filename may legitimately end in a space, so "report.txt " and
    // "report.txt" are two files. Trimming transferred the second while the
    // approval prompt and the audit record both named... also the second, with
    // nothing anywhere showing the substitution.
    for (const padded of [' /tmp/x', '/tmp/x ', '\t/tmp/x', '/tmp/report.txt  ']) {
      expect(() => sanitizeRemotePath(padded), padded).toThrow(/begin or end with whitespace/);
    }
    expect(() => sanitizeRemotePath('   ')).toThrow(/begin or end with whitespace/);
  });

  it('refuses a null byte, which would truncate the path at the syscall', () => {
    expect(() => sanitizeRemotePath('/tmp/safe' + NUL + '/../../etc/shadow')).toThrow(/control, bidirectional or zero-width/);
  });

  it('refuses a line break, which would forge a second line in the audit record', () => {
    expect(() => sanitizeRemotePath('/tmp/a' + LF + 'sudo id')).toThrow(/control, bidirectional or zero-width/);
    expect(() => sanitizeRemotePath('/tmp/a' + CR + 'x')).toThrow(/control, bidirectional or zero-width/);
    expect(() => sanitizeRemotePath('/tmp/a' + LSEP + 'x')).toThrow(/control, bidirectional or zero-width/);
  });

  it('refuses a bidirectional override, so the prompt cannot show a different path', () => {
    // The classic trick: renders as "...cod.exe", opens "...exe.doc".
    expect(() => sanitizeRemotePath('/tmp/annual' + RLO + 'cod.exe')).toThrow(/control, bidirectional or zero-width/);
    expect(() => sanitizeRemotePath('/tmp/x' + LRI + 'y')).toThrow(/control, bidirectional or zero-width/);
  });

  it('accepts the zero-width joiners, which are orthography and not a spoof', () => {
    // ZWNJ and ZWJ are invisible but meaningful — required in Persian and the
    // Indic scripts, structural inside an emoji sequence. An earlier class swept
    // them up with the rest of U+200B..U+200F and refused real filenames;
    // measured, `/srv/mi<ZWNJ>ravad.txt` is a name a filesystem accepts.
    const ZWNJ = String.fromCharCode(0x200c);
    const ZWJ = String.fromCharCode(0x200d);
    expect(sanitizeRemotePath('/srv/mi' + ZWNJ + 'ravad.txt')).toContain(ZWNJ);
    expect(sanitizeRemotePath('/srv/a' + ZWJ + 'b.txt')).toContain(ZWJ);
  });

  it('refuses the weaker bidi marks and the zero-width formatters too', () => {
    // An earlier class stopped at the overrides and isolates. These reorder
    // *neutral* characters — and a path is mostly neutrals — or render as
    // nothing at all, so two distinct paths print identically.
    const sneaky: [string, number][] = [
      ['ALM', 0x061c], ['LRM', 0x200e], ['RLM', 0x200f],
      ['ZWSP', 0x200b], ['WJ', 0x2060], ['BOM', 0xfeff],
      ['LRE', 0x202a], ['PDF', 0x202c], ['PDI', 0x2069],
    ];
    for (const [name, code] of sneaky) {
      expect(
        () => sanitizeRemotePath('/tmp/a' + String.fromCharCode(code) + 'b'),
        `${name} (U+${code.toString(16)}) survived`,
      ).toThrow(/control, bidirectional or zero-width/);
    }
  });

  it('refuses every C0 and C1 control, not just the three with names', () => {
    for (let code = 0x00; code <= 0x1f; code++) {
      expect(() => sanitizeRemotePath('/tmp/a' + String.fromCharCode(code))).toThrow();
    }
    for (let code = 0x7f; code <= 0x9f; code++) {
      expect(() => sanitizeRemotePath('/tmp/a' + String.fromCharCode(code))).toThrow();
    }
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

describe('remotePathForAudit', () => {
  it('returns the path when it is valid', () => {
    expect(remotePathForAudit('/etc/nginx.conf')).toBe('/etc/nginx.conf');
  });

  it('returns a fixed placeholder instead of throwing, for every refusal', () => {
    // It exists so a refused call still has something to file an audit record
    // under. Building the record from the raw path would put a control
    // character into a hash-chained log; building it from nothing left a client
    // probing the validation boundary invisible to the operator.
    for (const bad of [42, '', '  ', '/tmp/a' + NUL, '/tmp/a' + RLO + 'b', '/' + 'a'.repeat(4096)]) {
      expect(remotePathForAudit(bad)).toBe(REJECTED_REMOTE_PATH);
    }
  });

  it('never returns anything the sanitizer would reject', () => {
    expect(() => sanitizeRemotePath(REJECTED_REMOTE_PATH)).not.toThrow();
  });
});
