import { describe, it, expect } from 'vitest';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';
import { atLeast } from '../../property/fc-seed.js';

/**
 * A command word can name the same binary in several spellings: `sudo`,
 * `/usr/bin/sudo`, `SUDO`, `sudo.exe`, `C:\Windows\System32\sudo.exe`. The
 * tokeniser strips the directory part, but the tables that decide elevation,
 * wrapping and the never-allowed rules matched the remainder exactly, so the
 * suffix- and case-folded spellings — what a Windows target's own shell hands
 * back, and what a case-insensitive filesystem resolves — named nothing.
 * `sudo.exe id` classified `safe`, and `rm.exe -rf /`, `iptables.exe -F` and
 * `shutdown.exe /s` never reached the rules that refuse their bare names.
 *
 * The interpreter, carrier and broker tables already folded their keys
 * (`resolveInterpreter`); the prefix, wrapper, multiplexer,
 * forbidden-invocation and segment-rule tables now read the same folded name.
 */
describe('a folded command word names the same command', () => {
  it.each([
    ['sudo with an exe suffix', 'sudo.exe id'],
    ['sudo upper-cased', 'SUDO id'],
    ['sudo with a mixed suffix', 'sudo.EXE id'],
    ['wrapper with an exe suffix', 'env.exe sudo id'],
    ['wrapper upper-cased', 'env.EXE sudo id'],
    ['nohup with an exe suffix', 'nohup.exe sudo id'],
    ['tracing wrapper with an exe suffix', 'strace.exe sudo id'],
    ['busybox with an exe suffix', 'busybox.exe sudo id'],
  ])('%s is privileged, not safe', (_label, command) => {
    expect(classifyCommand(command).class, command).toBe('privileged');
  });
});

describe('folded spellings reach the never-allowed rules', () => {
  it.each([
    ['power-state invocation', 'shutdown.exe /s'],
    ['power-state invocation, full Windows path', 'C:\\Windows\\System32\\shutdown.exe /s'],
    ['reboot', 'reboot.exe'],
    ['halt with a flag', 'halt.exe -f'],
    ['poweroff', 'poweroff.exe'],
    ['eval', 'eval.exe sudo id'],
    ['multiplexer subcommand', 'systemctl.exe reboot'],
    ['multiplexer upper-cased', 'SYSTEMCTL reboot'],
    ['rm against the root', 'rm.exe -rf /'],
    ['firewall flush', 'iptables.exe -F'],
    ['world-writable root', 'chmod.exe -R 777 /'],
    ['root chown', 'chown.exe -R a:a /'],
    ['dd onto a device', 'dd.exe of=/dev/sda'],
    ['nft flush', 'nft.exe flush ruleset'],
    ['a copy onto authorized_keys', 'cp.exe /tmp/a /root/.ssh/authorized_keys'],
    ['dd writing authorized_keys', 'dd.exe if=x of=/root/.ssh/authorized_keys'],
    ['a move into cron.d', 'mv.exe x /etc/cron.d/y'],
    ['a device formatter upper-cased', 'MKFS.ext4 /dev/sdb1'],
    ['a device wiper upper-cased', 'WIPEFS -a /dev/sda'],
    ['a multiplexer operand with an exe suffix', 'systemctl reboot.exe'],
  ])('%s is refused and destructive', (_label, command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
    expect(atLeast(classifyCommand(command).class, 'destructive'), command).toBe(true);
  });

  it.each([
    ['a folded wrapper in front of a power-state command', 'env.exe shutdown -h now'],
    ['a folded wrapper in front of reboot', 'nohup.exe reboot'],
    ['a folded operand wrapper in front of rm', 'flock.exe /tmp/lk rm -rf /'],
    ['a folded wrapper with an assignment', 'env.exe A=1 rm -rf /'],
    ['an upper-cased prefix in front of rm', 'SUDO rm -rf /'],
    ['a folded prefix in front of reboot', 'sudo.exe reboot'],
  ])('%s keeps the refusal of what it wraps', (_label, command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
  });

  it.each([
    ['find -delete', 'find.exe / -delete'],
    ['sort -o', 'sort.exe -o /root/.ssh/authorized_keys /tmp/k'],
    ['rm against an absolute path', 'rm.exe -rf /srv/cache'],
    ['rm upper-cased against an absolute path', 'RM -rf /srv/cache'],
    ['an awk program writing a file', `AWK '{print > "/etc/x"}' f`],
    ['an awk program read from a file', 'awk.exe -f /tmp/p.awk'],
  ])('%s is destructive', (_label, command) => {
    expect(atLeast(classifyCommand(command).class, 'destructive'), command).toBe(true);
  });

  it('reads an awk program behind a folded name', () => {
    expect(classifyCommand(`awk.exe 'BEGIN{system("sudo id")}'`).class).toBe('privileged');
  });
});

describe('what the fix must not break', () => {
  it('leaves plain commands and ordinary readers where they were', () => {
    expect(classifyCommand('ls -la').class).toBe('read-only');
    expect(classifyCommand('sudo id').class).toBe('privileged');
    expect(classifyCommand('echo hi').class).toBe('read-only');
    // An unlisted name stays unlisted: folding resolves spellings of a name,
    // it does not add names. `LS` is not a reader on a case-sensitive host and
    // keeps the class the allowlist gives it there.
    expect(classifyCommand('LS -la').class).toBe('safe');
  });

  it('does not turn a mention into an invocation', () => {
    expect(classifyCommand('grep sudo.exe /var/log/x').class).toBe('read-only');
    expect(findForbiddenMatch('journalctl | grep reboot.exe')).toBeNull();
  });
});
