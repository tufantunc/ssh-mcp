import { describe, it, expect } from 'vitest';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';
import { PolicyEngine } from '../../../src/policy/engine.js';
import { makeProfile } from '../../fixtures/profile.js';
import { atLeast } from '../../property/fc-seed.js';

/**
 * The words between a wrapper and the command it runs can be read more than one
 * way: a flag this file has no table entry for may or may not take the next word
 * as its value, and a privilege prefix's name in a wrapper's operand slot is either
 * that operand or the prefix. The first cut of the wrapper-operand fix chose one
 * reading at each of those points, and each choice lost a command the previous
 * release had refused — the flag value or the operand became the head, and the
 * never-allowed rules never heard the command behind it.
 *
 * The scan now follows every reading and the rules take the strictest: a command
 * is refused, or elevated, if any reading of its words runs something that is.
 */
describe('a wrapper flag whose value is its own word', () => {
  it.each([
    ['env -u takes the variable name', 'env -u HOME rm -rf /'],
    ['env -C takes the directory', 'env -C / rm -rf /'],
    ['env -S takes the split string', 'env -S x rm -rf /'],
    ['strace -u takes the user', 'strace -u root rm -rf /'],
    ['strace -U takes the column list', 'strace -U name rm -rf /'],
    ['ltrace -u takes the user', 'ltrace -u root rm -rf /'],
    ['ionice -c takes the class', 'ionice -c idle rm -rf /'],
    ['flock -E takes the exit code', 'flock -E 1 /tmp/lk rm -rf /'],
    ['flock --conflict-exit-code takes the exit code', 'flock --conflict-exit-code 1 /tmp/lk rm -rf /'],
    ['flock --wait takes the timeout', 'flock --wait 5 /tmp/lk rm -rf /'],
    ['flock --timeout takes the timeout', 'flock --timeout 5 /tmp/lk rm -rf /'],
    ['chroot --groups takes the group list', 'chroot --groups 10 /mnt rm -rf /'],
    ['timeout -s takes the signal', 'timeout -s KILL 1h30m rm -rf /'],
    ['timeout -k takes the grace period', 'timeout -k 5 2m30s rm -rf /'],
  ])('%s, so the command behind it stays refused', (_label, command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
    expect(atLeast(classifyCommand(command).class, 'destructive'), command).toBe(true);
  });

  it.each([
    'env -u X tee /etc/cron.d/x',
    'strace -u root tee /root/.ssh/authorized_keys',
    'env -u X dd if=/dev/zero of=/dev/sda',
    'env -u FOO mkfs.ext4 /dev/sda',
    'env -u FOO iptables -F',
    'env -u FOO chmod -R 777 /',
  ])('%j stays on the never-allowed list', (command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
  });

  it.each([
    'flock --wait 5 /tmp/lk sudo id',
    'flock --timeout 5 /tmp/lk sudo id',
    'flock -E 1 /tmp/lk sudo id',
    'chroot --userspec root /mnt sudo id',
    'chroot --groups wheel /mnt sudo id',
    'chroot -g wheel /mnt sudo id',
    'timeout -s KILL 2m30s sudo id',
    'timeout -k 5 2m30s sudo id',
    'env -u X sudo id',
    'env -C /tmp sudo id',
    'strace -u root sudo id',
    'ionice -c idle sudo id',
  ])('%j is privileged', (command) => {
    expect(classifyCommand(command).class, command).toBe('privileged');
  });
});

describe('a flag the tables do not list', () => {
  // Whether an unlisted flag takes a value is not something the words say. Both
  // readings are followed, so neither guess can hide the command.
  it.each([
    ['a short-option cluster ending in a value flag', 'flock -nw 5 /tmp/lk rm -rf /'],
    ['an abbreviated long option', 'flock --wai 5 /tmp/lk rm -rf /'],
    ['a subcommand option after perf\'s operand', 'perf stat -e cycles rm -rf /'],
  ])('%s does not hide the command', (_label, command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
  });

  it.each([
    'flock --wai 5 /tmp/lk sudo id',
    'timeout --sig KILL 2m30s sudo id',
  ])('%j is privileged', (command) => {
    expect(classifyCommand(command).class, command).toBe('privileged');
  });

  it('treats operands as data only when every reading lands on a reader', () => {
    // One reading has `--foo` take `grep` and runs python3; a reader's operands
    // are data only if no reading runs something else.
    const command = `nohup --foo grep python3 -c 'import os; os.system("id")'`;
    expect(atLeast(classifyCommand(command).class, 'destructive'), command).toBe(true);
  });
});

describe('a wrapper flag spelled like the interpreter\'s own', () => {
  // `xargs -p` and `time -p` take no value, so `node` after them is the command.
  // The carrier scan read it as the value of node's own `-p`, as though the line
  // were `node -p node`, and never looked at the program that follows.
  it.each([
    "xargs -p node -e 'id'",
    "xargs -p node -p 'id'",
    "time -p node -p 'id'",
    "xargs -r php -r 'id'",
  ])('%j is at least destructive', (command) => {
    expect(atLeast(classifyCommand(command).class, 'destructive'), command).toBe(true);
  });

  it('reads the shell program behind the same flag', () => {
    expect(classifyCommand("xargs -p bash -c 'sudo id'").class).toBe('privileged');
  });

  it('still reads an interpreter named as a program flag\'s value as that value', () => {
    expect(classifyCommand("node -e 'console.log(1)' node").class).not.toBe('read-only');
  });
});

describe('a privilege prefix in a wrapper operand slot', () => {
  // Real flock takes `sudo` as the lockfile here and runs `rm -rf /` unprivileged;
  // the previous release read `sudo` as the prefix and refused the same command.
  // Either reading refuses it now.
  it.each([
    'flock sudo rm -rf /',
    'chroot sudo rm -rf /',
  ])('%j stays on the never-allowed list', (command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
  });

  it('keeps the elevation the previous release reported', () => {
    expect(classifyCommand('flock sudo id').class).toBe('privileged');
  });
});

describe('the engine refuses the same words under the default rules', () => {
  const engine = new PolicyEngine();
  const profile = makeProfile({ name: 'p', role: 'operator', group: 'prod', approvalPolicy: 'ask-destructive' });

  it.each([
    'env -u FOO rm -rf /',
    'strace -u root rm -rf /',
    'flock -E 1 /tmp/lk rm -rf /',
    'env -u X dd if=/dev/zero of=/dev/sda',
  ])('%j is denied for an operator on prod', (command) => {
    expect(engine.evaluate(command, profile).decision, command).toBe('deny');
  });
});

describe('command -v and -V run nothing', () => {
  // `command -v NAME` reports whether NAME resolves; it does not run it. Reading
  // past the wrapper made the looked-up name the head, and the never-allowed list
  // refused an existence check no approval could get past.
  it.each([
    'command -v reboot',
    'command -v shutdown',
    'command -V eval',
    'command -pv halt',
    'command -v reboot >/dev/null && echo yes',
  ])('%j is not on the never-allowed list', (command) => {
    expect(findForbiddenMatch(command), command).toBeNull();
  });

  it('still reads past command when it runs what follows', () => {
    expect(findForbiddenMatch('command reboot')).not.toBeNull();
    expect(findForbiddenMatch('command -p reboot')).not.toBeNull();
    expect(classifyCommand('command -p sudo id').class).toBe('privileged');
  });
});

describe('what the readings must not break', () => {
  it('a bare number in the operand slot is the operand, so a mention stays a mention', () => {
    expect(classifyCommand('timeout 5 grep sudo /var/log/auth.log').class).not.toBe('privileged');
    expect(classifyCommand('timeout 5 grep sudo /var/log/auth.log').class).not.toBe('destructive');
  });

  it('a declared flag that takes no value does not swallow the command', () => {
    expect(findForbiddenMatch('xargs -t rm -rf /')).not.toBeNull();
    expect(findForbiddenMatch('xargs -r rm -rf /')).not.toBeNull();
    expect(findForbiddenMatch('flock -u /tmp/lk rm -rf /')).not.toBeNull();
    expect(findForbiddenMatch('strace -c rm -rf /')).not.toBeNull();
    expect(findForbiddenMatch('time -p rm -rf /')).not.toBeNull();
    expect(findForbiddenMatch('setsid -c rm -rf /')).not.toBeNull();
    expect(findForbiddenMatch('ionice -t rm -rf /')).not.toBeNull();
  });

  it('reports the elevated binary as it was spelled', () => {
    expect(classifyCommand('sudo Docker ps').binary).toBe('Docker');
  });

  it('leaves ordinary wrapped readers alone', () => {
    expect(findForbiddenMatch('sudo -E grep reboot /var/log/x')).toBeNull();
    expect(findForbiddenMatch('sudo -i echo rm -rf /')).toBeNull();
    expect(classifyCommand('nice -5 grep sudo /var/log/auth.log').class).toBe('safe');
    expect(classifyCommand('stdbuf -oL grep sudo /var/log/auth.log').class).toBe('safe');
    expect(classifyCommand('flock -xn /tmp/lk grep sudo /var/log/auth.log').class).toBe('safe');
    expect(classifyCommand('strace -f grep sudo /var/log/auth.log').class).toBe('safe');
    expect(classifyCommand('env -i grep sudo /var/log/auth.log').class).toBe('safe');
    expect(classifyCommand('nice -n 10 grep sudo /var/log/auth.log').class).toBe('safe');
    expect(classifyCommand('watch -n 5 grep sudo /var/log/auth.log').class).toBe('safe');
  });
});
