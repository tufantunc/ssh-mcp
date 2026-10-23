import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../../../src/policy/classifier.js';
import { PolicyEngine } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

/**
 * GHSA-5cjr-rc2p-f66f: the never-allowed rules were regexes over literal
 * command text, so they matched one spelling of an operation and nothing else.
 * `rm -rf /` was refused outright while `rm -fr /`, `rm -r -f /`, `rm
 * --recursive --force /` and `rm -R -f /` classified `safe` — the one class
 * the default `ask-destructive` policy never prompts on — and executed with
 * no approval at all. `mkfs -t ext4 /dev/sda1` escaped `/mkfs\./` the same
 * way. The same fragility sat in the firewall and world-writable-root
 * patterns, in `chownsRoot`'s `-R`-only reading, and in the destructive floor
 * `rm -rf? /…` regex.
 *
 * The rules now read the operation through the tokeniser: the flag in any
 * spelling a getopt-parsed binary accepts — short clusters in either order
 * (`-rf`, `-fr`, `-Rf`), separated flags (`-r -f`), long forms
 * (`--recursive`) — with rm taking `-r`/`-R` and chmod/chown only `-R`,
 * lowercase `-r` being a mode operation there.
 */
describe('never-allowed spellings (GHSA-5cjr-rc2p-f66f)', () => {
  const engine = new PolicyEngine();
  const profile = {
    name: 'p', role: 'operator', group: 'prod',
    approvalPolicy: 'ask-destructive', readOnly: false,
  } as unknown as Profile;

  it.each([
    'rm -rf /', 'rm -fr /', 'rm -r -f /', 'rm -f -r /', 'rm --recursive --force /',
    'rm -R -f /', 'rm -Rf /', 'rm -r /', 'rm --recursive /', 'rm -rf "/"',
    'rm -rf //', 'rm -rf -- /', 'rm -rf /.', 'rm -rf ///', 'rm -rf /etc/..',
    'mkfs.ext4 /dev/sda1', 'mkfs -t ext4 /dev/sda1', 'mkfs.vfat /dev/sdb1', 'mkfs /dev/sda1',
    'mke2fs /dev/sda1', 'mkswap /dev/sda1', 'wipefs -a /dev/sda1',
    'chmod -R 777 /', 'chmod 777 -R /', 'chmod -R 0777 /', 'chmod -R 777 //',
    'chmod -R 777 /.', 'chmod -R 777 /etc/..', 'chmod -R 777 /etc',
    'chmod -R a+rwx /', 'chmod -R +w /', 'chmod -R ugo+rwx /', 'chmod -R 7777 /', 'chmod -R 666 /etc',
    'iptables -F', 'iptables --flush', 'ip6tables -F', 'ip6tables --flush',
    'iptables -P INPUT ACCEPT', 'nft flush ruleset',
    'chown -R app:app /', 'chown --recursive app:app /', 'chown -Rh app:app /', 'chown -R app:app //',
    'chown -R app:app /etc/..',
    // A wrapper in front of the same operations — and the carrier path the
    // forbidden scan reaches the rules through. The wrapper's OWN operand
    // (flock's lockfile, chroot's directory, taskset's mask, strace's -o
    // value, perf's subcommand) must not be read as the command: the review
    // round measured `flock /tmp/lk rm -rf /` walking past every rule.
    'env rm -fr /', 'timeout 5 rm -fr /', "sh -c 'rm -fr /'",
    'flock /tmp/lk rm -rf /', 'flock -x /tmp/lk mkfs.ext4 /dev/sda1',
    'chroot /mnt rm -rf /', 'taskset 0x1 rm -rf /', 'perf record rm -rf /',
    'strace -o /tmp/t rm -rf /',
  ])('%j is denied by the never-allowed list, not merely by role', (command) => {
    const evaluation = engine.evaluate(command, profile);
    expect(evaluation.decision, command).toBe('deny');
    expect(evaluation.ruleId, command).toBe('denylist');
    expect(evaluation.commandClass, command).toBe('destructive');
  });

  it('elevation in front of the same operation still names the never-allowed rule', () => {
    // `sudo rm -fr /` is the one spelling whose class is `privileged` — the
    // elevation names the binary that runs as root — but the refusal is the
    // denylist's, not the role's: never-allowed outranks everything.
    const evaluation = engine.evaluate('sudo rm -fr /', profile);
    expect(evaluation.decision).toBe('deny');
    expect(evaluation.commandClass).toBe('privileged');
    expect(evaluation.ruleId).toBe('denylist');
  });

  it('the recursive-rm destructive floor holds across the same spellings', () => {
    // The class floor below the refusal: recursive rm against any absolute
    // path. `rm -r /tmp/build` already made it; `rm -fr /tmp/build` fell to
    // `safe` before this fix.
    for (const command of [
      'rm -rf /tmp/build', 'rm -fr /tmp/build', 'rm -r -f /tmp/build',
      'rm --recursive /tmp/build', 'rm -Rf /tmp/build',
    ]) {
      expect(classifyCommand(command).class, command).toBe('destructive');
    }
  });

  it('the operations they neighbour stay as they were', () => {
    for (const [command, expected] of [
      // Ordinary recursive operations on ordinary paths.
      ['rm -r /tmp/build', 'destructive'],
      ['chown -R app:app /srv/app', 'safe'],
      // Modes without the world-write bit, and grants without other.
      ['chmod -R 755 /', 'safe'],
      ['chmod -R u+w /etc', 'safe'],
      // Reading the firewall, not opening it.
      ['iptables -L', 'safe'],
      ['iptables -P INPUT DROP', 'safe'],
      // Lowercase -r is a mode operation for chmod and chown, not recursion —
      // the per-binary letter restriction is deliberate and pinned.
      ['chmod -r 777 /', 'safe'],
      ['chown -r app:app /', 'safe'],
      // A mention is not an invocation — the rules are head-gated, and the
      // old text regexes' substring denials of these were the looseness this
      // change removes on purpose (#91 direction).
      ["echo 'rm -rf /'", 'read-only'],
      ['grep -e "mkfs.ext4 /dev/sda1" notes.txt', 'read-only'],
      ['cat /usr/bin/rm', 'read-only'],
      // git rm removes from a worktree, not the filesystem; treating the
      // embedded `rm -r /…` as data rather than the command is the same
      // mention-vs-invocation line (the old floor regex caught it by
      // substring).
      ['git rm -r /tmp/x', 'safe'],
    ] as const) {
      const parsed = classifyCommand(command);
      expect(parsed.class, command).toBe(expected);
      // And none of them trips the never-allowed list itself.
      const evaluation = engine.evaluate(command, profile);
      expect(evaluation.ruleId, command).not.toBe('denylist');
    }
  });
});
