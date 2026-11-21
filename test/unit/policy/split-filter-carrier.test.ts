import { describe, it, expect } from 'vitest';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';
import { PolicyEngine } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

/**
 * GHSA-gpfp-xjq7-64hv: GNU `split --filter=COMMAND` runs `sh -c COMMAND` per chunk, and
 * `split` was in no table, so only the speculative catch-all read its operands — and that
 * reads a value only when it contains whitespace. `split --filter=reboot x` classified
 * `safe`, and so did a filter that reaches `sudo` with no whitespace in it.
 *
 * `split --filter` is now a named carrier: its value is classified whatever its shape, the
 * outer command is `destructive` (the tar/sqlite3 answer for shell text this file can
 * read) and an inner elevation raises it to `privileged`.
 *
 * Spellings measured running on coreutils 9.11: `--filter=X`, `--filt=X`, `--f=X`,
 * `--filter X`, `--fi X`.
 */
const PREFIXES = ['--f', '--fi', '--fil', '--filt', '--filte', '--filter'];
const SPELLINGS = PREFIXES.flatMap((flag) => [`${flag}=`, `${flag} `]);

describe('split --filter is a carrier (GHSA-gpfp-xjq7-64hv)', () => {
  it.each(SPELLINGS)('reads a one-word filter spelled %sCOMMAND', (spelling) => {
    const command = `split ${spelling}reboot /etc/passwd`;
    expect(classifyCommand(command).class).toBe('destructive');
    expect(findForbiddenMatch(command)).not.toBeNull();
  });

  it.each(SPELLINGS)('reads an elevation spelled %sCOMMAND', (spelling) => {
    expect(classifyCommand(`split ${spelling}sudo x`).class).toBe('privileged');
  });

  it.each([
    ['split --filter=id /etc/passwd', 'destructive'],
    ['split --filter=/tmp/x.sh /etc/passwd', 'destructive'],
    ['split -b 1M --filter=id x', 'destructive'],
    // These two were already read before the fix (the value holds a space);
    // they guard the answer, they do not show the fix.
    ["split --filter='sudo id' x", 'privileged'],
    ["split --f 'sudo id' x", 'privileged'],
    // Every filter on the line is read, not only the first.
    ['split --filter=id --filter=sudo x', 'privileged'],
    // A detached value is consumed: `--f=sudo` here is the first filter's
    // value, a command by that name, not a second filter.
    ['split --filter --f=sudo x', 'destructive'],
    // Read past a wrapper, and folded like every other command word.
    ['env split --filter=reboot x', 'destructive'],
    ['SPLIT.EXE --filter=reboot x', 'destructive'],
    ['gsplit --filter=reboot x', 'destructive'],
    // Shell text with no whitespace in it is still the text `sh -c` runs.
    ["split --filter='id;reboot' x", 'destructive'],
    // `destructive`, not `privileged`: typed directly, this text is a command
    // word nothing here can name, and the carrier gives it the same class.
    ["split --filter='sudo${IFS}id' x", 'destructive'],
  ])('%s → %s', (command, expected) => {
    expect(classifyCommand(command).class).toBe(expected);
  });

  it('denies them for an operator on prod, where safe would have run', () => {
    const engine = new PolicyEngine();
    const profile = {
      name: 'prod', role: 'operator', group: 'prod',
      approvalPolicy: 'ask-destructive', readOnly: false,
    } as unknown as Profile;
    for (const [command, cls] of [
      ['split --filter=reboot /etc/passwd', 'destructive'],
      ['split --filter reboot /etc/passwd', 'destructive'],
      ['split --filter=sudo /etc/passwd', 'privileged'],
      ["split --filter='sudo${IFS}id' /etc/passwd", 'destructive'],
    ] as const) {
      const evaluation = engine.evaluate(command, profile);
      expect(evaluation.decision, command).toBe('deny');
      expect(evaluation.commandClass, command).toBe(cls);
    }
  });

  it.each([
    'split --filter=id --filter=reboot x',
    "split --filter='id\nreboot' x",
  ])('the forbidden-command scan reads every filter, across lines: %j', (command) => {
    expect(findForbiddenMatch(command)).not.toBeNull();
  });

  it.each([
    // No filter: split only writes its chunks, as it always classified.
    ['split -b 1M big.bin part-', 'safe'],
    ['split --lines=100 f', 'safe'],
    // A filter flag with nothing after it, or with an empty value, carries nothing.
    ['split x --filter', 'safe'],
    ['split --filter= x', 'safe'],
    // Not a prefix of `--filter`.
    ['split --filters reboot x', 'safe'],
    // A mention, not an invocation.
    ['echo --filter=reboot', 'read-only'],
    ['man split --filter=reboot', 'safe'],
    // `--filter` before the command word is the wrapper's, not split's.
    ['env --filter=reboot split x', 'safe'],
    // `--filter` on another binary is that binary's own option.
    ['docker ps --filter name=reboot', 'read-only'],
    ['rsync --filter=reboot a b', 'safe'],
  ])('keeps %s as %s', (command, expected) => {
    expect(classifyCommand(command).class).toBe(expected);
  });
});
