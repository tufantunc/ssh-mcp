import { describe, it, expect } from 'vitest';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { classifyCommand } from '../../../src/policy/classifier.js';
import type { Profile } from '../../../src/types.js';

/**
 * GHSA-qmx6-47vm-3vf7: a binary the classifier does not recognise laundered an
 * elevated command into `safe`, the class that raises no prompt.
 *
 * The fix does not scan text for `sudo`. An earlier design did, and it asserted
 * elevations the existing readers deliberately refuse to assert — awk's runtime
 * concatenation and `$S` both cap at `destructive` on purpose — and it beat the
 * nested classification that names the elevated binary correctly. Instead, the
 * operands of a segment no more specific reader claimed become nested commands,
 * and the existing anchored check finds the elevation on a command it leads.
 */
const operatorProd = {
  name: 'prod-web', host: 'h', port: 22, user: 'deploy', auth: 'agent', tty: false,
  timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
  role: 'operator', readOnly: false, approvalPolicy: 'ask-destructive', cert: false,
  announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
  sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
} as unknown as Profile;

const engine = new PolicyEngine(DEFAULT_RULES);
const decide = (command: string) => engine.evaluate(command, operatorProd, 'run-command');

describe('an unrecognised binary cannot hide a command in its operands', () => {
  it.each([
    ['osascript', `osascript -e 'do shell script "sudo id"'`],
    ['an unknown binary', `whatever-tool -e 'sudo id'`],
    ['an unknown binary, no flag', `whatever-tool 'sudo id'`],
  ])('refuses elevation carried by %s', (_label, command) => {
    expect(decide(command).commandClass, command).toBe('privileged');
    expect(decide(command).decision, command).toBe('deny');
  });

  it('names the binary that would run as root, not the carrier', () => {
    // The reason this is a nested classification rather than a text scan: the
    // existing anchored check runs on a command the elevation actually leads, so
    // it can say which binary root would execute. A text scan can only name the
    // outer word, and four awk tests caught exactly that.
    expect(classifyCommand(`osascript -e 'do shell script "sudo id"'`).binary).toBe('id');
  });

  it('finds elevation reached only through a substitution', () => {
    expect(decide(`whatever-tool -e "$(printf 'sudo id')"`).commandClass).toBe('privileged');
  });

  it('leaves the deliberate caps alone', () => {
    // Both are documented decisions this fix must not override: awk assembles the
    // command at run time, and `$S` cannot be resolved, so neither is a confirmed
    // elevation. `destructive` asks for approval; `privileged` would refuse.
    expect(classifyCommand(`awk 'BEGIN{"sudo" " id" | getline v}'`).class).toBe('destructive');
    expect(classifyCommand('S=sudo; $S id').class).toBe('destructive');
  });

  it('leaves the commands an operator runs all day alone', () => {
    for (const [command, expected] of [
      ['kubectl get pods', 'safe'],
      ['make deploy', 'safe'],
      ['docker run -e FOO=bar img', 'safe'],
      ['terraform apply', 'safe'],
      ["grep 'sudo' /var/log/auth.log", 'read-only'],
      ['find / -name perl', 'read-only'],
      ['echo "sudo id"', 'read-only'],
    ] as const) {
      expect(classifyCommand(command).class, command).toBe(expected);
    }
  });

  it('sees both halves of an operand that carries a separator', () => {
    // One word to the tokeniser, two commands to a shell. Pushing it as a nested
    // command is what makes the second half visible at all.
    expect(classifyCommand(`whatever-tool 'echo a; sudo id'`).class).toBe('privileged');
  });

  it('stays cheap on many long multi-word operands', () => {
    // The recursion is wider now: every multi-word operand of an unrecognised
    // binary is classified. The bound is a growth ratio rather than a wall clock —
    // CI runs under coverage, and an absolute bound here once failed at 3677ms.
    const operand = (n: number) => `'${'word '.repeat(n)}'`;
    const small = `whatever-tool ${Array.from({ length: 10 }, () => operand(10)).join(' ')}`;
    const large = `whatever-tool ${Array.from({ length: 100 }, () => operand(100)).join(' ')}`;
    const time = (c: string) => { const t = performance.now(); classifyCommand(c); return performance.now() - t; };
    time(small);
    const a = time(small);
    const b = time(large);
    // 100x the operands at 10x the length is 1000x the input; anything near linear
    // is fine and anything quadratic is not.
    expect(b).toBeLessThan(Math.max(a * 3000, 100));
  });

  it('costs an operand whose first word is an elevation name', () => {
    // The accepted cost, pinned so it is a decision rather than a surprise: an
    // operand that begins with `sudo ` has the shape of a command, which is why it
    // is caught. The elevation name has to lead — these two are unaffected.
    expect(classifyCommand('git commit -m "sudo fix"').class).toBe('privileged');
    expect(classifyCommand('git commit -m "fix the sudo thing"').class).toBe('safe');
    expect(classifyCommand('curl -H "X: sudo y" http://h').class).toBe('safe');
  });
});
