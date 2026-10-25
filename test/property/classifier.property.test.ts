import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { classifyCommand, findForbiddenMatch, isForbidden } from '../../src/policy/classifier.js';
import type { CommandClass } from '../../src/types.js';
import { atLeast, CLASS_RANK, fcParams } from './fc-seed.js';
import {
  anyString,
  closedCommand,
  isQuotableWord,
  operandFreeWrapper,
  operandWrapper,
  privilegePrefix,
  readerWithControlChar,
  separator,
  SHELL_CONTROL_CHARS,
  simpleCommand,
} from './command-arbitraries.js';

// The rules the classifier promises, stated once instead of through examples. Every policy
// advisory so far was a spelling or a combination of a command that classified lower than
// what it runs; each property below is a rule such a spelling would have to break.
// Generators and the fixed seed are explained in command-arbitraries.ts and fc-seed.ts.

const CLASSES = Object.keys(CLASS_RANK) as CommandClass[];
const classOf = (command: string) => classifyCommand(command).class;

describe('classifyCommand invariants', () => {
  it('never throws, and always returns one of the four classes', () => {
    fc.assert(
      fc.property(anyString, (input) => {
        expect(CLASSES).toContain(classOf(input));
      }),
      fcParams(1000),
    );
  });

  it('never throws on deeply nested substitutions', () => {
    // Recursion is capped inside the classifier (depth 8); this checks the cap holds well
    // past it. Cost grows linearly with depth even past the cap (about 5 ms per sample at
    // 50 locally, ten times that on a loaded CI runner), so 20 is the ceiling: past the
    // cap, inside vitest's per-test timeout.
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 20 }), simpleCommand, (depth, inner) => {
        const whole = classOf(`${'echo $('.repeat(depth)}${inner}${')'.repeat(depth)}`);
        expect(CLASSES).toContain(whole);
        // Carrying a command through substitutions never hides what it is, at any depth.
        expect(atLeast(whole, classOf(inner)), `${depth} x ${inner}`).toBe(true);
      }),
      fcParams(200),
    );
  });

  it('classifies the same string the same way every time', () => {
    fc.assert(
      fc.property(closedCommand, (command) => {
        expect(classOf(command)).toBe(classOf(command));
      }),
      fcParams(1000),
    );
  });

  it('classifies any command behind a privilege prefix as privileged', () => {
    // Bare, path-qualified, quoted and backslash-escaped spellings all still name the
    // prefix: `/usr/bin/sudo id` and `'sudo' id` run sudo as much as `sudo id` does.
    fc.assert(
      fc.property(privilegePrefix, fc.oneof(simpleCommand, fc.constant('')), (prefix, command) => {
        const full = `${prefix} ${command}`.trim();
        expect(classOf(full), full).toBe('privileged');
      }),
      fcParams(1000),
    );
  });

  it('never classifies a combination of commands below any of its parts', () => {
    fc.assert(
      fc.property(closedCommand, separator, closedCommand, (a, sep, c) => {
        const whole = classOf(`${a} ${sep} ${c}`);
        expect(atLeast(whole, classOf(a)), `${a} ${sep} ${c}`).toBe(true);
        expect(atLeast(whole, classOf(c)), `${a} ${sep} ${c}`).toBe(true);
      }),
      fcParams(1000),
    );
  });

  it('never lowers a command by running it through a wrapper that takes no operand', () => {
    fc.assert(
      fc.property(operandFreeWrapper, simpleCommand, (wrapper, command) => {
        expect(atLeast(classOf(`${wrapper} ${command}`), classOf(command)), `${wrapper} ${command}`).toBe(true);
      }),
      fcParams(1000),
    );
  });

  it('never lowers a command by running it through a wrapper with its own operand and flags', () => {
    fc.assert(
      fc.property(operandWrapper, simpleCommand, (wrapper, command) => {
        expect(atLeast(classOf(`${wrapper} ${command}`), classOf(command)), `${wrapper} ${command}`).toBe(true);
        if (isForbidden(command)) expect(isForbidden(`${wrapper} ${command}`), `${wrapper} ${command}`).toBe(true);
      }),
      fcParams(1000),
    );
  });

  it('never lowers a command by spelling its command word with a Windows suffix or in upper case', () => {
    const fold = (word: string, how: number) => (how === 0 ? `${word}.exe` : how === 1 ? word.toUpperCase() : `${word.toUpperCase()}.EXE`);
    fc.assert(
      fc.property(simpleCommand, fc.integer({ min: 0, max: 2 }), (command, how) => {
        const [head, ...rest] = command.split(' ');
        if (!/^[a-z][a-z0-9_-]*$/.test(head)) return;
        const folded = [fold(head, how), ...rest].join(' ');
        if (isForbidden(command)) expect(isForbidden(folded), folded).toBe(true);
        if (CLASS_RANK[classOf(command)] >= CLASS_RANK.destructive) {
          expect(atLeast(classOf(folded), classOf(command)), folded).toBe(true);
        }
      }),
      fcParams(1000),
    );
  });

  describe('a variant the shell reads the same way never lowers the class', () => {
    // Only words quoting cannot change: `isQuotableWord` is the one definition, shared
    // with the generator (globs, assignments, a leading `~`, anything split or
    // substituted on, and words already carrying a quote are excluded). A word is
    // eligible only when the whole word matches, so text already inside quotes, such as
    // an interpreter's program, is never re-quoted.
    const variants = (command: string): string[] => {
      const out = [` ${command}`, `${command} `, command.replace(' ', '\t')];
      const words = command.split(' ');
      words.forEach((word, i) => {
        if (!isQuotableWord(word)) return;
        for (const q of ["'", '"']) {
          const quoted = [...words];
          quoted[i] = `${q}${word}${q}`;
          out.push(quoted.join(' '));
        }
      });
      return out;
    };

    it('for whitespace and for quoting a plain word', () => {
      fc.assert(
        fc.property(simpleCommand, (command) => {
          const base = classOf(command);
          for (const v of variants(command)) expect(atLeast(classOf(v), base), JSON.stringify(v)).toBe(true);
        }),
        fcParams(1000),
      );
    });
  });

  it('classifies anything on the never-allowed list at least destructive', () => {
    let hits = 0;
    let windowsOnlyHits = 0;
    let runs = 0;
    fc.assert(
      fc.property(closedCommand, (command) => {
        runs++;
        if (findForbiddenMatch(command) === null) return;
        hits++;
        if (!isForbidden(command, 'posix')) windowsOnlyHits++;
        expect(atLeast(classOf(command), 'destructive'), command).toBe(true);
      }),
      fcParams(1000),
    );
    // Without matches this property asserts nothing; the generator weights them in.
    // Matches only the cmd.exe reading catches are counted separately, so that reading
    // is exercised too, not only the POSIX default.
    expect(hits / runs).toBeGreaterThanOrEqual(0.01);
    expect(windowsOnlyHits).toBeGreaterThan(0);
  });

  it('never classifies a command containing a shell control character as read-only', () => {
    // The classifier's own definition (SHELL_CONTROL_CHARS), copied in the generator
    // module: this pins the documented refusal, not a general theory of what a shell
    // treats as special. Every character of the set is placed next to a reader word by
    // `readerWithControlChar`, and each one is counted, so none can silently fall out.
    const seen = new Set<string>();
    fc.assert(
      fc.property(fc.oneof(closedCommand, anyString), readerWithControlChar, (command, { command: controlled, controlChar }) => {
        for (const ch of SHELL_CONTROL_CHARS) if (command.includes(ch)) seen.add(ch);
        seen.add(controlChar);
        expect(classOf(controlled), controlled).not.toBe('read-only');
        if (classOf(command) !== 'read-only') return;
        expect(SHELL_CONTROL_CHARS.some((ch) => command.includes(ch)), command).toBe(false);
      }),
      fcParams(1000),
    );
    expect([...seen].sort()).toEqual([...SHELL_CONTROL_CHARS].sort());
  });

  it('classifies a reader refused read-only as safe', () => {
    fc.assert(
      fc.property(fc.oneof(closedCommand, anyString), (command) => {
        const parsed = classifyCommand(command);
        if (!parsed.readOnlyRejection) return;
        expect(parsed.class, command).toBe('safe');
      }),
      fcParams(1000),
    );
  });
});
