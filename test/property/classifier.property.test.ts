import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { classifyCommand, findForbiddenMatch } from '../../src/policy/classifier.js';
import type { CommandClass } from '../../src/types.js';
import { atLeast, CLASS_RANK, fcParams } from './fc-seed.js';
import {
  anyString,
  closedCommand,
  OPERAND_FREE_WRAPPERS,
  PRIVILEGE_PREFIXES,
  separator,
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
    // Recursion is capped inside the classifier; this checks the cap holds well past it.
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 50 }), simpleCommand, (depth, inner) => {
        expect(CLASSES).toContain(classOf(`${'echo $('.repeat(depth)}${inner}${')'.repeat(depth)}`));
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
    fc.assert(
      fc.property(fc.constantFrom(...PRIVILEGE_PREFIXES), fc.oneof(simpleCommand, fc.constant('')), (prefix, command) => {
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
      fc.property(fc.constantFrom(...OPERAND_FREE_WRAPPERS), simpleCommand, (wrapper, command) => {
        expect(atLeast(classOf(`${wrapper} ${command}`), classOf(command)), `${wrapper} ${command}`).toBe(true);
      }),
      fcParams(1000),
    );
  });

  describe('a variant the shell reads the same way never lowers the class', () => {
    // Only words quoting cannot change: see `quotableWord` for what is excluded and why
    // (globs, assignments, a leading `~`, anything split or substituted on). A word is
    // eligible only when the whole word matches, so text already inside quotes, such as
    // an interpreter's program, is never re-quoted.
    const QUOTABLE = /^[a-z][a-z0-9_./-]*$/;

    const variants = (command: string): string[] => {
      const out = [` ${command}`, `${command} `, command.replace(' ', '\t')];
      const words = command.split(' ');
      words.forEach((word, i) => {
        if (!QUOTABLE.test(word)) return;
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
    let runs = 0;
    fc.assert(
      fc.property(closedCommand, (command) => {
        runs++;
        if (findForbiddenMatch(command) === null) return;
        hits++;
        expect(atLeast(classOf(command), 'destructive'), command).toBe(true);
      }),
      fcParams(1000),
    );
    // Without matches this property asserts nothing; the generator weights them in.
    expect(hits / runs).toBeGreaterThanOrEqual(0.01);
  });

  it('never classifies a command containing a shell control character as read-only', () => {
    // The classifier's own definition (SHELL_CONTROL_CHARS), copied: this pins the
    // documented refusal, not a general theory of what a shell treats as special.
    const CONTROL = /[;&|<>`$(){}\n\r]/;
    fc.assert(
      fc.property(fc.oneof(closedCommand, anyString), (command) => {
        if (classOf(command) !== 'read-only') return;
        expect(CONTROL.test(command), command).toBe(false);
      }),
      fcParams(1000),
    );
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
