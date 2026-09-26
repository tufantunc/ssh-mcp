import { describe, it, expect } from 'vitest';
import { matchesGrammar, type ArgGrammar } from '../../../src/policy/reader-grammar.js';

// A getopt-style grammar with one no-value flag, one value flag, and no
// operand shape — enough to exercise clustering, long options, and '--'/'-'
// without an operands rule getting in the way.
const GETOPT: ArgGrammar = {
  args: 'getopt',
  flags: ['-r'],
  valueFlags: ['-n', '--since'],
};

// An exact-style grammar (no clustering, no '=' splitting).
const EXACT: ArgGrammar = {
  args: 'exact',
  flags: ['-r', '-n'],
  valueFlags: ['--name'],
};

function expectOk(words: readonly string[], grammar: ArgGrammar) {
  expect(matchesGrammar(words, grammar)).toEqual({ ok: true });
}

function expectRefused(words: readonly string[], grammar: ArgGrammar, word: string) {
  expect(matchesGrammar(words, grammar)).toEqual({ ok: false, word });
}

describe('matchesGrammar', () => {
  describe("'any'", () => {
    it('accepts anything, including words no other style would', () => {
      const any: ArgGrammar = { args: 'any', audit: 'checked GNU, busybox, BSD — all read-only' };
      expectOk([], any);
      expectOk(['--whatever', '-x', 'literally anything'], any);
    });
  });

  describe("'--' terminator and lone '-'", () => {
    it('treats everything after -- as an operand, even something flag-shaped', () => {
      expectOk(['--', '-n'], GETOPT); // -n would otherwise demand a value
    });

    it('treats a lone - as an operand (stdin), not an option', () => {
      expectOk(['-'], GETOPT);
    });

    it('counts a lone - as an operand, not a silently-consumed empty option', () => {
      // If '-' were swallowed as a zero-character cluster instead of being
      // pushed to operands, this would wrongly pass a max:0 grammar.
      const grammar: ArgGrammar = { ...GETOPT, operands: { max: 0 } };
      expectRefused(['-'], grammar, '-');
    });

    it('counts a second -- after the first as an ordinary operand', () => {
      // Plain expectOk(['--', '--'], GETOPT) can't tell "counted as an
      // operand" apart from "swallowed as a second terminator" — both read
      // ok:true with no operands rule. max:0 makes the difference visible:
      // it only refuses if the second '--' actually reached `operands`.
      const grammar: ArgGrammar = { ...GETOPT, operands: { max: 0 } };
      expectRefused(['--', '--'], grammar, '--');
    });

    it('refuses -- as an unrecognised word in exact style', () => {
      // An exact parser (find) keeps evaluating its option words after '--'
      // (measured: `find -- d -fprint /tmp/x` wrote), so the matcher must not
      // treat '--' as end-of-checks there. Refused on the word itself, before
      // anything after it is read.
      expectRefused(['--', '-r'], EXACT, '--');
      expectRefused(['--', 'operand'], EXACT, '--');
    });
  });

  describe('optionsBeforeOperands', () => {
    const POSIX_ORDER: ArgGrammar = { args: 'getopt', flags: ['-c'], optionsBeforeOperands: true };

    it('refuses an option-looking word after the first operand', () => {
      expectRefused(['IN', '-c'], POSIX_ORDER, '-c');
    });

    it('accepts the same word before any operand', () => {
      expectOk(['-c', 'IN'], POSIX_ORDER);
      expectOk(['-c'], POSIX_ORDER);
    });

    it('keeps refusing for grammars that do not set the flag', () => {
      // Opt-in per entry: without the flag, an option after an operand is
      // judged as the option it spells (implementations that permute).
      expectOk(['IN', '-c'], { args: 'getopt', flags: ['-c'] });
    });

    it('a value flag never turns its consumed value into an operand', () => {
      // `-f 3` consumes `3` as a value, so a flag after it is still "before
      // the first operand" — the option-position rule is not tripped by a
      // consumed value. (`-c` after a real operand is refused above.)
      expectOk(['-f', '3', '-c'], {
        args: 'getopt', valueFlags: ['-f'], flags: ['-c'], optionsBeforeOperands: true,
      });
    });

    it('refuses `--` itself after the first operand', () => {
      // Re-review finding: the getopt `--` branch ran before the
      // option-position rule, so `uniq IN --` passed — but a non-permuting
      // implementation (macOS uniq's `+`-prefixed optstring) stops option
      // scanning at the first operand and reads `--` as the OUTFILE, a file
      // literally named `--`. `--` is an option-looking word like any other;
      // the position rule must judge it too.
      expectRefused(['IN', '--'], POSIX_ORDER, '--');
    });

    it('keeps `--` before the first operand as the terminator', () => {
      expectOk(['--', 'IN'], POSIX_ORDER);
    });
  });

  describe('getopt short cluster', () => {
    it('accepts a cluster mixing a flag character and a value-flag character', () => {
      // -r is a flag (continues the scan), -n is a value flag whose rest ("5")
      // is the attached value.
      expectOk(['-rn5'], GETOPT);
    });

    it('refuses a cluster containing an unlisted character', () => {
      // -m is not in flags or valueFlags: the whole word is refused.
      expectRefused(['-mo'], GETOPT, '-mo');
    });
  });

  describe('short value flags, attached and separate', () => {
    it('accepts an attached value', () => {
      expectOk(['-n5'], GETOPT);
    });

    it('accepts a separate value as the next word', () => {
      expectOk(['-n', '5'], GETOPT);
    });

    it('does not treat the consumed value word as an operand', () => {
      // operands: [] once -n consumes "5" — max:0 would still pass.
      const grammar: ArgGrammar = { ...GETOPT, operands: { max: 0 } };
      expectOk(['-n', '5'], grammar);
    });
  });

  describe('getopt long options', () => {
    it('accepts an exactly-listed long flag', () => {
      expectOk(['--verbose'], { ...GETOPT, flags: ['-r', '--verbose'] });
    });

    it('accepts --name=value for a valueFlags entry', () => {
      expectOk(['--since=yesterday'], GETOPT);
    });

    it('accepts --name value (separate) for a valueFlags entry', () => {
      expectOk(['--since', 'yesterday'], GETOPT);
    });

    it('refuses =value attached to a no-value flags entry', () => {
      const grammar: ArgGrammar = { args: 'getopt', flags: ['--verbose'] };
      expectRefused(['--verbose=loud'], grammar, '--verbose=loud');
    });

    it('refuses an abbreviated long option', () => {
      // --sinc is not --since, and getopt-style abbreviation is not honoured.
      expectRefused(['--sinc'], GETOPT, '--sinc');
    });
  });

  describe('exact style', () => {
    it('accepts an exactly-listed flag and a value flag with a separate value', () => {
      expectOk(['-r', '--name', 'value'], EXACT);
    });

    it('does not split --name=value; only the literal listed word matches', () => {
      // '--name=value' was never listed (only '--name' was), so it is refused
      // whole — exact style does no splitting on the caller's behalf.
      expectRefused(['--name=value'], EXACT, '--name=value');
    });

    it('refuses a short cluster: exact style has no clustering', () => {
      // '-rn' was never listed as its own word, even though '-r' and '-n'
      // are each listed individually.
      expectRefused(['-rn'], EXACT, '-rn');
    });
  });

  describe('a name listed in both flags and valueFlags', () => {
    // Ambiguous authoring: the matcher must refuse rather than pick a side,
    // on every path that could see it — otherwise the two paths disagree
    // (one treats it as taking a value, the other as taking none) and a
    // grammar that got this wrong would matter depending only on which kind
    // of word carried the ambiguous name.
    it('refuses on the getopt long-option path, never consuming the next word', () => {
      const grammar: ArgGrammar = { args: 'getopt', flags: ['--x'], valueFlags: ['--x'] };
      expectRefused(['--x', '--evil'], grammar, '--x');
    });

    it('refuses on the exact-style path', () => {
      const grammar: ArgGrammar = { args: 'exact', flags: ['--x'], valueFlags: ['--x'] };
      expectRefused(['--x', 'value'], grammar, '--x');
    });

    it('refuses on the getopt short-cluster path', () => {
      const grammar: ArgGrammar = { args: 'getopt', flags: ['-x'], valueFlags: ['-x'] };
      expectRefused(['-x', '5'], grammar, '-x');
    });
  });

  describe('operands.max', () => {
    it('accepts up to max operands', () => {
      const grammar: ArgGrammar = { args: 'getopt', operands: { max: 1 } };
      expectOk(['file.txt'], grammar);
    });

    it('refuses the first operand past max, naming it', () => {
      const grammar: ArgGrammar = { args: 'getopt', operands: { max: 1 } };
      expectRefused(['a', 'b'], grammar, 'b');
    });

    it('refuses any operand at all when max is 0', () => {
      const grammar: ArgGrammar = { args: 'getopt', operands: { max: 0 } };
      expectRefused(['host'], grammar, 'host');
    });

    it('refuses any operand when max is NaN, rather than accepting any count', () => {
      // `operands.length > NaN` is always false, so an unguarded comparison
      // would accept unlimited operands under a broken bound.
      const grammar: ArgGrammar = { args: 'getopt', operands: { max: NaN } };
      expectRefused(['a', 'b'], grammar, 'a');
    });

    it('refuses any operand when max is not an integer, with a defined word', () => {
      // `operands[1.5]` is `undefined` — reading it directly would return
      // ok:false with no word, breaking the { ok: false; word: string }
      // contract this matcher promises.
      const grammar: ArgGrammar = { args: 'getopt', operands: { max: 1.5 } };
      expectRefused(['a', 'b'], grammar, 'a');
    });

    it('refuses any operand when max is negative', () => {
      const grammar: ArgGrammar = { args: 'getopt', operands: { max: -1 } };
      expectRefused(['a'], grammar, 'a');
    });

    it('accepts zero operands even when max is malformed', () => {
      // A malformed bound is a grammar bug, but there is nothing an empty
      // operand list could have let through unsafely.
      const grammar: ArgGrammar = { args: 'getopt', operands: { max: NaN } };
      expectOk([], grammar);
    });
  });

  describe('operands.first', () => {
    const grammar: ArgGrammar = { args: 'getopt', operands: { first: ['show', 'list', 'get'] } };

    it('accepts a first operand from the allowed set', () => {
      expectOk(['show'], grammar);
    });

    it('refuses a first operand outside the allowed set', () => {
      expectRefused(['delete'], grammar, 'delete');
    });

    it('does not require a first operand to be present at all', () => {
      expectOk([], grammar);
    });
  });

  describe('operands.each', () => {
    const grammar: ArgGrammar = { args: 'getopt', operands: { each: /^\+/ } };

    it('accepts every operand matching the pattern', () => {
      expectOk(['+%Y', '+%m'], grammar);
    });

    it('refuses the first operand that does not match, naming it', () => {
      expectRefused(['+%Y', 'oops'], grammar, 'oops');
    });

    it('checks a sticky (y) pattern fresh for every operand, not from where the last one left off', () => {
      // Without resetting lastIndex, testing '+a' first leaves the sticky
      // regex's lastIndex at 1; testing 'b+' next then matches the '+' that
      // happens to sit at index 1 of THAT string too — accepting an operand
      // that does not itself start with '+'. Each call must start fresh.
      const sticky: ArgGrammar = { args: 'getopt', operands: { each: /\+/y } };
      expectRefused(['+a', 'b+'], sticky, 'b+');
    });

    it('checks a global (g) pattern fresh for every operand, not from a leftover match position', () => {
      // Without resetting lastIndex, matching '+' at index 1 of 'a+' leaves
      // lastIndex at 2; the next call would then search the single-character
      // operand '+' starting from index 2, past its end, and wrongly refuse
      // an operand that plainly contains '+'.
      const global: ArgGrammar = { args: 'getopt', operands: { each: /\+/g } };
      expectOk(['a+', '+'], global);
    });
  });

  describe('a value flag at the end with no value', () => {
    it('refuses a short value flag that is the last word, naming the flag', () => {
      expectRefused(['-n'], GETOPT, '-n');
    });

    it('refuses a value flag at the end of a cluster, naming the flag not the cluster', () => {
      expectRefused(['-rn'], GETOPT, '-n');
    });

    it('refuses a long value flag that is the last word', () => {
      expectRefused(['--since'], GETOPT, '--since');
    });

    it('refuses an exact-style value flag that is the last word', () => {
      expectRefused(['--name'], EXACT, '--name');
    });
  });

  describe('optionalValueFlags — getopt short option in a cluster', () => {
    it('accepts an attached value', () => {
      const grammar: ArgGrammar = { args: 'getopt', optionalValueFlags: ['-U'] };
      expectOk(['-U5'], grammar);
    });

    it('treats a bare optional-value flag as having no value, and the next word as an operand', () => {
      // operands: { max: 0 } is what proves '5' reached the operand list,
      // rather than being silently consumed as -U's value.
      const grammar: ArgGrammar = {
        args: 'getopt',
        optionalValueFlags: ['-U'],
        operands: { max: 0 },
      };
      expectRefused(['-U', '5'], grammar, '5');
    });

    it('accepts it inside a cluster after a flag character', () => {
      const grammar: ArgGrammar = { args: 'getopt', flags: ['-r'], optionalValueFlags: ['-U'] };
      expectOk(['-rU5'], grammar);
    });

    it('never consumes the next word, even an unlisted option', () => {
      const grammar: ArgGrammar = { args: 'getopt', optionalValueFlags: ['-U'] };
      expectRefused(['-U', '--evil'], grammar, '--evil');
    });
  });

  describe('optionalValueFlags — getopt long option', () => {
    it('accepts it bare', () => {
      const grammar: ArgGrammar = { args: 'getopt', optionalValueFlags: ['--pretty'] };
      expectOk(['--pretty'], grammar);
    });

    it('accepts --name=value with the value attached', () => {
      const grammar: ArgGrammar = { args: 'getopt', optionalValueFlags: ['--pretty'] };
      expectOk(['--pretty=oneline'], grammar);
    });

    it('does not consume a separate next word', () => {
      const grammar: ArgGrammar = { args: 'getopt', optionalValueFlags: ['--pretty'] };
      expectRefused(['--pretty', '--evil'], grammar, '--evil');
    });

    it('leaves the next word to be judged as an operand', () => {
      const grammar: ArgGrammar = {
        args: 'getopt',
        optionalValueFlags: ['--pretty'],
        operands: { max: 0 },
      };
      expectRefused(['--pretty', 'x'], grammar, 'x');
    });
  });

  describe('optionalValueFlags — exact style', () => {
    it('matches the bare word, like a flag', () => {
      const grammar: ArgGrammar = { args: 'exact', optionalValueFlags: ['-name'] };
      expectOk(['-name'], grammar);
    });

    it('does not split an attached value off; the whole word must be listed', () => {
      const grammar: ArgGrammar = { args: 'exact', optionalValueFlags: ['-name'] };
      expectRefused(['-name=x'], grammar, '-name=x');
    });
  });

  describe('a name listed in optionalValueFlags and one other list', () => {
    it('refuses flags + optionalValueFlags on the long-option path', () => {
      const grammar: ArgGrammar = { args: 'getopt', flags: ['--x'], optionalValueFlags: ['--x'] };
      expectRefused(['--x', '--evil'], grammar, '--x');
    });

    it('refuses valueFlags + optionalValueFlags on the long-option path', () => {
      const grammar: ArgGrammar = { args: 'getopt', valueFlags: ['--x'], optionalValueFlags: ['--x'] };
      expectRefused(['--x', 'value'], grammar, '--x');
    });

    it('refuses flags + optionalValueFlags on the short-cluster path', () => {
      const grammar: ArgGrammar = { args: 'getopt', flags: ['-x'], optionalValueFlags: ['-x'] };
      expectRefused(['-x', '5'], grammar, '-x');
    });

    it('refuses valueFlags + optionalValueFlags on the short-cluster path', () => {
      const grammar: ArgGrammar = { args: 'getopt', valueFlags: ['-x'], optionalValueFlags: ['-x'] };
      expectRefused(['-x', '5'], grammar, '-x');
    });
  });

  describe('numericShort', () => {
    it("accepts git's -<n> revision limit when true", () => {
      const grammar: ArgGrammar = { args: 'getopt', numericShort: true };
      expectOk(['-20'], grammar);
    });

    it('refuses -<n> when numericShort is absent', () => {
      const grammar: ArgGrammar = { args: 'getopt' };
      expectRefused(['-20'], grammar, '-20');
    });

    it('refuses -<n> when numericShort is explicitly false', () => {
      const grammar: ArgGrammar = { args: 'getopt', numericShort: false };
      expectRefused(['-20'], grammar, '-20');
    });

    it('refuses a word that mixes digits with a letter, even when true', () => {
      const grammar: ArgGrammar = { args: 'getopt', numericShort: true };
      expectRefused(['-2x'], grammar, '-2x');
    });

    it('is ignored in exact style', () => {
      const grammar: ArgGrammar = { args: 'exact', numericShort: true };
      expectRefused(['-20'], grammar, '-20');
    });

    it('refuses a digit-only word whose leading char is ambiguous, rather than letting the shortcut accept it', () => {
      // -2 is listed in both flags and valueFlags — ambiguous on every other
      // path, and the numeric shortcut must not silently pick a side either.
      const grammar: ArgGrammar = {
        args: 'getopt',
        numericShort: true,
        flags: ['-2'],
        valueFlags: ['-2'],
      };
      expectRefused(['-2', 'x'], grammar, '-2');
    });

    it('lets an explicitly listed valueFlags entry win over the numeric shortcut', () => {
      // Without the fix, the shortcut accepts '-2' unconditionally and 'x'
      // is left as an operand; operands: { max: 0 } would then refuse 'x'.
      // With the fix, the explicit valueFlags entry consumes 'x' as -2's
      // value, leaving no operands at all.
      const grammar: ArgGrammar = {
        args: 'getopt',
        numericShort: true,
        valueFlags: ['-2'],
        operands: { max: 0 },
      };
      expectOk(['-2', 'x'], grammar);
    });
  });
});
