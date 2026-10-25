import { describe, it, expect, afterEach } from 'vitest';
import fc from 'fast-check';
import { classifyCommand } from '../../src/policy/classifier.js';
import { FC_DEFAULT_SEED, fcParams } from './fc-seed.js';
import {
  closedCommand,
  isQuotableWord,
  quotableWord,
  readerWithControlChar,
  SHELL_CONTROL_CHARS,
  simpleCommand,
} from './command-arbitraries.js';

// The classifier properties are only as strong as these generators. A generator that
// never produces a privileged or a read-only command makes every "never lowers" property
// pass while asserting nothing, so its reach is a test of its own.

// Seeded like the properties, so a private FC_SEED run checks the generators' reach on
// that seed too.
const sample = <T>(arb: fc.Arbitrary<T>) => fc.sample(arb, fcParams(300));

describe('fcParams', () => {
  const saved = process.env.FC_SEED;
  afterEach(() => {
    if (saved === undefined) delete process.env.FC_SEED;
    else process.env.FC_SEED = saved;
  });

  it('uses the fixed default seed when FC_SEED is unset or empty', () => {
    delete process.env.FC_SEED;
    expect(fcParams(10)).toEqual({ numRuns: 10, seed: FC_DEFAULT_SEED });
    process.env.FC_SEED = '';
    expect(fcParams(10).seed).toBe(FC_DEFAULT_SEED);
  });

  it('uses FC_SEED when it is an integer', () => {
    process.env.FC_SEED = '424242';
    expect(fcParams(5)).toEqual({ numRuns: 5, seed: 424242 });
  });

  it('refuses an FC_SEED that is not an integer, rather than silently using the default', () => {
    process.env.FC_SEED = 'abc';
    expect(() => fcParams(5)).toThrow(/FC_SEED/);
  });

  it('refuses an FC_SEED outside 32 bits, which fast-check would silently wrap onto another seed', () => {
    // fast-check reduces a seed to a signed 32-bit integer, so 2^32 + the default would
    // replay the default's inputs while the run reports a different seed.
    process.env.FC_SEED = String(2 ** 32 + FC_DEFAULT_SEED);
    expect(() => fcParams(5)).toThrow(/FC_SEED/);
    process.env.FC_SEED = String(-(2 ** 31) - 1);
    expect(() => fcParams(5)).toThrow(/FC_SEED/);
    process.env.FC_SEED = String(2 ** 31 - 1);
    expect(fcParams(5).seed).toBe(2 ** 31 - 1);
  });
});

/** Unescaped occurrences of `ch`, counting a backslash as escaping the next character. */
function unescapedCount(s: string, ch: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\') { i++; continue; }
    if (s[i] === ch) n++;
  }
  return n;
}

/** How many shell segments the command splits into outside quotes, `&&`/`||` counting once. */
function countSegments(command: string): number {
  let quote: string | null = null;
  let escaped = false;
  let boundary = false;
  let segments = 1;
  for (const ch of command) {
    if (escaped) { escaped = false; boundary = false; continue; }
    if (quote !== null) {
      if (ch === quote) quote = null;
      boundary = false;
      continue;
    }
    if (ch === '\\') { escaped = true; boundary = false; continue; }
    if (ch === '"' || ch === "'") { quote = ch; boundary = false; continue; }
    if (ch === ';' || ch === '&' || ch === '|' || ch === '\n') {
      if (!boundary) segments++;
      boundary = true;
      continue;
    }
    boundary = false;
  }
  return segments;
}

describe('closedCommand', () => {
  it('closes every quote and substitution it opens', () => {
    for (const c of sample(closedCommand)) {
      expect(unescapedCount(c, "'") % 2, c).toBe(0);
      expect(unescapedCount(c, '"') % 2, c).toBe(0);
      expect(c.split('$(').length - 1, c).toBe(unescapedCount(c, ')'));
    }
  });

  it('reaches every class, so properties over it are not vacuous', () => {
    const classes = new Set(sample(closedCommand).map((c) => classifyCommand(c).class));
    expect([...classes].sort()).toEqual(['destructive', 'privileged', 'read-only', 'safe']);
  });

  it('stays within two segments, so a composed pair stays within the four-segment cap', () => {
    // The one never-allowed shape that is two segments by nature (a download piped into
    // a shell) appears whole rather than inside a segment, so every sample counts its
    // own segments and a property joining two samples cannot exceed four.
    for (const c of sample(closedCommand)) expect(countSegments(c), c).toBeLessThanOrEqual(2);
  });

  it('keeps samples short enough that two joined with a separator stay near the 200-character cap', () => {
    for (const c of sample(closedCommand)) expect(c.length, c).toBeLessThanOrEqual(100);
  });
});

describe('simpleCommand', () => {
  it('is one segment: no separator outside quotes', () => {
    for (const c of sample(simpleCommand)) {
      expect(c, c).not.toMatch(/[;&|\n]/);
      expect(countSegments(c), c).toBe(1);
    }
  });
});

describe('quotableWord', () => {
  it('never contains a character whose meaning changes when quoted', () => {
    for (const w of sample(quotableWord)) expect(isQuotableWord(w), w).toBe(true);
  });

  it('rejects the named exclusions: globs, assignments, tilde, substitution, escape, quotes', () => {
    // Each line is a word quoting which really does change what the shell runs, or would
    // leave the quoted variant's quotes unbalanced: `ls a*` expands, `A=1 cmd` stops
    // being an assignment when quoted, `ls '~'` no longer expands the home directory.
    for (const w of ['a*b', 'a?b', 'a[b', 'a b', 'a;b', 'a&b', 'a|b', 'a<b', 'a>b', 'a$b',
      'a`b', 'a\\b', 'A=1', "'q'", '"q"', '~x', '/tmp)', 'a(b', '{a}']) {
      expect(isQuotableWord(w), w).toBe(false);
    }
    expect(isQuotableWord(''), 'the empty word adds an argument when quoted').toBe(false);
    expect(isQuotableWord('a~b'), 'a tilde that does not lead the word is just a letter').toBe(true);
  });
});

describe('readerWithControlChar', () => {
  it('carries exactly one control character from the copied set, and never classifies read-only', () => {
    const seen = new Set<string>();
    for (const { command, controlChar } of sample(readerWithControlChar)) {
      expect(SHELL_CONTROL_CHARS, command).toContain(controlChar);
      expect(command, command).toContain(controlChar);
      expect(classifyCommand(command).class, command).not.toBe('read-only');
      seen.add(controlChar);
    }
    // A character the samples never carry is a character the property never checks.
    expect([...seen].sort()).toEqual([...SHELL_CONTROL_CHARS].sort());
  });
});
