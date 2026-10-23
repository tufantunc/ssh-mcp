import { describe, it, expect, afterEach } from 'vitest';
import fc from 'fast-check';
import { classifyCommand } from '../../src/policy/classifier.js';
import { FC_DEFAULT_SEED, fcParams } from './fc-seed.js';
import { closedCommand, quotableWord, simpleCommand } from './command-arbitraries.js';

// The classifier properties are only as strong as these generators. A generator that
// never produces a privileged or a read-only command makes every "never lowers" property
// pass while asserting nothing, so its reach is a test of its own.

const sample = <T>(arb: fc.Arbitrary<T>) => fc.sample(arb, { numRuns: 300, seed: FC_DEFAULT_SEED });

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

  it('stays within the size cap', () => {
    for (const c of sample(closedCommand)) expect(c.length, c).toBeLessThanOrEqual(240);
  });
});

describe('simpleCommand', () => {
  it('is one segment: no separator outside quotes', () => {
    for (const c of sample(simpleCommand)) expect(c, c).not.toMatch(/[;&|\n]/);
  });
});

describe('quotableWord', () => {
  it('never contains a character whose meaning changes when quoted', () => {
    for (const w of sample(quotableWord)) expect(w, w).not.toMatch(/[*?[\]\s;&|<>`$\\=]|^~/);
  });
});
