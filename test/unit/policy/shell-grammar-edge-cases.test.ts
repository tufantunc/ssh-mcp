import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';
import { readShellGrammar } from '../../../src/policy/shell-grammar.js';

/**
 * Edge cases of the grammar reading, each one found by breaking a single line of the
 * lexer or of its use in the classifier and looking for an input that could tell: a
 * glued operator, an escape inside a substitution, a descriptor with two digits, the
 * second line after a here-document. The tables in `shell-grammar.test.ts` and
 * `shell-grammar-reading.test.ts` say what the reading is for; these pin its corners.
 *
 * `facet` is what is asserted: the class (`cls`), the never-allowed match (`forb`), the
 * binary named (`bin`), or a field of the lexer's reading.
 */
type Facet = 'cls' | 'forb' | 'flat' | 'subs' | 'bin' | 'alt' | 'heres' | 'globs' | 'funcs';
interface Case {
  command: string;
  facet: Facet;
  expected: unknown;
  dialect?: 'posix' | 'windows';
}
const cases = JSON.parse(
  readFileSync(new URL('../../fixtures/policy/grammar-edge-cases.json', import.meta.url), 'utf8'),
) as Case[];

const measure = ({ command, facet, dialect }: Case): unknown => {
  if (facet === 'cls') return classifyCommand(command).class;
  if (facet === 'forb') return findForbiddenMatch(command) !== null;
  if (facet === 'bin') return classifyCommand(command).binary;
  const reading = readShellGrammar(command, dialect ?? 'posix');
  if (facet === 'flat') return reading.flattened;
  if (facet === 'subs') return reading.substitutions;
  if (facet === 'alt') return reading.alternates;
  if (facet === 'heres') return reading.hereStrings;
  if (facet === 'globs') return reading.expandingWords;
  if (facet === 'funcs') return reading.functionNames;
  // A mistyped facet must not be measured as something else.
  throw new Error(`unknown facet ${String(facet)}`);
};

describe('edge cases of the grammar reading', () => {
  it('holds the cases', () => {
    expect(cases.length).toBe(180);
  });

  it.each(cases.map((c) => [c.facet, c.command, c] as const))('%s of %j', (_facet, _command, c) => {
    expect(measure(c)).toEqual(c.expected);
  });
});
