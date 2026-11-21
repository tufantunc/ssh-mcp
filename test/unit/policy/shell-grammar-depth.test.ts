import { describe, it, expect } from 'vitest';
import { readShellGrammar } from '../../../src/policy/shell-grammar.js';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';

/**
 * Nesting is depth the sender chooses, so nothing here may recurse on it. In a file of
 * its own: the growth-ratio tests read CPU time for the whole process, and a hundred
 * thousand levels of garbage collection next to them moved their readings.
 */
describe('nesting far deeper than a call stack', () => {
  it('is read by the lexer', () => {
    for (const unit of ['"$(', '$(', '${', '(', '{ ', '$("', 'if ', '((', "$'", '=(']) {
      expect(() => readShellGrammar(unit.repeat(100_000), 'posix'), unit).not.toThrow();
    }
  });

  it('gets an answer from the classifier', () => {
    for (const unit of ['"$(', '$("', '${x:-"']) {
      const command = `echo ${unit.repeat(21_000)}`;
      expect(() => classifyCommand(command), unit).not.toThrow();
      expect(() => findForbiddenMatch(command), unit).not.toThrow();
    }
  }, 120_000);
});
