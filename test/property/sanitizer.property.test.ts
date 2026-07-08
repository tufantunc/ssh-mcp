import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { sanitizeMetadata } from '../../src/guard/sanitizer.js';

describe('sanitizeMetadata property tests', () => {
  it('never contains CR, LF, NUL, or Unicode separators after sanitization', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 500 }), (input) => {
        const result = sanitizeMetadata(input);
        if (result !== undefined) {
          expect(result).not.toMatch(/[\r\n\u2028\u2029\x00]/);
        }
      }),
      { numRuns: 10000 },
    );
  });

  it('result length never exceeds maxLength', () => {
    fc.assert(
      fc.property(
        fc.string({ maxLength: 1000 }),
        fc.integer({ min: 1, max: 500 }),
        (input, maxLen) => {
          const result = sanitizeMetadata(input, maxLen);
          if (result !== undefined) {
            expect(result.length).toBeLessThanOrEqual(maxLen);
          }
        },
      ),
      { numRuns: 5000 },
    );
  });
});
