import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  REJECTED_REMOTE_PATH,
  remotePathForAudit,
  sanitizeCommand,
  sanitizeRemotePath,
} from '../../src/guard/sanitizer.js';

// sanitizeCommand is the boundary that keeps caller-controlled text from
// carrying a newline into the remote shell (Issue #44 was exactly that, via a
// metadata field). Its control-char stripping had no test of any kind: deleting
// the CONTROL_CHARS replace from sanitizeCommand broke nothing in the suite.
// fast-check's default string generator almost never emits CR/LF/NUL, so a
// property over plain fc.string() would pass even with the sanitizer removed.
// This generator interleaves the exact characters that matter.
const DANGEROUS = ['\r', '\n', '\u2028', '\u2029', '\u0000'];
const commandWithControlChars = fc
  .array(
    fc.oneof(
      { weight: 3, arbitrary: fc.string({ minLength: 1, maxLength: 12 }) },
      { weight: 2, arbitrary: fc.constantFrom(...DANGEROUS) },
    ),
    { maxLength: 40 },
  )
  .map((parts) => parts.join(''));

describe('sanitizeCommand property tests', () => {
  it('never returns CR, LF, NUL or Unicode separators', () => {
    fc.assert(
      fc.property(commandWithControlChars, (input) => {
        let result: string;
        try {
          result = sanitizeCommand(input, Number.MAX_SAFE_INTEGER);
        } catch {
          return; // empty/whitespace-only input is rejected, which is also safe
        }
        expect(result).not.toMatch(/[\r\n\u2028\u2029\x00]/);
      }),
      { numRuns: 10000 },
    );
  });

  it('never returns a command longer than maxChars', () => {
    fc.assert(
      fc.property(
        fc.string({ maxLength: 1000 }),
        fc.integer({ min: 1, max: 500 }),
        (input, maxChars) => {
          let result: string;
          try {
            result = sanitizeCommand(input, maxChars);
          } catch {
            return; // rejected (empty or over the limit) — nothing reaches the shell
          }
          expect(result.length).toBeLessThanOrEqual(maxChars);
        },
      ),
      { numRuns: 5000 },
    );
  });

  // The v1 CWE-78 corpus. These payloads must never reach a shell; since #198
  // they are refused rather than joined into one line, because joining them
  // still ran something — just not what the caller asked for, and with no
  // error to say so.
  it.each([
    ['the #44 PoC shape', 'ls\nid > /root/poc.txt'],
    ['a CRLF pair', 'echo hi\r\nwhoami'],
    ['a Unicode line separator', 'echo a\u2028b'],
  ])('refuses %s outright', (_label, payload) => {
    expect(() => sanitizeCommand(payload, 1000)).toThrow(/line break/);
  });

  it('refuses an embedded null byte by name', () => {
    // Previously replaced with a space, which turned this into a command that
    // ran. Naming it is also how a caller learns what was wrong: a NUL is
    // invisible in every client that renders the argument back.
    expect(() => sanitizeCommand('echo a\u0000b', 1000)).toThrow(/null byte/);
  });

  it('rejects input that is only whitespace as empty', () => {
    expect(() => sanitizeCommand('\n\r ', 1000)).toThrow(/empty/i);
  });

  it('rejects input that is only a null byte by name, not as empty', () => {
    // It trims to a single NUL rather than to nothing, so "empty" would be a
    // lie about what the caller sent.
    expect(() => sanitizeCommand('\n\r\u0000', 1000)).toThrow(/null byte/);
  });
});


/**
 * The same argument, for the path boundary.
 *
 * `sanitizeRemotePath` guards the confusion between three renderings of one
 * call: the string policy classifies, the message a human approves, and the path
 * actually transferred. Six example cases covered six representatives of a class
 * with roughly ninety members — narrowing the class to `/[\r\n\0]/` passed all
 * of them. This draws from the whole set.
 */
/**
 * Written out here rather than imported from the module under test.
 *
 * Importing `PATH_CONTROL_CHARS` and asserting against it makes the property
 * assert the source equals itself: narrowing the class narrows the check and the
 * assertion together. Measured — with the class cut down to CR/LF/NUL, every one
 * of these properties still passed. This literal is the contract; the module has
 * to meet it.
 *
 * It earned that: narrowing the class to let U+200C and U+200D through was a
 * deliberate change, and this literal is what made it deliberate rather than
 * silent — it failed until it was updated too. The joiners are asserted from the
 * other side below.
 */
const MUST_REJECT = /[\u0000-\u001f\u007f-\u009f\u061c\u200b\u200e\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

const FORBIDDEN_CODES: number[] = [
  ...Array.from({ length: 0x20 }, (_, i) => i),           // C0
  ...Array.from({ length: 0x21 }, (_, i) => 0x7f + i),    // DEL + C1
  0x061c,                                                 // ALM
  0x200b, 0x200e, 0x200f,                                 // ZWSP, LRM, RLM — not the joiners
  ...Array.from({ length: 7 }, (_, i) => 0x2028 + i),     // separators + LRE..RLO
  ...Array.from({ length: 5 }, (_, i) => 0x2060 + i),     // WJ + invisible ops
  ...Array.from({ length: 4 }, (_, i) => 0x2066 + i),     // isolates
  0xfeff,                                                 // BOM
];

const pathWithForbiddenChars = fc
  .array(
    fc.oneof(
      { weight: 3, arbitrary: fc.string({ minLength: 1, maxLength: 12 }) },
      { weight: 2, arbitrary: fc.constantFrom(...FORBIDDEN_CODES).map((c) => String.fromCharCode(c)) },
      { weight: 1, arbitrary: fc.constantFrom('/', '.', '-', ' ') },
    ),
    { maxLength: 40 },
  )
  .map((parts) => parts.join(''));

describe('sanitizeRemotePath property tests', () => {
  it('never returns a path carrying any character from the forbidden class', () => {
    fc.assert(
      fc.property(pathWithForbiddenChars, (input) => {
        let result: string;
        try {
          result = sanitizeRemotePath(input);
        } catch {
          return; // a refusal is the other safe outcome
        }
        expect(result).not.toMatch(MUST_REJECT);
      }),
      { numRuns: 10000 },
    );
  });

  it('returns the input unchanged whenever it returns at all', () => {
    // The one property that separates this from sanitizeCommand: a path is never
    // rewritten. Trimming would retarget the transfer, because a POSIX filename
    // may legitimately begin or end with whitespace.
    fc.assert(
      fc.property(pathWithForbiddenChars, (input) => {
        let result: string;
        try {
          result = sanitizeRemotePath(input);
        } catch {
          return;
        }
        expect(result).toBe(input);
      }),
      { numRuns: 10000 },
    );
  });

  it('remotePathForAudit never throws and never yields an unsafe string', () => {
    fc.assert(
      fc.property(pathWithForbiddenChars, (input) => {
        const result = remotePathForAudit(input);
        expect(result === REJECTED_REMOTE_PATH || result === input).toBe(true);
        expect(result).not.toMatch(MUST_REJECT);
      }),
      { numRuns: 10000 },
    );
  });
});

describe('the two hand-written lists cannot drift apart', () => {
  it('every code the generator emits is one the contract refuses, and nothing is missing', () => {
    // `MUST_REJECT` is written out so the property cannot assert the source
    // equals itself — but `FORBIDDEN_CODES` decides what the generator ever
    // emits, and a shrinking generator is invisible to the property it feeds.
    // Measured: deleting the zero-width entries from FORBIDDEN_CODES alone, and
    // deleting the whole C1 range, both survived the entire suite. Two lists,
    // one contract, and nothing tying them together.
    for (const code of FORBIDDEN_CODES) {
      expect(String.fromCharCode(code), 'U+' + code.toString(16)).toMatch(MUST_REJECT);
    }
    const missing: string[] = [];
    for (let code = 0; code <= 0xffff; code++) {
      if (MUST_REJECT.test(String.fromCharCode(code)) && !FORBIDDEN_CODES.includes(code)) {
        missing.push('U+' + code.toString(16));
      }
    }
    expect(missing, 'codepoints the contract refuses that the generator never emits').toEqual([]);
  });
});

describe('the zero-width joiners sit outside the forbidden class, in both directions', () => {
  const ZWNJ = String.fromCharCode(0x200c);
  const ZWJ = String.fromCharCode(0x200d);

  it('never refuses a path whose only zero-width characters are joiners', () => {
    // The other half of the contract above. ZWNJ and ZWJ are orthography — a
    // Persian or Indic filename needs them, and an emoji sequence is built from
    // them — so a class that refused them refused real input.
    fc.assert(
      fc.property(
        fc.array(
          fc.oneof(
            { weight: 3, arbitrary: fc.constantFrom('report', 'srv', 'data', 'x1') },
            { weight: 2, arbitrary: fc.constantFrom(ZWNJ, ZWJ) },
            { weight: 1, arbitrary: fc.constantFrom('/', '.', '-') },
          ),
          { minLength: 1, maxLength: 20 },
        ).map((parts) => '/srv/' + parts.join('')),
        (input) => {
          expect(() => sanitizeRemotePath(input)).not.toThrow();
          expect(sanitizeRemotePath(input)).toBe(input);
        },
      ),
      { numRuns: 2000 },
    );
  });
});
