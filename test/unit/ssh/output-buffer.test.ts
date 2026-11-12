import { describe, it, expect } from 'vitest';
import { appendCapped, finalizeCapped } from '../../../src/ssh/output-buffer.js';
import { redactText } from '../../../src/guard/redactor.js';

/** Stream `chunks` through the buffer the way exec() does. */
function stream(chunks: string[], cap: number, mode: 'head' | 'tail'): string {
  let buffer = '';
  for (const chunk of chunks) buffer = appendCapped(buffer, chunk, cap, mode);
  return finalizeCapped(buffer, cap, mode);
}

describe('appendCapped — head mode is the historical behaviour', () => {
  it('stops appending once the buffer has reached the cap', () => {
    // Exactly the old `stdout.length < maxOutput ? stdout + chunk : stdout`:
    // the chunk that crosses the cap is still appended whole.
    expect(stream(['AAAA', 'BBBB', 'CCCC'], 5, 'head')).toBe('AAAABBBB');
  });

  it('appends nothing once the cap is reached, regardless of the chunk', () => {
    expect(appendCapped('12345', '6789', 5, 'head')).toBe('12345');
  });
});

describe('appendCapped — tail mode keeps the recent end', () => {
  it('keeps the most recent data across many chunks', () => {
    const chunks = Array.from({ length: 100 }, (_, i) => `#${String(i).padStart(3, '0')}|`);
    const visible = stream(chunks, 25, 'tail');
    expect(visible).toHaveLength(25);
    expect(visible.endsWith('#099|')).toBe(true);
    expect(visible).not.toContain('#000|');
  });

  it('never exceeds twice the cap mid-stream', () => {
    // The 2x slack is a memory bound, not just an implementation detail: without
    // it the buffer grows with the whole stream.
    let buffer = '';
    let longest = 0;
    for (let i = 0; i < 200; i++) {
      buffer = appendCapped(buffer, 'abcdefg', 4, 'tail');
      longest = Math.max(longest, buffer.length);
    }
    expect(longest).toBeLessThanOrEqual(4 * 2);
  });

  it('trims mid-stream to a line start, so progress never shows a cut line', () => {
    let buffer = '';
    for (let i = 0; i < 30; i++) {
      buffer = appendCapped(buffer, `line-${String(i).padStart(2, '0')}\n`, 20, 'tail');
      expect(buffer).toMatch(/^line-\d\d\n/);
    }
  });

  it('is safe for an empty stream', () => {
    expect(stream([''], 100, 'tail')).toBe('');
    expect(stream([''], 100, 'head')).toBe('');
  });

  it('keeps nothing at a cap of 0 rather than the whole stream', () => {
    // `slice(-0)` is `slice(0)`: a negative-index trim would return everything.
    expect(appendCapped('abc', 'def', 0, 'tail')).toBe('');
    expect(finalizeCapped('abcdef', 0, 'tail')).toBe('');
  });
});

describe('finalizeCapped — the value handed to the caller', () => {
  it('returns short tail buffers unchanged', () => {
    expect(finalizeCapped('abc', 10, 'tail')).toBe('abc');
  });

  it('leaves head output untouched, including over-cap chunks', () => {
    expect(finalizeCapped('AAAABBBB', 5, 'head')).toBe('AAAABBBB');
  });

  it('starts at the next line when the cut lands inside one', () => {
    // The last 9 characters start inside "bbbb", which is dropped whole.
    expect(finalizeCapped('aaaa\nbbbb\ncc\nddd\n', 9, 'tail')).toBe('cc\nddd\n');
  });

  it('keeps the line the cut lands at the start of', () => {
    // The cut falls exactly after a line break: "cd" is whole and stays.
    expect(finalizeCapped('ab\ncd\nef', 5, 'tail')).toBe('cd\nef');
  });

  it('cuts mid-line only when the window holds no line to start at', () => {
    // A break only at the very end would leave nothing after it.
    expect(finalizeCapped('xxxxxxxxxx\n', 4, 'tail')).toBe('xxx\n');
    expect(finalizeCapped('0123456789abcde', 5, 'tail')).toBe('abcde');
  });

  it('never starts with half of a surrogate pair', () => {
    // Odd caps over mixed content: the plain cut lands on the low half of an emoji.
    const visible = finalizeCapped('x🙂🙂', 3, 'tail');
    expect(visible).not.toMatch(/^[\uDC00-\uDFFF]/);
    expect(visible).toBe('🙂');
    expect(finalizeCapped('aaaa🙂b', 2, 'tail')).toBe('b');
  });
});

describe('tail mode and redaction', () => {
  it('does not cut a secret away from its name', () => {
    // Redaction runs on the trimmed output. A plain character cut left
    // "SSWORD=hunter2", whose name is not a sensitive one, and the value went through.
    const visible = stream(['x'.repeat(40), '\nDB_PASSWORD=hunter2\n', 'done\n'], 20, 'tail');
    const redacted = redactText(visible, { entropyScan: true });
    expect(redacted).not.toContain('hunter2');
    expect(redacted).toContain('done');
  });
});
