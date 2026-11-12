import { describe, it, expect } from 'vitest';
import { appendCapped, finalizeCapped } from '../../../src/ssh/output-buffer.js';

describe('appendCapped — head mode is the historical behaviour', () => {
  it('stops appending once the buffer has reached the cap', () => {
    let buffer = '';
    for (const chunk of ['AAAA', 'BBBB', 'CCCC']) {
      buffer = appendCapped(buffer, chunk, 5, 'head');
    }
    // Exactly the old `stdout.length < maxOutput ? stdout + chunk : stdout`:
    // the chunk that crosses the cap is still appended whole.
    expect(buffer).toBe('AAAABBBB');
    expect(finalizeCapped(buffer, 5, 'head')).toBe('AAAABBBB');
  });

  it('appends nothing once the cap is reached, regardless of the chunk', () => {
    expect(appendCapped('12345', '6789', 5, 'head')).toBe('12345');
  });
});

describe('appendCapped — tail mode keeps the recent end', () => {
  it('keeps the most recent data across many chunks', () => {
    let buffer = '';
    for (let i = 0; i < 100; i++) {
      buffer = appendCapped(buffer, `#${String(i).padStart(3, '0')}|`, 25, 'tail');
    }
    // Mid-stream the buffer is allowed the 2x slack; the caller sees one cap.
    expect(buffer.length).toBeLessThanOrEqual(50);
    const visible = finalizeCapped(buffer, 25, 'tail');
    expect(visible.length).toBe(25);
    expect(visible.endsWith('#099|')).toBe(true);
    expect(visible).not.toContain('#000|');
  });

  it('never exceeds twice the cap mid-stream', () => {
    // The 2x slack is a memory bound, not just an implementation detail: without
    // it the buffer grows with the whole stream.
    let buffer = '';
    const observed: number[] = [];
    for (let i = 0; i < 200; i++) {
      buffer = appendCapped(buffer, 'abcdefg', 4, 'tail');
      observed.push(buffer.length);
    }
    expect(Math.max(...observed)).toBeLessThanOrEqual(4 * 2);
  });

  it('survives multi-byte content at a chunk boundary', () => {
    let buffer = '';
    // Each emoji is two UTF-16 code units; the cap is an even number of units,
    // so a trim lands on a character boundary and cannot split a surrogate pair.
    for (let i = 0; i < 20; i++) {
      buffer = appendCapped(buffer, '🙂🙂🙂', 6, 'tail');
    }
    expect(finalizeCapped(buffer, 6, 'tail')).toBe('🙂🙂🙂');
    expect(buffer.length).toBeLessThanOrEqual(12);
  });

  it('is safe for an empty stream', () => {
    expect(appendCapped('', '', 100, 'tail')).toBe('');
    expect(appendCapped('', '', 100, 'head')).toBe('');
    expect(finalizeCapped('', 100, 'tail')).toBe('');
    expect(finalizeCapped('', 100, 'head')).toBe('');
  });
});

describe('finalizeCapped — the value handed to the caller', () => {
  it('bounds tail output to the last maxBytes', () => {
    expect(finalizeCapped('0123456789abcde', 5, 'tail')).toBe('abcde');
  });

  it('leaves head output untouched, including over-cap chunks', () => {
    expect(finalizeCapped('AAAABBBB', 5, 'head')).toBe('AAAABBBB');
  });

  it('returns short tail buffers unchanged', () => {
    expect(finalizeCapped('abc', 10, 'tail')).toBe('abc');
  });
});
