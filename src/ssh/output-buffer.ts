import type { OutputTruncation } from '../types.js';

/**
 * Bounded accumulation for a command's stdout and stderr.
 *
 * The cap is `maxOutputBytes`, counted, as it always was, in JavaScript string length
 * (UTF-16 code units), not bytes on the wire. `head` keeps the start of the stream and
 * `tail` keeps the end; which one an operator wants depends on the command, and for a
 * `grep` over a large log it is the end.
 *
 * Tail mode never hands back a partial first line when the window holds a line break.
 * Redaction runs on this module's output, and its name-keyed layer reads the name to
 * the left of `=` or `Bearer`: a cut through `DB_PASSWORD=...` that left `SSWORD=...`
 * would pass the value through unmasked. Head mode never had that exposure, because it
 * cuts at the end, where the name has already been kept. So the window starts after the
 * first line break past the cut, and only a window with no line break in it is cut
 * mid-line — then at a character boundary, never inside a surrogate pair.
 */

/**
 * Append a chunk under a cap.
 *
 * Head mode is the historical behaviour, kept exactly: stop appending once the buffer
 * has reached the cap, so the chunk that crosses it is kept whole and the result can
 * exceed the cap by up to one chunk. Tail mode always appends and, once the buffer
 * passes twice the cap, trims it back to one cap's worth. The slack keeps the trim
 * amortised; trimming on every chunk would copy the buffer per chunk.
 */
export function appendCapped(
  previous: string,
  chunk: string,
  maxChars: number,
  mode: OutputTruncation,
): string {
  if (mode === 'head') return previous.length >= maxChars ? previous : previous + chunk;
  const next = previous + chunk;
  return next.length > maxChars * 2 ? tailWindow(next, maxChars) : next;
}

/**
 * The value the caller sees: head output untouched, tail output trimmed to at most one
 * cap, starting on a line boundary where the window allows it.
 */
export function finalizeCapped(value: string, maxChars: number, mode: OutputTruncation): string {
  if (mode === 'head' || value.length <= maxChars) return value;
  return tailWindow(value, maxChars);
}

/**
 * The last `maxChars` of `value` at most, moved forward to the next line start. Both
 * callers pass a value longer than `maxChars`, so `cut` is positive, and a cap of 0
 * keeps nothing rather than reaching `slice(-0)`, which would keep everything.
 */
function tailWindow(value: string, maxChars: number): string {
  const cut = value.length - maxChars;
  if (value[cut - 1] === '\n') return value.slice(cut);
  const lineBreak = value.indexOf('\n', cut);
  // A break with text after it: start there. A break only at the very end (or none)
  // means the window is one line; dropping it would return nothing.
  if (lineBreak !== -1 && lineBreak + 1 < value.length) return value.slice(lineBreak + 1);
  const code = value.charCodeAt(cut);
  const lowSurrogate = code >= 0xdc00 && code <= 0xdfff;
  return value.slice(lowSurrogate ? cut + 1 : cut);
}
