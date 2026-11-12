import type { OutputTruncation } from '../types.js';

/**
 * Bounded accumulation for command output.
 *
 * `read-command` used to keep the *first* `maxOutputBytes` of a stream and drop
 * everything after it. That is a bad default for the case operators hit most:
 * `grep pattern /var/log/big.log` returns the oldest matches and silently loses
 * every recent one, so a plausible-looking truncated answer says "nothing
 * happened" about the window the caller actually cared about. A visible error is
 * safer than truncation that looks complete; where truncation is unavoidable,
 * `tail` mode makes the recent end the one that survives without asking the
 * operator to remember `| tail` on every command.
 *
 * Tail mode keeps up to twice the cap while streaming, then drops down to one cap
 * from the front. The 2x slack is the whole point: trimming back to the cap on
 * every chunk would copy the whole buffer per chunk (quadratic in the stream
 * length), while the slack keeps memory bounded at 2x the configured cap and
 * makes the copies amortised. `finalizeCapped` then hands the caller exactly the
 * last `maxBytes` characters.
 *
 * Lengths are JavaScript string lengths (UTF-16 code units), matching the cap that
 * `maxOutputBytes` already enforced; this is not a count of bytes on the wire.
 */

/**
 * Append a chunk under a cap.
 *
 * Head mode is the historical behaviour, kept byte-for-byte: stop appending once
 * the buffer has reached the cap. Tail mode always appends, but once the buffer
 * passes twice the cap it is cut back to the last `maxBytes`.
 */
export function appendCapped(
  previous: string,
  chunk: string,
  maxBytes: number,
  mode: OutputTruncation,
): string {
  if (mode === 'head') return previous.length >= maxBytes ? previous : previous + chunk;
  // The config schema requires a positive cap; treating a non-positive one as
  // "keep nothing" keeps `slice(-0)` from returning the whole stream.
  if (maxBytes <= 0) return '';
  const next = previous + chunk;
  return next.length > maxBytes * 2 ? next.slice(-maxBytes) : next;
}

/**
 * The value the caller sees.
 *
 * Head mode returns the buffer untouched, so today's output is unchanged. Tail
 * mode bounds it to the last `maxBytes`, which is also the final trim if the
 * stream ended before the 2x slack was reached.
 */
export function finalizeCapped(value: string, maxBytes: number, mode: OutputTruncation): string {
  if (mode === 'head') return value;
  if (maxBytes <= 0) return '';
  return value.length > maxBytes ? value.slice(-maxBytes) : value;
}
