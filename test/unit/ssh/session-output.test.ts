import { describe, it, expect, vi, afterEach } from 'vitest';
import { trimNewlines, generateSessionMarker } from '../../../src/ssh/session.js';

describe('trimNewlines', () => {
  it('strips leading and trailing newlines but nothing in between', () => {
    expect(trimNewlines('\n\nhello\n\n')).toBe('hello');
    expect(trimNewlines('a\n\nb')).toBe('a\n\nb');
    expect(trimNewlines('no newlines')).toBe('no newlines');
    expect(trimNewlines('\n\n\n')).toBe('');
    expect(trimNewlines('')).toBe('');
  });

  it('leaves other whitespace alone, as the previous regexes did', () => {
    expect(trimNewlines('\n  spaced  \n')).toBe('  spaced  ');
    expect(trimNewlines('\n\ttabbed\t\n')).toBe('\ttabbed\t');
  });

  // The regex this replaced was /\n+$/, unanchored at the start: on output that
  // is mostly newlines and does not end in one, the engine retried `\n+` from
  // every offset. The session buffer holds up to 2 MB of remote command output,
  // where that measured around 25 minutes — on the event loop every other
  // session and connection shares.
  it('stays linear on output built to make the old pattern backtrack', () => {
    const pathological = '\n'.repeat(2_000_000) + 'a';

    const started = process.hrtime.bigint();
    const result = trimNewlines(pathological);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    expect(result).toBe('a');
    // Linear work on 2 MB is single-digit milliseconds; the quadratic version
    // did not finish in minutes. A second is far below one and far above the
    // other, so this asserts the difference rather than machine speed.
    expect(elapsedMs).toBeLessThan(1000);
  });
});

describe('generateSessionMarker', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('produces values safe for both the printf and the RegExp they are built into', () => {
    for (let i = 0; i < 100; i++) {
      // base64url only: no quote can break out of the single-quoted printf, and
      // no metacharacter can change the meaning of the trailer pattern.
      expect(generateSessionMarker()).toMatch(/^[A-Za-z0-9_-]{16}$/);
    }
  });

  it('does not repeat', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(generateSessionMarker());
    expect(seen.size).toBe(1000);
  });

  // Forging a marker lets a remote host emit its own trailer and dictate the
  // exit code this server records. Math.random() is reconstructible from
  // observed output, and every marker is sent to that host in the clear — so
  // the guarantee is that markers do not come from it at all.
  it('does not draw from Math.random', () => {
    const random = vi.spyOn(Math, 'random').mockReturnValue(0.5);

    const first = generateSessionMarker();
    const second = generateSessionMarker();

    expect(random).not.toHaveBeenCalled();
    expect(first).not.toBe(second);
  });
});
