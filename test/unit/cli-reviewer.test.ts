import { describe, expect, it } from 'vitest';
import { parseReviewerTimeout, parseReviewerUrl } from '../../src/cli.js';

describe('reviewer CLI parsing', () => {
  it('normalizes an HTTP(S) reviewer URL', () => {
    expect(parseReviewerUrl('http://localhost:8080/')).toBe('http://localhost:8080');
    expect(parseReviewerUrl('https://reviewer.internal/base/')).toBe('https://reviewer.internal/base');
  });

  it.each([undefined, null, '', 'localhost:8080', 'file:///tmp/reviewer'])('rejects unusable URL %o', (url) => {
    expect(() => parseReviewerUrl(url)).toThrow(/reviewerUrl/);
  });

  it('rejects credentials embedded in the URL', () => {
    expect(() => parseReviewerUrl('https://user:secret@reviewer.internal')).toThrow(/credentials/);
  });

  it('defaults review timeout to 30 seconds', () => {
    expect(parseReviewerTimeout(undefined)).toBe(30_000);
  });

  it.each(['1000', '30000', '120000'])('accepts bounded timeout %s', (timeout) => {
    expect(parseReviewerTimeout(timeout)).toBe(Number(timeout));
  });

  it.each([null, '', '999', '120001', '1.5', 'slow'])('rejects invalid timeout %o', (timeout) => {
    expect(() => parseReviewerTimeout(timeout)).toThrow(/reviewerTimeoutMs/);
  });
});
