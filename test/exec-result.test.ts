import { describe, it, expect } from 'vitest';
import { buildExecResult } from '../src/index';

describe('buildExecResult', () => {
  describe('successful commands', () => {
    it('returns stdout when the command exits 0 with no stderr', () => {
      const result = buildExecResult(0, null, 'hello\n', '');
      expect(result).toEqual({ ok: true, text: 'hello\n' });
    });

    it('still succeeds when a command exits 0 but writes to stderr', () => {
      // Regression: this used to be reported as an error, and stdout was lost.
      // Real examples: git, npm, apt, systemctl, curl progress output.
      const result = buildExecResult(0, null, 'real output\n', 'Warning: deprecated\n');
      expect(result.ok).toBe(true);
      expect((result as { text: string }).text).toContain('real output');
      expect((result as { text: string }).text).toContain('Warning: deprecated');
    });

    it('separates stdout and stderr with a newline when stdout lacks one', () => {
      const result = buildExecResult(0, null, 'no trailing newline', 'warning\n');
      expect((result as { text: string }).text).toBe('no trailing newline\nwarning\n');
    });

    it('does not add a second newline when stdout already ends with one', () => {
      const result = buildExecResult(0, null, 'line\n', 'warning\n');
      expect((result as { text: string }).text).toBe('line\nwarning\n');
    });

    it('returns stderr alone when the command wrote nothing to stdout', () => {
      const result = buildExecResult(0, null, '', 'only stderr\n');
      expect(result).toEqual({ ok: true, text: 'only stderr\n' });
    });
  });

  describe('failed commands', () => {
    it('fails on a non-zero exit code and reports stderr', () => {
      const result = buildExecResult(1, null, '', 'command not found\n');
      expect(result.ok).toBe(false);
      expect((result as { message: string }).message).toContain('code 1');
      expect((result as { message: string }).message).toContain('command not found');
    });

    it('fails on a non-zero exit code even when stderr is empty', () => {
      // Regression: a silent failure used to be reported as success.
      const result = buildExecResult(1, null, 'partial output\n', '');
      expect(result.ok).toBe(false);
      expect((result as { message: string }).message).toContain('code 1');
      expect((result as { message: string }).message).toContain('partial output');
    });

    it('reports "(no output)" when a command fails silently', () => {
      const result = buildExecResult(2, null, '', '');
      expect(result.ok).toBe(false);
      expect((result as { message: string }).message).toContain('(no output)');
    });

    it('fails when the command was killed by a signal', () => {
      const result = buildExecResult(null, 'SIGKILL', 'partial\n', '');
      expect(result.ok).toBe(false);
      expect((result as { message: string }).message).toContain('SIGKILL');
    });
  });

  describe('missing exit code', () => {
    it('succeeds when no exit code is reported and stderr is empty', () => {
      const result = buildExecResult(null, null, 'output\n', '');
      expect(result).toEqual({ ok: true, text: 'output\n' });
    });

    it('fails when no exit code is reported but stderr has content', () => {
      const result = buildExecResult(undefined, null, '', 'something broke\n');
      expect(result.ok).toBe(false);
      expect((result as { message: string }).message).toContain('something broke');
    });
  });
});
