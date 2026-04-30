import { describe, it, expect } from 'vitest';
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import { resultToMcpContent } from '../src/index';
import type { ExecResult } from '../src/transports/types';

// Regression: previously any non-empty stderr threw "Error (code 0):" even when
// the command exited 0. sudo-exec via ssh2 transport reliably tripped this
// because sudo `-p "" -S` writes a trailing newline to stderr after consuming
// the password, and many tools (curl/git/apt/dotnet) emit progress on stderr.

describe('resultToMcpContent', () => {
  const baseOk: ExecResult = { stdout: '', stderr: '', exitCode: 0 };

  it('returns stdout on plain success', () => {
    const r = resultToMcpContent({ ...baseOk, stdout: 'hello\n' });
    expect(r.content[0]).toEqual({ type: 'text', text: 'hello\n' });
  });

  it('does NOT throw on exit 0 with stderr (regression for sudo-exec "Error (code 0):")', () => {
    const r = resultToMcpContent({
      stdout: 'uid=0(root)\n',
      stderr: '\n', // sudo -S trailing newline
      exitCode: 0,
    });
    expect((r.content[0] as any).type).toBe('text');
    // Whitespace-only stderr is dropped; stdout is returned as-is.
    expect((r.content[0] as any).text).toBe('uid=0(root)\n');
  });

  it('appends substantive stderr to stdout on exit 0', () => {
    const r = resultToMcpContent({
      stdout: 'apt output\n',
      stderr: 'WARNING: apt does not have a stable CLI interface.\n',
      exitCode: 0,
    });
    const text = (r.content[0] as any).text as string;
    expect(text).toContain('apt output');
    expect(text).toContain('[stderr]');
    expect(text).toContain('stable CLI interface');
  });

  it('returns stderr-only output when stdout is empty and exit 0', () => {
    const r = resultToMcpContent({
      stdout: '',
      stderr: 'progress info on stderr\n',
      exitCode: 0,
    });
    expect((r.content[0] as any).text).toBe('progress info on stderr\n');
  });

  it('throws on non-zero exit with stderr', () => {
    expect(() => resultToMcpContent({
      stdout: '',
      stderr: 'permission denied\n',
      exitCode: 1,
    })).toThrow(McpError);
  });

  it('treats null exitCode as 0 (legacy ssh2 close without code)', () => {
    const r = resultToMcpContent({
      stdout: 'data',
      stderr: '\r\n',
      exitCode: null,
    });
    expect((r.content[0] as any).text).toBe('data');
  });

  it('routes timeout category to typed error', () => {
    expect(() => resultToMcpContent({
      stdout: '',
      stderr: 'Command execution timed out after 60000ms',
      exitCode: null,
      category: 'timeout',
    })).toThrow(McpError);
  });

  it('routes auth category to typed error', () => {
    expect(() => resultToMcpContent({
      stdout: '',
      stderr: 'permission denied (publickey)',
      exitCode: 255,
      category: 'auth',
    })).toThrow(/SSH authentication error/);
  });
});
