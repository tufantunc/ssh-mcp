import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { Profile } from '../../../src/types.js';
import { fakeSsh2Channel } from '../../helpers/fake-channel.js';
import { makeProfile } from '../../fixtures/profile.js';

/**
 * The cap must be applied to both streams, and the configured end must be the
 * one the caller receives. The helper's own tests cover the arithmetic; this
 * drives the real `exec()` path so a future edit cannot wire one stream or forget
 * the final trim.
 */

let stdoutChunks: string[];
let stderrChunks: string[];

beforeEach(() => {
  stdoutChunks = [];
  stderrChunks = [];
  vi.resetModules();
  vi.doMock('ssh2', () => {
    class FakeClient extends EventEmitter {
      connect() { setTimeout(() => this.emit('ready'), 0); return this; }
      exec(
        _cmd: string,
        _opts: unknown,
        cb: (err: Error | undefined, stream: unknown) => void,
      ) {
        const { channel } = fakeSsh2Channel();
        setTimeout(() => cb(undefined, channel), 0);
        // `exec()` attaches its listeners in the promise continuation, so the
        // data has to arrive on a later tick than the callback.
        setTimeout(() => {
          for (const chunk of stdoutChunks) channel.emit('data', Buffer.from(chunk));
          for (const chunk of stderrChunks) channel.stderr.emit('data', Buffer.from(chunk));
          channel.emit('close', 0, null);
        }, 1);
      }
      end() { /* nothing to tear down */ }
    }
    return { Client: FakeClient, default: { Client: FakeClient } };
  });
});

afterEach(() => {
  vi.doUnmock('ssh2');
  vi.resetModules();
});

async function exec(overrides: Partial<Profile>) {
  const { SSHConnection } = await import('../../../src/ssh/connection.js');
  const conn = new SSHConnection(
    makeProfile({ maxOutputBytes: 5, ...overrides }),
    { password: 'x' } as never,
    new Map(),
    'insecure',
  );
  return conn.exec('cat /var/log/big.log', { timeoutMs: 30_000 });
}

describe('exec() applies the configured truncation to both streams', () => {
  it('tail keeps the last bytes of stdout and stderr', async () => {
    stdoutChunks = ['AAAA', 'BBBB', 'CCCC'];
    stderrChunks = ['ERR1', 'ERR2'];
    const result = await exec({ outputTruncation: 'tail' });
    expect(result.stdout).toBe('BCCCC');
    expect(result.stderr).toBe('1ERR2');
  });

  it('defaults to head when the profile omits outputTruncation', async () => {
    stdoutChunks = ['AAAA', 'BBBB', 'CCCC'];
    stderrChunks = ['ERR1', 'ERR2'];
    const result = await exec({});
    expect(result.stdout).toBe('AAAABBBB');
    expect(result.stderr).toBe('ERR1ERR2');
  });
});
