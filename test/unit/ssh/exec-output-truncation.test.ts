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
  vi.restoreAllMocks();
  vi.doUnmock('ssh2');
  vi.resetModules();
});

async function connect(overrides: Partial<Profile>) {
  const { SSHConnection } = await import('../../../src/ssh/connection.js');
  return new SSHConnection(
    makeProfile({ maxOutputBytes: 5, ...overrides }),
    { password: 'x' } as never,
    new Map(),
    'insecure',
  );
}

async function exec(overrides: Partial<Profile>) {
  return (await connect(overrides)).exec('cat /var/log/big.log', { timeoutMs: 30_000 });
}

describe('exec() applies the configured truncation to both streams', () => {
  // Each stream passes twice the cap mid-stream and ends between one and two caps, so
  // the append and the final trim each change the answer: skipping either, or wiring
  // a stream back to head mode, gives a different string.
  it('tail keeps the last bytes of stdout and stderr', async () => {
    stdoutChunks = ['AAAA', 'BBBB', 'CCCC', 'DD'];
    stderrChunks = ['ERR1', 'ERR2', 'ERR3', 'E4'];
    const result = await exec({ outputTruncation: 'tail' });
    expect(result.stdout).toBe('CCCDD');
    expect(result.stderr).toBe('RR3E4');
  });

  it('head keeps the start of both streams', async () => {
    stdoutChunks = ['AAAA', 'BBBB', 'CCCC', 'DD'];
    stderrChunks = ['ERR1', 'ERR2', 'ERR3', 'E4'];
    const result = await exec({ outputTruncation: 'head' });
    expect(result.stdout).toBe('AAAABBBB');
    expect(result.stderr).toBe('ERR1ERR2');
  });

  it('reads the mode per command, so a reload applies to the next one', async () => {
    stdoutChunks = ['AAAA', 'BBBB', 'CCCC', 'DD'];
    const conn = await connect({ outputTruncation: 'head' });
    expect((await conn.exec('cat x', { timeoutMs: 30_000 })).stdout).toBe('AAAABBBB');
    conn.replaceProfile({ ...conn.profile, outputTruncation: 'tail' });
    expect((await conn.exec('cat x', { timeoutMs: 30_000 })).stdout).toBe('CCCDD');
  });

  it('reports progress as data received, which never goes backwards', async () => {
    // Tail mode shrinks the buffer at each trim; MCP progress must only increase.
    let now = 0;
    vi.spyOn(Date, 'now').mockImplementation(() => (now += 1_000));
    stdoutChunks = ['AAAA', 'BBBB', 'CCCC', 'DD'];
    const reported: number[] = [];
    await (await connect({ outputTruncation: 'tail' })).exec('cat x', {
      timeoutMs: 30_000,
      onProgress: (bytes) => reported.push(bytes),
    });
    expect(reported).toEqual([4, 8, 12, 14]);
  });
});
