import { describe, it, expect } from 'vitest';
import { Readable } from 'node:stream';
import type { SFTPWrapper } from 'ssh2';
import { SftpClient } from '../../../src/ssh/sftp.js';

/**
 * download()'s size probe, against a server that never answers it.
 *
 * This cannot be driven from the integration suite: the probe is bounded by the
 * profile's command timeout, and a stat against a container on loopback answers
 * well inside even a 1ms bound, so the timer never wins. An earlier attempt to
 * test it there passed identically with the fix reverted — it pinned nothing.
 * Here the stub simply never calls back, so "never answers" is exact.
 */
function clientWith(sftp: Partial<SFTPWrapper>, timeout: number) {
  const conn = {
    profile: { maxOutputBytes: 1_048_576, timeout },
    ensureConnected: async () => {},
    getClient: () => ({
      sftp: (cb: (err: Error | undefined, handle: SFTPWrapper) => void) =>
        cb(undefined, { end: () => {}, ...sftp } as SFTPWrapper),
    }),
  };
  return new SftpClient(conn as never);
}

describe('download()', () => {
  it('still downloads when the size probe never answers', async () => {
    const body = Buffer.from('probe never answered, transfer still ran');
    const client = clientWith(
      {
        stat: () => { /* deliberately never calls back */ },
        createReadStream: () => Readable.from([body]) as never,
      },
      30,
    );

    const started = Date.now();
    const out = await client.download({ remotePath: '/tmp/x' });

    expect(out.toString()).toBe(body.toString());
    // It waited for the bound and then moved on, rather than hanging.
    expect(Date.now() - started).toBeGreaterThanOrEqual(25);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  // The other half of "the size is unknown": the server answers, but with an
  // error — no permission on the parent, a path that is a directory. That was
  // already non-fatal before the bound was added, and it has to stay that way,
  // or bounding the probe would have quietly turned a working download into a
  // failure.
  it('still downloads when the probe answers with an error', async () => {
    const body = Buffer.from('stat refused, transfer still ran');
    const client = clientWith(
      {
        stat: ((_p: string, cb: (e: Error | undefined) => void) =>
          cb(new Error('permission denied'))) as never,
        createReadStream: () => Readable.from([body]) as never,
      },
      1000,
    );

    const out = await client.download({ remotePath: '/tmp/x' });
    expect(out.toString()).toBe(body.toString());
  });

  it('refuses up front when the probe does answer and the file is too big', async () => {
    const client = clientWith(
      {
        stat: ((_p: string, cb: (e: Error | undefined, s: { size: number }) => void) =>
          cb(undefined, { size: 99_999_999 })) as never,
        createReadStream: () => Readable.from([Buffer.alloc(1)]) as never,
      },
      1000,
    );

    await expect(client.download({ remotePath: '/tmp/big' })).rejects.toThrow(
      /exceeds the 1048576 byte limit/,
    );
  });

  // The cap is enforced on the stream too, because the probe can be stale,
  // unavailable, or a lie — which is precisely the case above.
  it('enforces the cap mid-stream when the probe could not answer', async () => {
    const client = clientWith(
      {
        stat: () => { /* never answers */ },
        createReadStream: () => Readable.from([Buffer.alloc(64), Buffer.alloc(64)]) as never,
      },
      20,
    );

    await expect(
      client.download({ remotePath: '/tmp/x', maxBytes: 100 }),
    ).rejects.toThrow(/exceeded the 100 byte limit while transferring/);
  });
});
