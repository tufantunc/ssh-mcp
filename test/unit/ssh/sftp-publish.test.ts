import { describe, it, expect } from 'vitest';
import type { SFTPWrapper } from 'ssh2';
import { publishRemote } from '../../../src/ssh/sftp.js';

/**
 * The unadvertised-extension path, which no server in this repo can produce.
 *
 * docker-compose pins OpenSSH's sftp-server and the Dropbear image installs
 * openssh-sftp-server on top, so `hardlink@openssh.com` and
 * `posix-rename@openssh.com` are always advertised there. ssh2 reports a
 * missing extension by throwing *before* it sends anything, with no `code` on
 * the Error — which is why an earlier version's `code === 8` test left the
 * plain-rename fallback unreachable and `overwrite: true` failing outright.
 */
const UNADVERTISED = () => {
  throw new Error('Server does not support this extended request');
};

const BOUNDS = { maxBytes: 1024, idleTimeoutMs: 1000 };

/** Only the four methods publishRemote can reach. */
function stub(over: Partial<Record<string, unknown>> = {}): {
  sftp: SFTPWrapper;
  calls: string[];
} {
  const calls: string[] = [];
  const sftp = {
    ext_openssh_hardlink: (_o: string, _n: string, cb: (e?: Error) => void) => {
      calls.push('hardlink');
      cb();
    },
    ext_openssh_rename: (_o: string, _n: string, cb: (e?: Error) => void) => {
      calls.push('ext-rename');
      cb();
    },
    rename: (_o: string, _n: string, cb: (e?: Error) => void) => {
      calls.push('rename');
      cb();
    },
    ...over,
  } as unknown as SFTPWrapper;
  return { sftp, calls };
}

describe('publishRemote', () => {
  describe('overwrite: true', () => {
    it('uses the OpenSSH rename extension when the server advertises it', async () => {
      const { sftp, calls } = stub();
      await publishRemote(sftp, '/t/.part', '/t/f', { ...BOUNDS, overwrite: true });
      expect(calls).toEqual(['ext-rename']);
    });

    // The fix. Previously this rejected with ssh2's internal message and the
    // fallback never ran, so uploads failed on every server without the
    // extension even though plain SSH_FXP_RENAME would have worked.
    it('falls back to plain rename when the extension throws', async () => {
      const { sftp, calls } = stub({ ext_openssh_rename: UNADVERTISED });
      await publishRemote(sftp, '/t/.part', '/t/f', { ...BOUNDS, overwrite: true });
      expect(calls).toEqual(['rename']);
    });

    it('falls back when the server answers OP_UNSUPPORTED instead of throwing', async () => {
      const { sftp, calls } = stub({
        ext_openssh_rename: (_o: string, _n: string, cb: (e?: Error) => void) => {
          calls.push('ext-rename');
          cb(Object.assign(new Error('unsupported'), { code: 8 }));
        },
      });
      await publishRemote(sftp, '/t/.part', '/t/f', { ...BOUNDS, overwrite: true });
      expect(calls).toEqual(['ext-rename', 'rename']);
    });

    it('surfaces a real rename failure rather than retrying', async () => {
      const { sftp, calls } = stub({
        ext_openssh_rename: (_o: string, _n: string, cb: (e?: Error) => void) => {
          calls.push('ext-rename');
          cb(Object.assign(new Error('permission denied'), { code: 3 }));
        },
      });
      await expect(
        publishRemote(sftp, '/t/.part', '/t/f', { ...BOUNDS, overwrite: true }),
      ).rejects.toThrow(/permission denied/);
      expect(calls).toEqual(['ext-rename']);
    });
  });

  describe('overwrite: false', () => {
    it('publishes with the hardlink extension', async () => {
      const { sftp, calls } = stub();
      await publishRemote(sftp, '/t/.part', '/t/f', BOUNDS);
      expect(calls).toEqual(['hardlink']);
    });

    // Without the wrapper the caller got ssh2's opaque internal string, and the
    // one message that tells them what to do about it was unreachable.
    it('gives the actionable message when the extension throws', async () => {
      const { sftp } = stub({ ext_openssh_hardlink: UNADVERTISED });
      await expect(publishRemote(sftp, '/t/.part', '/t/f', BOUNDS)).rejects.toThrow(
        /cannot atomically publish a file without overwrite; retry with overwrite=true/,
      );
    });

    it('gives the same message for an OP_UNSUPPORTED answer', async () => {
      const { sftp } = stub({
        ext_openssh_hardlink: (_o: string, _n: string, cb: (e?: Error) => void) =>
          cb(Object.assign(new Error('unsupported'), { code: 8 })),
      });
      await expect(publishRemote(sftp, '/t/.part', '/t/f', BOUNDS)).rejects.toThrow(
        /retry with overwrite=true/,
      );
    });

    // v3 has no dedicated "already exists" status, so OpenSSH reports EEXIST as
    // FAILURE — the only code that actually means what the race message says.
    it('reports a lost race only for FAILURE', async () => {
      const { sftp } = stub({
        ext_openssh_hardlink: (_o: string, _n: string, cb: (e?: Error) => void) =>
          cb(Object.assign(new Error('failure'), { code: 4 })),
      });
      await expect(publishRemote(sftp, '/t/.part', '/t/f', BOUNDS)).rejects.toThrow(
        /Refusing to overwrite a remote file created during transfer/,
      );
    });

    // Everything else used to be reported as a lost race too, sending the
    // reader to look for a concurrent writer that never existed.
    it('passes through any other server error instead of blaming a race', async () => {
      const { sftp } = stub({
        ext_openssh_hardlink: (_o: string, _n: string, cb: (e?: Error) => void) =>
          cb(Object.assign(new Error('permission denied'), { code: 3 })),
      });
      let message = '';
      try {
        await publishRemote(sftp, '/t/.part', '/t/f', BOUNDS);
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toMatch(/SFTP upload publish failed: permission denied/);
      expect(message).not.toMatch(/created during transfer/);
    });
  });
});
