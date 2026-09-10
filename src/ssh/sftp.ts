import type { SFTPWrapper } from 'ssh2';
import { Readable, type Writable } from 'node:stream';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path/posix';
import type { SftpUploadOpts, SftpDownloadOpts, SftpStat } from '../types.js';
import type { SSHConnection } from './connection.js';
import { openWithRetry } from './channel-retry.js';

export interface FileTransferOptions {
  maxBytes: number;
  /**
   * Bounds each *step* of a transfer rather than the transfer as a whole: a
   * metadata round-trip, or a stretch of the copy with no bytes moving.
   *
   * A single wall-clock budget for the whole operation cannot serve both the
   * byte cap and the wire: with a 1 GiB cap and a 60s budget, a transfer has to
   * sustain 17.9 MB/s or die mid-stream, so the shipped cap was unreachable at
   * the shipped timeout. Re-arming on progress separates the two questions —
   * "is this connection still moving?" gets a tight answer, and how long a
   * large file may legitimately take stops being a function of it.
   */
  idleTimeoutMs: number;
  abortSignal?: AbortSignal;
  overwrite?: boolean;
  mode?: number;
}

export interface SftpListResult {
  entries: SftpStat[];
  truncated: boolean;
}

interface DeadlineOptions {
  idleTimeoutMs: number;
  abortSignal?: AbortSignal;
}

/**
 * Copy `source` into `destination`, failing if either stalls or the byte cap is
 * exceeded.
 *
 * The cap is enforced on the stream as it flows, not only from a prior stat:
 * a remote size can be stale, unavailable, or a lie, and a local file can grow
 * while it is read.
 */
async function transfer(
  source: Readable,
  destination: Writable,
  opts: FileTransferOptions,
  direction: 'upload' | 'download',
): Promise<number> {
  const controller = new AbortController();
  let rejectFailure!: (reason: unknown) => void;
  const failure = new Promise<never>((_resolve, reject) => { rejectFailure = reject; });
  const abortStreams = () => {
    const reason = controller.signal.reason instanceof Error
      ? controller.signal.reason
      : new Error(`SFTP file ${direction} aborted`);
    rejectFailure(reason);
    source.destroy();
    destination.destroy();
  };
  const onSourceError = (err: Error) => rejectFailure(err);
  const onDestinationError = (err: Error) => rejectFailure(err);

  // Re-armed after every chunk. A slow-but-live transfer survives; a channel
  // that stops delivering fails within one idle window.
  let idle: ReturnType<typeof setTimeout> | undefined;
  const arm = () => {
    if (idle) clearTimeout(idle);
    idle = setTimeout(
      () => controller.abort(
        new Error(`SFTP file ${direction} stalled: no progress for ${opts.idleTimeoutMs}ms`),
      ),
      opts.idleTimeoutMs,
    );
  };
  const disarm = () => { if (idle) clearTimeout(idle); idle = undefined; };

  const onAbort = () => controller.abort(
    opts.abortSignal?.reason ?? new Error(`SFTP file ${direction} aborted`),
  );
  controller.signal.addEventListener('abort', abortStreams, { once: true });
  source.on('error', onSourceError);
  destination.on('error', onDestinationError);
  opts.abortSignal?.addEventListener('abort', onAbort, { once: true });
  if (opts.abortSignal?.aborted) onAbort();

  let bytes = 0;
  const remoteStream = direction === 'upload' ? destination : source;
  let resolveRemoteClosed!: () => void;
  const remoteClosed = new Promise<void>((resolve) => { resolveRemoteClosed = resolve; });
  const onRemoteClose = () => resolveRemoteClosed();
  remoteStream.once('close', onRemoteClose);
  const waitForRemoteClose = async () => {
    if (remoteStream.closed) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        remoteClosed,
        new Promise<void>((resolve) => {
          timer = setTimeout(resolve, Math.min(opts.idleTimeoutMs, 1_000));
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  arm();
  try {
    const copy = async () => {
      for await (const value of source) {
        if (controller.signal.aborted) throw controller.signal.reason;
        const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
        bytes += chunk.length;
        if (bytes > opts.maxBytes) {
          throw new Error(`SFTP file ${direction} exceeds the ${opts.maxBytes} byte transfer limit`);
        }
        arm();
        if (!destination.write(chunk)) await once(destination, 'drain');
      }
      const completed = new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          destination.removeListener(direction === 'upload' ? 'close' : 'finish', done);
          destination.removeListener('error', failed);
        };
        const done = () => { cleanup(); resolve(); };
        const failed = (err: Error) => { cleanup(); reject(err); };
        destination.once(direction === 'upload' ? 'close' : 'finish', done);
        destination.once('error', failed);
      });
      destination.end();
      if (direction === 'upload' ? !destination.closed : !destination.writableFinished) {
        await completed;
      }
      // A generic Readable may reach EOF without closing itself. SFTP read streams also
      // need an explicit close after EOF so the server receives SSH_FXP_CLOSE before the
      // subsystem channel is ended.
      if (direction === 'download' && !source.closed) source.destroy();
      await waitForRemoteClose();
      if (direction === 'upload' && !source.destroyed) source.destroy();
      return bytes;
    };
    return await Promise.race([copy(), failure]);
  } catch (err) {
    source.destroy();
    destination.destroy();
    await waitForRemoteClose();
    if (controller.signal.aborted && controller.signal.reason instanceof Error) {
      throw controller.signal.reason;
    }
    throw err;
  } finally {
    disarm();
    controller.signal.removeEventListener('abort', abortStreams);
    source.removeListener('error', onSourceError);
    destination.removeListener('error', onDestinationError);
    remoteStream.removeListener('close', onRemoteClose);
    opts.abortSignal?.removeEventListener('abort', onAbort);
  }
}

/**
 * Run one callback-style SFTP operation under its own bound.
 *
 * Every metadata round-trip gets `idleTimeoutMs` measured from its own start,
 * so no single step can hang and none of them consume a budget the next step
 * needs.
 */
function callbackBeforeDeadline<T>(
  opts: DeadlineOptions,
  label: string,
  start: (callback: (err?: Error, value?: T) => void) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (err?: Error, value?: T) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.abortSignal?.removeEventListener('abort', abort);
      if (err) reject(err);
      else resolve(value as T);
    };
    const abort = () => finish(
      opts.abortSignal?.reason instanceof Error
        ? opts.abortSignal.reason
        : new Error(`${label} aborted`),
    );
    const timer = setTimeout(
      () => finish(new Error(`${label} timed out after ${opts.idleTimeoutMs}ms`)),
      opts.idleTimeoutMs,
    );
    opts.abortSignal?.addEventListener('abort', abort, { once: true });
    if (opts.abortSignal?.aborted) abort();
    else {
      try { start(finish); } catch (err) { finish(err as Error); }
    }
  });
}

function remoteTemporaryPath(remotePath: string): string {
  return join(dirname(remotePath), `.ssh-mcp-upload-${randomUUID()}.part`);
}

export class SftpClient {
  constructor(private conn: SSHConnection) {}

  private async withSftp<T>(fn: (sftp: SFTPWrapper) => Promise<T>): Promise<T> {
    // ensureConnected lives inside the retry: Dropbear drops the whole
    // connection under SFTP channel churn, so an attempt can fail because the
    // link died rather than because the channel was refused. Re-establishing
    // before each attempt covers both.
    const sftp = await openWithRetry(async () => {
      await this.conn.ensureConnected();
      const client = this.conn.getClient();
      return new Promise<SFTPWrapper>((resolve, reject) => {
        client.sftp((err, handle) => {
          if (err) {
            reject(new Error(`SFTP error: ${err.message}`));
            return;
          }
          resolve(handle);
        });
      });
    });
    try {
      return await fn(sftp);
    } finally {
      // Every client.sftp() opens a new subsystem channel. Without end() they
      // accumulate for the life of the connection until the server's MaxSessions
      // limit (OpenSSH default: 10) is hit, after which no channel — SFTP, exec
      // or shell — can be opened on this connection any more.
      try { sftp.end(); } catch { /* already torn down */ }
    }
  }

  /**
   * Write string or Buffer content to a remote path.
   *
   * Deliberately a direct write at 0o644, not a staged `.part` published with
   * rename, and `||` rather than `??` so `mode: 0` falls back instead of
   * producing a file nobody can read. This is a pre-existing tool: staging
   * needs write permission on the *directory* where a direct write needs it
   * only on the file, and republishing discards the target's mode, owner and
   * ACL. #185 asked for the text-based tools to stay unchanged, and
   * test/integration/ssh-sftp.test.ts pins all three properties.
   *
   * The streaming path with the opposite trade-offs is uploadFile().
   */
  async upload(opts: SftpUploadOpts): Promise<void> {
    return this.withSftp(async (sftp) => {
      return new Promise<void>((resolve, reject) => {
        const stream = sftp.createWriteStream(opts.remotePath, { mode: opts.mode || 0o644 });
        stream.on('error', reject);
        stream.on('close', resolve);
        stream.end(Buffer.isBuffer(opts.content) ? opts.content : Buffer.from(opts.content));
      });
    });
  }

  /**
   * Upload from an already-open source without buffering it in the MCP process.
   *
   * Publishes through a sibling `.part` so a failed transfer never leaves a
   * half-written file at the destination. That is the right trade for a new
   * tool whose destination is expected to be new, and the wrong one for
   * upload() above.
   */
  async uploadFile(source: Readable, remotePath: string, opts: FileTransferOptions): Promise<number> {
    return this.withSftp(async (sftp) => {
      const exists = async () => callbackBeforeDeadline<boolean>(opts, 'SFTP upload stat', (callback) => {
        sftp.stat(remotePath, (err) => {
          if (!err) callback(undefined, true);
          else if ((err as any).code === 2 || (err as any).code === 'ENOENT') callback(undefined, false);
          else callback(new Error(`SFTP upload stat failed: ${err.message}`));
        });
      });
      if (!opts.overwrite && await exists()) {
        throw new Error('Refusing to overwrite an existing remote file');
      }

      const temporary = remoteTemporaryPath(remotePath);
      let published = false;
      try {
        const destination = sftp.createWriteStream(temporary, { flags: 'wx', mode: opts.mode ?? 0o600 });
        const bytes = await transfer(source, destination, opts, 'upload');
        if (!opts.overwrite && await exists()) {
          throw new Error('Refusing to overwrite a remote file created during transfer');
        }
        await callbackBeforeDeadline<void>(opts, 'SFTP upload publish', (callback) => {
          const standardRename = () => sftp.rename(
            temporary,
            remotePath,
            (err) => callback(err ?? undefined),
          );
          if (!opts.overwrite) {
            // SFTP v3 rename does not portably provide no-clobber semantics. The
            // OpenSSH hardlink extension maps to link(2), which atomically fails if
            // the destination appeared after the second stat check.
            sftp.ext_openssh_hardlink(temporary, remotePath, (err) => {
              if (err) {
                const unsupported = (err as any).code === 8 || (err as any).code === 'OP_UNSUPPORTED';
                callback(new Error(unsupported
                  ? 'The SFTP server cannot atomically publish a file without overwrite; retry with overwrite=true'
                  : 'Refusing to overwrite a remote file created during transfer'));
              } else callback();
            });
            return;
          }
          sftp.ext_openssh_rename(temporary, remotePath, (err) => {
            if ((err as any)?.code === 8 || (err as any)?.code === 'OP_UNSUPPORTED') standardRename();
            else callback(err ?? undefined);
          });
        });
        published = true;
        if (!opts.overwrite) {
          // The hardlink above left two names for one inode; drop ours.
          await this.removeTemporary(sftp, temporary, opts).catch(() => {
            console.error('Warning: an SFTP upload was published but its stale .part hard link could not be removed');
          });
        }
        return bytes;
      } finally {
        if (!published) await this.removeTemporary(sftp, temporary, opts).catch(() => {});
      }
    });
  }

  private async removeTemporary(
    sftp: SFTPWrapper,
    temporary: string,
    opts: DeadlineOptions,
  ): Promise<void> {
    // Cleanup gets its own short bound: it must not extend a failed transfer,
    // and a server that cannot unlink is a warning, never the reported error.
    const bounded = { idleTimeoutMs: Math.min(opts.idleTimeoutMs, 1_000) };
    return callbackBeforeDeadline<void>(
      bounded,
      'SFTP upload cleanup',
      (callback) => sftp.unlink(temporary, (err) => callback(err ?? undefined)),
    );
  }

  /** Download into an already-open destination without buffering it in memory. */
  async downloadFile(remotePath: string, destination: Writable, opts: FileTransferOptions): Promise<number> {
    return this.withSftp(async (sftp) => {
      const size = await callbackBeforeDeadline<number | undefined>(opts, 'SFTP download stat', (callback) => {
        sftp.stat(remotePath, (err, stats) => callback(undefined, err ? undefined : stats?.size));
      });
      if (size !== undefined && size > opts.maxBytes) {
        throw new Error(`SFTP file download exceeds the ${opts.maxBytes} byte transfer limit (${size} bytes)`);
      }
      const source = sftp.createReadStream(remotePath);
      return transfer(source, destination, opts, 'download');
    });
  }

  async download(opts: SftpDownloadOpts): Promise<Buffer> {
    const maxBytes = opts.maxBytes ?? this.conn.profile.maxOutputBytes;

    return this.withSftp(async (sftp) => {
      // Refuse before transferring anything when the size is known up front.
      const size = await new Promise<number | undefined>((resolve) => {
        sftp.stat(opts.remotePath, (err, stats) => resolve(err ? undefined : stats?.size));
      });
      if (size !== undefined && size > maxBytes) {
        throw new Error(
          `Refusing to download ${opts.remotePath}: ${size} bytes exceeds the ${maxBytes} byte limit ` +
          `(commandMaxOutputBytes). Narrow the file or raise the limit for this profile.`,
        );
      }

      return new Promise<Buffer>((resolve, reject) => {
        const chunks: Buffer[] = [];
        let received = 0;
        const stream = sftp.createReadStream(opts.remotePath);
        stream.on('data', (chunk: Buffer) => {
          received += chunk.length;
          // stat can be stale or unavailable (growing file, no permission), so
          // enforce the cap on the stream too and stop reading immediately.
          if (received > maxBytes) {
            stream.destroy();
            reject(new Error(
              `Refusing to download ${opts.remotePath}: exceeded the ${maxBytes} byte limit while transferring.`,
            ));
            return;
          }
          chunks.push(chunk);
        });
        stream.on('error', reject);
        stream.on('close', () => resolve(Buffer.concat(chunks)));
      });
    });
  }

  /**
   * List a remote directory, reading at most `maxEntries + 1` entries.
   *
   * The extra entry is what makes `truncated` honest without a second call: it
   * distinguishes "exactly maxEntries" from "more than that". Unbounded
   * readdir was the previous shape, and a directory with a million entries
   * turned one call into a million-object array.
   */
  async list(
    remotePath: string,
    maxEntries: number,
    opts: DeadlineOptions & { maxBytes: number },
  ): Promise<SftpListResult> {
    return this.withSftp(async (sftp) => {
      const handle = await callbackBeforeDeadline<Buffer>(opts, 'SFTP list open', (callback) => {
        sftp.opendir(remotePath, (err, opened) => {
          callback(err ? new Error(`SFTP list error: ${err.message}`) : undefined, opened);
        });
      });
      const raw: any[] = [];
      let rawBytes = 0;
      let inputTruncated = false;

      try {
        while (raw.length <= maxEntries && !inputTruncated) {
          const batch = await callbackBeforeDeadline<any[] | null>(opts, 'SFTP list read', (callback) => {
            sftp.readdir(handle, (err: any, list: any[]) => {
              if (err?.code === 1) callback(undefined, null);
              else if (err) callback(new Error(`SFTP list error: ${err.message}`));
              else callback(undefined, list);
            });
          });
          if (batch === null) break;
          if (batch.length === 0) break;
          for (const entry of batch) {
            // Bound the raw buffer as well as the entry count: names are
            // attacker-controlled and 128 bytes covers the attrs beside them.
            rawBytes += Buffer.byteLength(String(entry.filename), 'utf8') + 128;
            if (rawBytes > opts.maxBytes) {
              inputTruncated = true;
              break;
            }
            raw.push(entry);
            if (raw.length > maxEntries) break;
          }
        }
      } finally {
        await callbackBeforeDeadline<void>(opts, 'SFTP list close', (callback) => {
          sftp.close(handle, () => callback());
        }).catch(() => {});
      }

      return {
        truncated: inputTruncated || raw.length > maxEntries,
        entries: raw.slice(0, maxEntries).map((entry) => ({
          path: `${remotePath}/${entry.filename}`,
          size: entry.attrs.size,
          mode: entry.attrs.mode,
          isDirectory: (entry.attrs.mode & 0o170000) === 0o040000,
          isFile: (entry.attrs.mode & 0o170000) === 0o100000,
          mtime: new Date(entry.attrs.mtime * 1000),
          atime: new Date(entry.attrs.atime * 1000),
        })),
      };
    });
  }

  async stat(remotePath: string): Promise<SftpStat> {
    return this.withSftp(async (sftp) => {
      return new Promise<SftpStat>((resolve, reject) => {
        sftp.stat(remotePath, (err: Error | undefined, stats: any) => {
          if (err) {
            reject(new Error(`SFTP stat error: ${err.message}`));
            return;
          }
          resolve({
            path: remotePath,
            size: stats.size,
            mode: stats.mode,
            isDirectory: (stats.mode & 0o170000) === 0o040000,
            isFile: (stats.mode & 0o170000) === 0o100000,
            mtime: new Date(stats.mtime * 1000),
            atime: new Date(stats.atime * 1000),
          });
        });
      });
    });
  }
}
