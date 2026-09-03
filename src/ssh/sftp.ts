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
  timeoutMs: number;
  abortSignal?: AbortSignal;
  overwrite?: boolean;
  mode?: number;
}

export interface SftpListResult {
  entries: SftpStat[];
  truncated: boolean;
}

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
  const timeout = setTimeout(
    () => controller.abort(new Error(`SFTP file ${direction} timed out after ${opts.timeoutMs}ms`)),
    opts.timeoutMs,
  );
  const onAbort = () => controller.abort(opts.abortSignal?.reason ?? new Error(`SFTP file ${direction} aborted`));
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
        new Promise<void>((resolve) => { timer = setTimeout(resolve, Math.min(opts.timeoutMs, 1_000)); }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  try {
    const copy = async () => {
      for await (const value of source) {
        if (controller.signal.aborted) throw controller.signal.reason;
        const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
        bytes += chunk.length;
        if (bytes > opts.maxBytes) {
          throw new Error(`SFTP file ${direction} exceeds the ${opts.maxBytes} byte transfer limit`);
        }
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
    const transferred = await Promise.race([copy(), failure]);
    return transferred;
  } catch (err) {
    source.destroy();
    destination.destroy();
    await waitForRemoteClose();
    if (controller.signal.aborted && controller.signal.reason instanceof Error) {
      throw controller.signal.reason;
    }
    throw err;
  } finally {
    clearTimeout(timeout);
    controller.signal.removeEventListener('abort', abortStreams);
    source.removeListener('error', onSourceError);
    destination.removeListener('error', onDestinationError);
    remoteStream.removeListener('close', onRemoteClose);
    opts.abortSignal?.removeEventListener('abort', onAbort);
  }
}

interface DeadlineOptions {
  timeoutMs: number;
  abortSignal?: AbortSignal;
}

function callbackBeforeDeadline<T>(
  deadline: number,
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
    const remaining = Math.max(0, deadline - Date.now());
    const timer = setTimeout(() => finish(new Error(`${label} timed out after ${opts.timeoutMs}ms`)), remaining);
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

  async upload(opts: SftpUploadOpts): Promise<void> {
    const data = Buffer.isBuffer(opts.content) ? opts.content : Buffer.from(opts.content);
    await this.uploadFile(Readable.from(data), opts.remotePath, {
      maxBytes: data.length,
      timeoutMs: this.conn.profile.timeout,
      overwrite: true,
      mode: opts.mode ?? 0o600,
    });
  }

  /** Upload an already-open local file without buffering it in the MCP process. */
  async uploadFile(source: Readable, remotePath: string, opts: FileTransferOptions): Promise<number> {
    return this.withSftp(async (sftp) => {
      const deadline = Date.now() + opts.timeoutMs;
      const exists = async () => callbackBeforeDeadline<boolean>(deadline, opts, 'SFTP upload stat', (callback) => {
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
        const bytes = await transfer(source, destination, {
          ...opts,
          timeoutMs: Math.max(1, deadline - Date.now()),
        }, 'upload');
        if (!opts.overwrite && await exists()) {
          throw new Error('Refusing to overwrite a remote file created during transfer');
        }
        await callbackBeforeDeadline<void>(deadline, opts, 'SFTP upload publish', (callback) => {
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
          const cleanupOpts = { timeoutMs: Math.min(opts.timeoutMs, 1_000) };
          await callbackBeforeDeadline<void>(
            Date.now() + cleanupOpts.timeoutMs,
            cleanupOpts,
            'SFTP upload cleanup',
            (callback) => sftp.unlink(temporary, (err) => callback(err ?? undefined)),
          ).catch(() => {
            console.error('Warning: an SFTP upload was published but its stale .part hard link could not be removed');
          });
        }
        return bytes;
      } finally {
        if (!published) {
          const cleanupOpts = { timeoutMs: Math.min(opts.timeoutMs, 1_000) };
          await callbackBeforeDeadline<void>(
            Date.now() + cleanupOpts.timeoutMs,
            cleanupOpts,
            'SFTP upload cleanup',
            (callback) => sftp.unlink(temporary, () => callback()),
          ).catch(() => {});
        }
      }
    });
  }

  /** Download into an already-open local file without buffering it in memory. */
  async downloadFile(remotePath: string, destination: Writable, opts: FileTransferOptions): Promise<number> {
    return this.withSftp(async (sftp) => {
      const deadline = Date.now() + opts.timeoutMs;
      const size = await callbackBeforeDeadline<number | undefined>(deadline, opts, 'SFTP download stat', (callback) => {
        sftp.stat(remotePath, (err, stats) => callback(undefined, err ? undefined : stats?.size));
      });
      if (size !== undefined && size > opts.maxBytes) {
        throw new Error(`SFTP file download exceeds the ${opts.maxBytes} byte transfer limit (${size} bytes)`);
      }
      const source = sftp.createReadStream(remotePath);
      return transfer(source, destination, {
        ...opts,
        timeoutMs: Math.max(1, deadline - Date.now()),
      }, 'download');
    });
  }

  /** Read at most maxEntries + 1 entries so a remote directory cannot exhaust memory. */
  async list(
    remotePath: string,
    maxEntries: number,
    opts: DeadlineOptions & { maxBytes: number },
  ): Promise<SftpListResult> {
    return this.withSftp(async (sftp) => {
      const deadline = Date.now() + opts.timeoutMs;
      const handle = await callbackBeforeDeadline<Buffer>(deadline, opts, 'SFTP list open', (callback) => {
        sftp.opendir(remotePath, (err, opened) => {
          callback(err ? new Error(`SFTP list error: ${err.message}`) : undefined, opened);
        });
      });
      const raw: any[] = [];
      let rawBytes = 0;
      let inputTruncated = false;

      try {
        while (raw.length <= maxEntries && !inputTruncated) {
          const batch = await callbackBeforeDeadline<any[] | null>(deadline, opts, 'SFTP list read', (callback) => {
            sftp.readdir(handle, (err: any, list: any[]) => {
              if (err?.code === 1) callback(undefined, null);
              else if (err) callback(new Error(`SFTP list error: ${err.message}`));
              else callback(undefined, list);
            });
          });
          if (batch === null) break;
          if (batch.length === 0) break;
          for (const entry of batch) {
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
        await callbackBeforeDeadline<void>(deadline, opts, 'SFTP list close', (callback) => {
          sftp.close(handle, () => callback());
        });
      }

      const truncated = inputTruncated || raw.length > maxEntries;
      return {
        truncated,
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

  /**
   * Download a remote file, refusing anything over the cap.
   *
   * exec output has always been capped, but SFTP download was not: the whole
   * file was buffered, concatenated, decoded to a UTF-16 string and entropy
   * scanned. A large remote file therefore turned one tool call into multi-GB
   * RSS and a multi-second event-loop stall for the entire server.
   */
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
