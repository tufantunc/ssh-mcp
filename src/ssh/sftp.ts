import ssh2 from 'ssh2';
import type { FileEntryWithStats, SFTPWrapper, Attributes } from 'ssh2';
import { Readable, type Writable } from 'node:stream';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path/posix';
import type { SftpUploadOpts, SftpDownloadOpts, SftpStat } from '../types.js';
import type { SSHConnection } from './connection.js';
import { openWithRetry } from './channel-retry.js';

/*
 * Through the default import, not `import { utils } from 'ssh2'`.
 *
 * ssh2 is CommonJS. Node's ESM loader statically detects some of its named
 * exports (`Client`, which connection.ts imports that way) but not `utils`, so
 * the named form type-checks, passes every vitest run — vitest transforms the
 * module itself — and then throws `SyntaxError: Named export 'utils' not found`
 * the first time the *built* artifact is loaded. Only the e2e suite, which
 * spawns build/index.js, would have caught it.
 */
const { STATUS_CODE } = ssh2.utils.sftp;

/**
 * The numeric SFTP status a failed request carries, if any.
 *
 * ssh2 sets `code` only from the SSH_FXP_STATUS word (a number), never a
 * libuv-style string — an earlier version of this file also tested for
 * `'ENOENT'` and `'OP_UNSUPPORTED'`, which can never match. Those dead
 * comparisons were what forced `(err as any).code`, and the cast in turn hid
 * that they were dead. Errors ssh2 raises itself (`'No response from server'`,
 * and the unadvertised-extension throw below) carry no `code` at all, which is
 * why this returns `undefined` rather than a sentinel.
 */
function statusCode(err: unknown): number | undefined {
  const code = (err as { code?: unknown } | null | undefined)?.code;
  return typeof code === 'number' ? code : undefined;
}

/**
 * `readdir`'s three-argument form, which the runtime supports and the typings omit.
 *
 * ssh2 declares only `readdir(location, callback)` (@types/ssh2 index.d.ts:1897)
 * but implements `readdir(where, opts, cb)` (SFTP.js:866) — and `opts.full` is
 * the only way to stop it splicing `.` and `..` out of every batch before the
 * callback sees them, which is what `list()` below needs to tell a short batch
 * from end-of-directory.
 */
type ReaddirWithOptions = (
  handle: Buffer,
  opts: { full: true },
  callback: (err: Error | undefined, list: FileEntryWithStats[]) => void,
) => void;

/** Bounds every transfer needs. Required, because a missing bound is not a default. */
export interface TransferBounds {
  maxBytes: number;
  /**
   * Bounds each *step* of a transfer rather than the transfer as a whole: one
   * metadata round-trip, or a stretch of the copy with no bytes moving.
   *
   * A single wall-clock budget for the whole operation cannot serve both the
   * byte cap and the wire: 1 GiB inside 60s demands 17.9 MB/s sustained, so a
   * generous cap becomes unreachable at a normal timeout. Re-arming on progress
   * separates the two questions — "is this connection still moving?" gets a
   * tight answer, and how long a large file may legitimately take stops being a
   * function of it.
   */
  idleTimeoutMs: number;
  abortSignal?: AbortSignal;
}

/** Upload-only knobs. Separate, because a download can honour neither. */
export interface UploadFileOptions extends TransferBounds {
  overwrite?: boolean;
  mode?: number;
}

export interface SftpListOptions {
  maxEntries: number;
  /**
   * Budget for the listing this call will *return*, not for bytes on the wire —
   * `maxBytes` elsewhere in this file means the latter, so this one is named
   * apart on purpose.
   */
  maxResponseBytes: number;
  idleTimeoutMs: number;
  abortSignal?: AbortSignal;
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
 * Thrown when a step's own bound expired, as distinct from the server refusing.
 *
 * The difference matters at exactly one place: a publish whose *wait* expired
 * may still have landed, because the bound covers the wait and not the request.
 * A publish the server actively refused has definitively not landed. Treating
 * both as ambiguous told a caller its file "may already hold this upload" when
 * the real answer was a permission error.
 */
export class DeadlineExceededError extends Error {}

const MAX_TIMER_MS = 2 ** 31 - 1;

/**
 * Refuse a bound that cannot do its job, rather than letting it fail oddly.
 *
 * `idleTimeoutMs` above 2^31-1 (or `Infinity`, or `NaN`) is clamped by Node to
 * 1ms, so every step then fails immediately with a message quoting the value
 * the caller asked for — self-refuting output from a plausible input. `0` is
 * worse than useless here: elsewhere in this codebase 0 means "no limit"
 * (`commandQuotaPerDay`, `approvalGrantTtlMs`), so a caller following the house
 * convention would get the exact opposite of what it asked for.
 */
function assertBounds(idleTimeoutMs: number, byteBudget: number, label: string): void {
  if (!Number.isInteger(idleTimeoutMs) || idleTimeoutMs < 1 || idleTimeoutMs > MAX_TIMER_MS) {
    throw new Error(
      `${label}: idleTimeoutMs must be an integer between 1 and ${MAX_TIMER_MS}; ` +
      `0 does not mean "unlimited" here`,
    );
  }
  if (!Number.isSafeInteger(byteBudget) || byteBudget < 1) {
    throw new Error(`${label}: the byte budget must be a positive safe integer`);
  }
}

/** One place the wire shape becomes this module's own, so the masks exist once. */
function toSftpStat(path: string, attrs: Attributes): SftpStat {
  return {
    path,
    size: attrs.size,
    mode: attrs.mode,
    isDirectory: (attrs.mode & 0o170000) === 0o040000,
    isFile: (attrs.mode & 0o170000) === 0o100000,
    mtime: new Date(attrs.mtime * 1000),
    atime: new Date(attrs.atime * 1000),
  };
}

/**
 * Copy `source` into `destination`, failing if either stalls or the byte cap is
 * exceeded. Returns the number of bytes the far side acknowledged.
 *
 * The cap is enforced on the stream as it flows, not only from a prior stat: a
 * remote size can be stale, unavailable, or a lie, and a local file can grow
 * while it is read.
 *
 * **Ownership:** this ends `destination` — that is how the bytes are flushed and
 * how the count becomes trustworthy — but never closes what the destination
 * wraps. A caller whose `Writable` sits on a resource that must outlive the
 * stream (a `FileHandle` it still has to `sync()` and publish) must construct it
 * with `autoClose: false`; otherwise `end()` closes the handle here and the
 * caller's later `sync()` fails with EBADF.
 */
async function transfer(
  source: Readable,
  destination: Writable,
  opts: TransferBounds,
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

  // Derived once. These three facts are the same question — which end is the
  // SFTP-backed stream, and therefore which completion event is authoritative —
  // and re-deriving them at each use made the body read as five decisions.
  const remoteStream = direction === 'upload' ? destination : source;
  const settledEvent = direction === 'upload' ? 'close' : 'finish';
  const destinationSettled = () => (
    direction === 'upload' ? destination.closed : destination.writableFinished
  );

  // Re-armed after every chunk, and once more for the finalize. A slow-but-live
  // transfer survives; a channel that stops delivering fails within one window.
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
  let resolveRemoteClosed!: () => void;
  const remoteClosed = new Promise<void>((resolve) => { resolveRemoteClosed = resolve; });
  const onRemoteClose = () => resolveRemoteClosed();
  remoteStream.once('close', onRemoteClose);
  // ssh2 constructs its streams with emitClose: false, so a close that has
  // already happened never replays. Bounded, because this is a courtesy wait
  // after the work is done, not a step that may hang the caller.
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
        // With the signal: `once` settles on 'drain' or 'error' only, and ssh2's
        // destroy path emits 'close' without 'error'. A destination that went
        // away cleanly while we were backpressured therefore left this waiting
        // for the whole idle window, and surfaced as "no progress" rather than
        // as the close it was.
        if (!destination.write(chunk)) {
          await once(destination, 'drain', { signal: controller.signal });
        }
      }

      // The finalize costs an SSH_FXP_CLOSE round-trip whose latency has nothing
      // to do with chunk cadence. Without re-arming, it ran on whatever was left
      // of the window the last chunk set — sometimes almost nothing — and a
      // transfer in which every byte was acknowledged failed as "stalled".
      arm();
      const completed = new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          destination.removeListener(settledEvent, done);
          destination.removeListener('error', failed);
        };
        const done = () => { cleanup(); resolve(); };
        const failed = (err: Error) => { cleanup(); reject(err); };
        destination.once(settledEvent, done);
        destination.once('error', failed);
      });
      destination.end();
      if (!destinationSettled()) await completed;
      // Not dead code on the download side, though it looks it: `source` there
      // is ssh2's SFTP read stream, built with emitClose: false, so `.closed`
      // never becomes true and finishing the `for await` does not get
      // SSH_FXP_CLOSE onto the wire. Without this the handle is still open when
      // withSftp ends the subsystem channel. A review round called it dead after
      // checking a plain Readable, where it genuinely is.
      if (direction === 'download' && !source.destroyed) source.destroy();
      await waitForRemoteClose();
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
 * Every metadata round-trip gets `idleTimeoutMs` measured from its own start, so
 * no single step can hang and none of them consume a budget the next step needs.
 *
 * It bounds the *wait*, not the request: a reply that arrives after the bound
 * finds `settled` already true and is dropped. Callers for whom a late success
 * matters have to re-establish the state rather than assume failure.
 *
 * Exported for its own tests. Driving the timeout through a real SFTP call
 * cannot pin it: against a container on loopback a metadata round-trip finishes
 * inside a 1ms bound, so the copy's stall wins the race and the branch this
 * helper exists for stays unexercised.
 */
export function callbackBeforeDeadline<T>(
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
      () => finish(new DeadlineExceededError(`${label} timed out after ${opts.idleTimeoutMs}ms`)),
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

/**
 * Publish a staged upload, atomically where the server allows it.
 *
 * ssh2 does not report an unadvertised extension through the callback — it
 * `throw`s before sending anything, with no `code` on the Error. Both extension
 * calls are therefore wrapped: an earlier version tested the callback for
 * `code === 8`, so the plain-`rename` fallback written for exactly these servers
 * was unreachable and `overwrite: true` failed outright against anything that
 * does not advertise posix-rename@openssh.com.
 *
 * Exported for its own tests. No server in this repo can exercise the throw:
 * docker-compose pins OpenSSH's sftp-server, and even the Dropbear image
 * installs openssh-sftp-server because Dropbear ships no SFTP subsystem — so
 * both extensions are always advertised and the fallback would stay unverified
 * without a stub.
 */
export function publishRemote(
  sftp: SFTPWrapper,
  temporary: string,
  remotePath: string,
  opts: UploadFileOptions,
): Promise<void> {
  return callbackBeforeDeadline<void>(opts, 'SFTP upload publish', (callback) => {
    const standardRename = () => sftp.rename(
      temporary,
      remotePath,
      (err) => callback(err ?? undefined),
    );

    const unsupported = () => callback(new Error(
      'The SFTP server cannot atomically publish a file without overwrite; retry with overwrite=true',
    ));

    if (!opts.overwrite) {
      // SFTP v3 rename has no portable no-clobber semantics. The OpenSSH
      // hardlink extension maps to link(2), which fails atomically if the
      // destination appeared after the stat above.
      try {
        sftp.ext_openssh_hardlink(temporary, remotePath, (err) => {
          if (!err) return callback();
          const code = statusCode(err);
          if (code === STATUS_CODE.OP_UNSUPPORTED) return unsupported();
          // v3 has no dedicated "already exists" status, so OpenSSH reports
          // EEXIST as FAILURE. Anything else — permission, a filesystem that
          // cannot hardlink, quota — used to be reported as a lost race too,
          // sending the reader to look for a concurrent writer that never was.
          if (code === STATUS_CODE.FAILURE) {
            return callback(new Error('Refusing to overwrite a remote file created during transfer'));
          }
          return callback(new Error(`SFTP upload publish failed: ${err.message}`));
        });
      } catch {
        unsupported();
      }
      return;
    }

    try {
      sftp.ext_openssh_rename(temporary, remotePath, (err) => {
        if (statusCode(err) === STATUS_CODE.OP_UNSUPPORTED) standardRename();
        else callback(err ?? undefined);
      });
    } catch {
      standardRename();
    }
  });
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
   * half-written file at the destination — the right trade for a new tool whose
   * destination is expected to be new, and the wrong one for upload() above.
   *
   * Note what `overwrite: true` costs, since it is the case where the
   * destination is *not* new: publishing by rename replaces the inode, so the
   * target's owner and ACL do not survive. The permission bits do, unless the
   * caller passes a mode — but only the low nine: setuid, setgid and the sticky
   * bit are dropped rather than carried across. See the chmod below.
   */
  async uploadFile(source: Readable, remotePath: string, opts: UploadFileOptions): Promise<number> {
    assertBounds(opts.idleTimeoutMs, opts.maxBytes, 'SFTP upload');
    return this.withSftp(async (sftp) => {
      const exists = async () => callbackBeforeDeadline<boolean>(opts, 'SFTP upload stat', (callback) => {
        sftp.stat(remotePath, (err) => {
          if (!err) callback(undefined, true);
          else if (statusCode(err) === STATUS_CODE.NO_SUCH_FILE) callback(undefined, false);
          else callback(new Error(`SFTP upload stat failed: ${err.message}`));
        });
      });
      if (!opts.overwrite && await exists()) {
        throw new Error('Refusing to overwrite an existing remote file');
      }

      // Read before the transfer, because after it the destination is about to
      // be replaced and its mode is the only part we can carry across.
      const inheritedMode = opts.overwrite && opts.mode === undefined
        ? await callbackBeforeDeadline<number | undefined>(opts, 'SFTP upload mode stat', (callback) => {
            sftp.stat(remotePath, (err, stats) => callback(undefined, err ? undefined : stats?.mode));
          })
        : undefined;

      const temporary = remoteTemporaryPath(remotePath);
      let published = false;
      try {
        const destination = sftp.createWriteStream(temporary, {
          flags: 'wx',
          mode: opts.mode || 0o600,
        });
        const bytes = await transfer(source, destination, opts, 'upload');

        if (inheritedMode !== undefined) {
          // Without this, replacing a 0644 service config with a 0600 one is a
          // successful-looking upload that silently breaks every other reader.
          //
          // The low nine bits only. `& 0o7777` also carried setuid, setgid and
          // the sticky bit across, which turns "may replace this file" into "may
          // run code as its owner" — measured against a 04755 destination owned
          // by the SSH user: the content became the caller's and the mode stayed
          // 4755. Nothing else in the upload path could have caught it, because
          // the caller never named a mode; it arrived by inheritance, through the
          // one argument the caller can omit.
          await callbackBeforeDeadline<void>(opts, 'SFTP upload chmod', (callback) => {
            sftp.chmod(temporary, inheritedMode & 0o777, (err) => callback(err ?? undefined));
          });
        }
        if (!opts.overwrite && await exists()) {
          throw new Error('Refusing to overwrite a remote file created during transfer');
        }

        try {
          await publishRemote(sftp, temporary, remotePath, opts);
          published = true;
        } catch (err) {
          // Only a bound that expired is ambiguous: the request may still be
          // in flight, so the destination existing afterwards could be this
          // upload. Reporting that as a plain failure sent a retrying caller
          // into "Refusing to overwrite an existing remote file" —
          // indistinguishable from a squatter, and an argument for
          // `overwrite: true` built on a false premise. A publish the server
          // actively refused is not ambiguous and must keep its own error.
          if (err instanceof DeadlineExceededError && await exists().catch(() => false)) {
            published = true;
            throw new Error(
              'SFTP upload publish did not confirm within its bound, but the destination now exists. ' +
              'Verify the remote file before retrying; it may already hold this upload.',
            );
          }
          throw err;
        }

        if (!opts.overwrite) {
          // The hardlink above left two names for one inode; drop ours.
          await this.removeTemporary(sftp, temporary, opts.idleTimeoutMs).catch(() => {
            console.error('Warning: an SFTP upload was published but its stale .part hard link could not be removed');
          });
        }
        return bytes;
      } finally {
        if (!published) {
          await this.removeTemporary(sftp, temporary, opts.idleTimeoutMs).catch(() => {
            // Logged, not swallowed: this is the case that leaves remote state
            // nobody knows about. local-path.ts says the same thing for the
            // local half, and saying nothing here was the asymmetry.
            console.error(
              `Warning: an unpublished SFTP upload left a staging file in ${dirname(remotePath)}; ` +
              'look for .ssh-mcp-upload-*.part and remove it',
            );
          });
        }
      }
    });
  }

  /**
   * Remove a staging file.
   *
   * Takes the timeout as a number rather than the caller's options, because it
   * deliberately ignores `abortSignal`: cleanup runs on the aborted path, and a
   * signal threaded through here would make it unrunnable exactly when needed.
   * Its own short bound keeps it from extending a transfer that already failed.
   */
  private async removeTemporary(
    sftp: SFTPWrapper,
    temporary: string,
    idleTimeoutMs: number,
  ): Promise<void> {
    return callbackBeforeDeadline<void>(
      { idleTimeoutMs: Math.min(idleTimeoutMs, 1_000) },
      'SFTP upload cleanup',
      (callback) => sftp.unlink(temporary, (err) => callback(err ?? undefined)),
    );
  }

  /**
   * Download into an already-open destination without buffering it in memory.
   *
   * Ends the destination when the transfer completes — see transfer()'s
   * ownership note. A caller holding a `FileHandle` it still needs (to `sync()`
   * and publish) must create the stream with `autoClose: false`.
   */
  async downloadFile(remotePath: string, destination: Writable, opts: TransferBounds): Promise<number> {
    assertBounds(opts.idleTimeoutMs, opts.maxBytes, 'SFTP download');
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
      //
      // Bounded, because this promise had no reject path and no timeout: a
      // server that accepted SSH_FXP_STAT and never answered left this tool
      // call suspended for the life of the connection, with no error and
      // nothing for a caller to act on. That is the same shape as #197 on the
      // exec side. The bound is the profile's command timeout, which is what
      // every other step of a tool call already answers to; an unanswerable
      // stat now falls through to the streaming cap below, exactly as an
      // unavailable one always did.
      const size = await callbackBeforeDeadline<number | undefined>(
        { idleTimeoutMs: this.conn.profile.timeout },
        'SFTP download stat',
        (callback) => {
          sftp.stat(opts.remotePath, (err, stats) => callback(undefined, err ? undefined : stats?.size));
        },
      ).catch(() => undefined);
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
   * List a remote directory, retaining at most `maxEntries + 1` entries.
   *
   * Reads happen in server-sized batches; the bound is on what is *retained*,
   * and the one entry past the limit is what makes `truncated` honest without a
   * second round-trip. Unbounded readdir was the previous shape, and a directory
   * with a million entries turned one call into a million-object array.
   */
  async list(remotePath: string, opts: SftpListOptions): Promise<SftpListResult> {
    assertBounds(opts.idleTimeoutMs, opts.maxResponseBytes, 'SFTP list');
    if (!Number.isInteger(opts.maxEntries) || opts.maxEntries < 1) {
      throw new Error('SFTP list: maxEntries must be a positive integer');
    }
    return this.withSftp(async (sftp) => {
      const handle = await callbackBeforeDeadline<Buffer>(opts, 'SFTP list open', (callback) => {
        sftp.opendir(remotePath, (err, opened) => {
          callback(err ? new Error(`SFTP list error: ${err.message}`) : undefined, opened);
        });
      });
      const entries: SftpStat[] = [];
      let retained = 0;
      let responseBytes = 0;
      let budgetTruncated = false;
      // The loop advances on retained entries or on EOF, and neither is
      // guaranteed: a batch holding only `.`/`..` is legitimately empty after
      // filtering and must not be read as EOF, so a server answering every
      // READDIR that way kept this issuing requests forever. Each step has its
      // own idle bound; nothing bounded the number of steps, and a synthetic
      // tool call carries no overall deadline — so the call never settled.
      // Sixteen is far past any real directory layout and still terminates.
      const MAX_BARREN_BATCHES = 16;
      let barren = 0;

      try {
        while (retained <= opts.maxEntries && !budgetTruncated) {
          const batch = await callbackBeforeDeadline<FileEntryWithStats[] | null>(
            opts,
            'SFTP list read',
            (callback) => {
              // `{ full: true }` so `.` and `..` reach us. Without it ssh2 splices
              // them out before the callback, and a server whose READDIR batch
              // holds only those two names arrives here as a zero-length batch —
              // which the loop would read as EOF and report a listing it never
              // read as complete. Genuine EOF is the EOF status, nothing else.
              (sftp.readdir as unknown as ReaddirWithOptions)(
                handle,
                { full: true },
                (err, list) => {
                  if (statusCode(err) === STATUS_CODE.EOF) callback(undefined, null);
                  else if (err) callback(new Error(`SFTP list error: ${err.message}`));
                  else callback(undefined, list);
                },
              );
            },
          );
          if (batch === null) break;

          const before = retained;
          for (const entry of batch) {
            if (entry.filename === '.' || entry.filename === '..') continue;
            // Bill what is actually retained. `longname` is the server's `ls -l`
            // line — attacker-controlled, unbounded up to the packet limit, and
            // repeating the filename — so charging only the filename let a
            // hostile server retain three orders of magnitude more than the
            // budget said. Projecting to SftpStat here rather than pushing
            // ssh2's object drops `longname` instead of holding it.
            responseBytes += Buffer.byteLength(entry.filename, 'utf8')
              + Buffer.byteLength(entry.longname ?? '', 'utf8')
              + 256;
            if (responseBytes > opts.maxResponseBytes) {
              budgetTruncated = true;
              break;
            }
            retained++;
            if (retained > opts.maxEntries) break;
            entries.push(toSftpStat(join(remotePath, entry.filename), entry.attrs));
          }

          if (retained === before && !budgetTruncated) {
            if (++barren >= MAX_BARREN_BATCHES) {
              throw new Error(
                `SFTP list error: server returned ${MAX_BARREN_BATCHES} consecutive batches with no entries and no EOF`,
              );
            }
          } else {
            barren = 0;
          }
        }
      } finally {
        await callbackBeforeDeadline<void>(opts, 'SFTP list close', (callback) => {
          sftp.close(handle, () => callback());
        }).catch(() => {});
      }

      return { truncated: budgetTruncated || retained > opts.maxEntries, entries };
    });
  }

  async stat(remotePath: string): Promise<SftpStat> {
    return this.withSftp(async (sftp) => {
      return new Promise<SftpStat>((resolve, reject) => {
        sftp.stat(remotePath, (err: Error | undefined, stats) => {
          if (err) {
            reject(new Error(`SFTP stat error: ${err.message}`));
            return;
          }
          resolve(toSftpStat(remotePath, stats));
        });
      });
    });
  }
}
