import type { SFTPWrapper } from 'ssh2';
import type { SftpUploadOpts, SftpDownloadOpts, SftpStat } from '../types.js';
import type { SSHConnection } from './connection.js';

export class SftpClient {
  constructor(private conn: SSHConnection) {}

  private async withSftp<T>(fn: (sftp: SFTPWrapper) => Promise<T>): Promise<T> {
    await this.conn.ensureConnected();
    const client = this.conn.getClient();
    const sftp = await new Promise<SFTPWrapper>((resolve, reject) => {
      client.sftp((err, handle) => {
        if (err) {
          reject(new Error(`SFTP error: ${err.message}`));
          return;
        }
        resolve(handle);
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

  async list(remotePath: string): Promise<SftpStat[]> {
    return this.withSftp(async (sftp) => {
      return new Promise<SftpStat[]>((resolve, reject) => {
        sftp.readdir(remotePath, (err: Error | undefined, list: any[]) => {
          if (err) {
            reject(new Error(`SFTP list error: ${err.message}`));
            return;
          }
          resolve(
            list.map((entry) => ({
              path: `${remotePath}/${entry.filename}`,
              size: entry.attrs.size,
              mode: entry.attrs.mode,
              isDirectory: (entry.attrs.mode & 0o170000) === 0o040000,
              isFile: (entry.attrs.mode & 0o170000) === 0o100000,
              mtime: new Date(entry.attrs.mtime * 1000),
              atime: new Date(entry.attrs.atime * 1000),
            })),
          );
        });
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
