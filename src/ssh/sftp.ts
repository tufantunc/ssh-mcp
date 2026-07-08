import type { ClientChannel } from 'ssh2';
import type { SftpUploadOpts, SftpDownloadOpts, SftpStat } from '../types.js';
import type { SSHConnection } from './connection.js';

export class SftpClient {
  constructor(private conn: SSHConnection) {}

  private async withSftp<T>(fn: (sftp: any) => Promise<T>): Promise<T> {
    await this.conn.ensureConnected();
    const client = this.conn.getClient();
    return new Promise((resolve, reject) => {
      client.sftp((err: Error | undefined, sftp: any) => {
        if (err) {
          reject(new Error(`SFTP error: ${err.message}`));
          return;
        }
        fn(sftp).then(resolve).catch(reject);
      });
    });
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

  async download(opts: SftpDownloadOpts): Promise<Buffer> {
    return this.withSftp(async (sftp) => {
      return new Promise<Buffer>((resolve, reject) => {
        const chunks: Buffer[] = [];
        const stream = sftp.createReadStream(opts.remotePath);
        stream.on('data', (chunk: Buffer) => chunks.push(chunk));
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
