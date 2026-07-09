import { appendFile, mkdir, stat, rename, readFile, chmod, open } from 'fs/promises';
import { createWriteStream, type WriteStream } from 'fs';
import { homedir, platform } from 'os';
import { join, dirname } from 'path';
import { randomUUID, createHash } from 'crypto';
import type { AuditRecord } from '../types.js';
import { redactText } from '../guard/redactor.js';

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
const MAX_FILES = 10;

export function getAuditLogPath(): string {
  const home = homedir();
  const p = platform();

  if (p === 'darwin') {
    return join(home, 'Library', 'Logs', 'ssh-mcp', 'audit.log');
  }
  if (p === 'win32') {
    return join(process.env.LOCALAPPDATA || join(home, 'AppData', 'Local'), 'ssh-mcp', 'audit.log');
  }
  const xdgData = process.env.XDG_DATA_HOME || join(home, '.local', 'share');
  return join(xdgData, 'ssh-mcp', 'audit.log');
}

export class AuditStore {
  private logPath: string;
  private entropyScan: boolean;
  private tamperEvident: boolean;
  private lastHash: string = '';
  private writeStream: WriteStream | null = null;
  private dirEnsured = false;
  private recordCount = 0;

  constructor(logPath?: string, entropyScan = false, tamperEvident = false) {
    this.logPath = logPath || getAuditLogPath();
    this.entropyScan = entropyScan;
    this.tamperEvident = tamperEvident;
  }

  private async ensureStream(): Promise<WriteStream> {
    if (this.writeStream && !this.writeStream.destroyed) return this.writeStream;

    if (!this.dirEnsured) {
      await mkdir(dirname(this.logPath), { recursive: true });
      this.dirEnsured = true;
    }

    this.writeStream = createWriteStream(this.logPath, { flags: 'a' });
    try { await chmod(this.logPath, 0o600); } catch { /* may not exist yet */ }
    return this.writeStream;
  }

  async record(entry: Omit<AuditRecord, 'timestamp' | 'eventId'>): Promise<void> {
    const record: AuditRecord = {
      ...entry,
      timestamp: new Date().toISOString(),
      eventId: randomUUID(),
    };

    const redactedCommand = redactText(record.command, { entropyScan: this.entropyScan });
    const redactedError = record.error ? redactText(record.error, { entropyScan: this.entropyScan }) : undefined;

    let lineObj: Record<string, unknown> = { ...record, command: redactedCommand, error: redactedError };

    if (this.tamperEvident) {
      if (!this.lastHash) {
        await this.loadLastHash();
      }
      const prevHash = this.lastHash;
      const contentForHash = JSON.stringify(lineObj) + prevHash;
      const selfHash = createHash('sha256').update(contentForHash).digest('hex');
      lineObj = { ...lineObj, prevHash, selfHash };
      this.lastHash = selfHash;
    }

    const line = JSON.stringify(lineObj) + '\n';

    await this.rotateIfNeeded();
    const stream = await this.ensureStream();
    await new Promise<void>((resolve, reject) => {
      stream.write(line, (err) => err ? reject(err) : resolve());
    });

    this.recordCount++;
  }

  private async loadLastHash(): Promise<void> {
    try {
      const fileStat = await stat(this.logPath);
      const readSize = Math.min(fileStat.size, 8192);
      const fd = await open(this.logPath, 'r');
      const buf = Buffer.alloc(readSize);
      await fd.read(buf, 0, readSize, fileStat.size - readSize);
      await fd.close();
      const content = buf.toString('utf8');
      const lines = content.split('\n').filter(Boolean);
      if (lines.length === 0) return;
      const lastLine = JSON.parse(lines[lines.length - 1]);
      this.lastHash = lastLine.selfHash || '';
    } catch {
      // File doesn't exist or can't be read — start fresh
    }
  }

  private async rotateIfNeeded(): Promise<void> {
    try {
      const fileStat = await stat(this.logPath);
      if (fileStat.size < MAX_FILE_SIZE) return;

      if (this.writeStream && !this.writeStream.destroyed) {
        await new Promise<void>((resolve) => {
          this.writeStream!.end(() => resolve());
        });
        this.writeStream = null;
      }

      for (let i = MAX_FILES - 1; i > 0; i--) {
        const oldPath = `${this.logPath}.${i}`;
        const newPath = `${this.logPath}.${i + 1}`;
        try {
          await rename(oldPath, newPath);
        } catch (err: any) {
          if (err.code !== 'ENOENT') throw err;
        }
      }
      await rename(this.logPath, `${this.logPath}.1`);
    } catch (err: any) {
      if (err.code === 'ENOENT') return;
      throw err;
    }
  }
}
