import { appendFile, mkdir, stat, rename, readFile } from 'fs/promises';
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

  constructor(logPath?: string, entropyScan = false, tamperEvident = false) {
    this.logPath = logPath || getAuditLogPath();
    this.entropyScan = entropyScan;
    this.tamperEvident = tamperEvident;
  }

  async record(entry: Omit<AuditRecord, 'timestamp' | 'eventId'>): Promise<void> {
    const record: AuditRecord = {
      ...entry,
      timestamp: new Date().toISOString(),
      eventId: randomUUID(),
    };

    const redactedCommand = redactText(record.command, { entropyScan: this.entropyScan });

    let lineObj: Record<string, unknown> = { ...record, command: redactedCommand };

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

    await mkdir(dirname(this.logPath), { recursive: true });
    await this.rotateIfNeeded();
    await appendFile(this.logPath, line, 'utf8');
  }

  private async loadLastHash(): Promise<void> {
    try {
      const content = await readFile(this.logPath, 'utf8');
      const lines = content.trim().split('\n').filter(Boolean);
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
