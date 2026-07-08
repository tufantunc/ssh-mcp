import { appendFile, mkdir, stat, rename } from 'fs/promises';
import { homedir, platform } from 'os';
import { join, dirname } from 'path';
import { randomUUID } from 'crypto';
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

  constructor(logPath?: string, entropyScan = false) {
    this.logPath = logPath || getAuditLogPath();
    this.entropyScan = entropyScan;
  }

  async record(entry: Omit<AuditRecord, 'timestamp' | 'eventId'>): Promise<void> {
    const record: AuditRecord = {
      ...entry,
      timestamp: new Date().toISOString(),
      eventId: randomUUID(),
    };

    const redactedCommand = redactText(record.command, { entropyScan: this.entropyScan });

    const line = JSON.stringify({
      ...record,
      command: redactedCommand,
    }) + '\n';

    await mkdir(dirname(this.logPath), { recursive: true });
    await this.rotateIfNeeded();
    await appendFile(this.logPath, line, 'utf8');
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
