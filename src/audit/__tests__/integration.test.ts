import { mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { describe, expect, it } from 'vitest';

import { AuditStore, activeFilePath } from '../store.js';
import { ExecResult, ISshTransport } from '../../transports/types.js';

describe('audit integration with exec wrapper', () => {
  it('writes one JSONL line after a successful exec against a stub transport', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-audit-wrapper-'));
    try {
      process.env.SSH_MCP_AUDIT_DIR = dir;
      process.env.SSH_MCP_AUDIT_MAX_BYTES = '8';
      process.env.SSH_MCP_DISABLE_MAIN = '1';
      const { executeAuditedTransportCommand } = await import('../../index.js');

      const calls: string[] = [];
      const transport: Pick<ISshTransport, 'exec' | 'execElevated'> = {
        exec: async (command: string): Promise<ExecResult> => {
          calls.push(command);
          return { stdout: '0123456789-secret', stderr: '', exitCode: 0 };
        },
        execElevated: async (): Promise<ExecResult> => {
          throw new Error('not used');
        },
      };
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 8 });

      const response = await executeAuditedTransportCommand({
        transport,
        store,
        tool: 'exec',
        profile: 'stub-profile',
        command: 'echo --password=secret',
        description: 'integration token abc',
      });

      expect(response.content[0].text).toContain('0123456789-secret');
      expect(calls[0]).toContain('--password=secret');

      const file = activeFilePath(dir);
      const records = readFileSync(file, 'utf8').trim().split('\n').map(line => JSON.parse(line));
      expect(records).toHaveLength(1);
      expect(records[0].profile).toBe('stub-profile');
      expect(records[0].tool).toBe('exec');
      expect(records[0].command).toContain('--password=<redacted>');
      expect(records[0].command).not.toContain('secret');
      expect(records[0].exec.stdout).toBe('01234567');
      expect(records[0].exec.stdout_truncated).toBe(true);
    } finally {
      delete process.env.SSH_MCP_AUDIT_DIR;
      delete process.env.SSH_MCP_AUDIT_MAX_BYTES;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('neutralizes description newlines before executing audited transport commands', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-audit-wrapper-description-'));
    try {
      process.env.SSH_MCP_AUDIT_DIR = dir;
      process.env.SSH_MCP_DISABLE_MAIN = '1';
      const { executeAuditedTransportCommand } = await import('../../index.js');

      const calls: string[] = [];
      const transport: Pick<ISshTransport, 'exec' | 'execElevated'> = {
        exec: async (command: string): Promise<ExecResult> => {
          calls.push(command);
          return { stdout: 'ok', stderr: '', exitCode: 0 };
        },
        execElevated: async (): Promise<ExecResult> => {
          throw new Error('not used');
        },
      };
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 1000 });

      await executeAuditedTransportCommand({
        transport,
        store,
        tool: 'exec',
        command: 'true',
        description: 'safe note\nuname -a\r\nwhoami',
      });

      expect(calls[0]).toBe('true # safe note uname -a whoami');
      expect(calls[0]).not.toMatch(/[\r\n]/);

      const file = activeFilePath(dir);
      const records = readFileSync(file, 'utf8').trim().split('\n').map(line => JSON.parse(line));
      expect(records[0].command).toBe('true # safe note uname -a whoami');
      expect(records[0].command).not.toMatch(/[\r\n]/);
    } finally {
      delete process.env.SSH_MCP_AUDIT_DIR;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('preserves synthetic failed-ExecResult context in wrapper audit records (Codex 3556038517)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-audit-wrapper-failed-result-'));
    try {
      process.env.SSH_MCP_AUDIT_DIR = dir;
      process.env.SSH_MCP_DISABLE_MAIN = '1';
      const { executeAuditedTransportCommand } = await import('../../index.js');

      // Non-zero exit with EMPTY stderr: resultToMcpContent throws the
      // synthetic "Command exited with status N" detail. The wrapper audit
      // record must carry that context instead of an empty stderr.
      const transport: Pick<ISshTransport, 'exec' | 'execElevated'> = {
        exec: async (): Promise<ExecResult> => ({ stdout: '', stderr: '', exitCode: 3 }),
        execElevated: async (): Promise<ExecResult> => {
          throw new Error('not used');
        },
      };
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 1000 });

      await expect(
        executeAuditedTransportCommand({
          transport,
          store,
          tool: 'exec',
          profile: 'p',
          command: 'false',
        }),
      ).rejects.toThrow(/Command exited with status 3/);

      const file = activeFilePath(dir);
      const records = readFileSync(file, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
      // Exactly ONE record: the mapped-error audit must not double-write.
      expect(records).toHaveLength(1);
      expect(records[0].exec.exit_code).toBe(3);
      expect(records[0].exec.stderr).toContain('Command exited with status 3');
    } finally {
      delete process.env.SSH_MCP_AUDIT_DIR;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('writes a failure audit record when the transport throws (audit contract covers failure)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-audit-wrapper-fail-'));
    try {
      process.env.SSH_MCP_AUDIT_DIR = dir;
      process.env.SSH_MCP_DISABLE_MAIN = '1';
      const { executeAuditedTransportCommand } = await import('../../index.js');

      const transport: Pick<ISshTransport, 'exec' | 'execElevated'> = {
        exec: async (): Promise<ExecResult> => {
          throw new Error('spawn ENOENT');
        },
        execElevated: async (): Promise<ExecResult> => {
          throw new Error('not used');
        },
      };
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 1000 });

      await expect(
        executeAuditedTransportCommand({
          transport,
          store,
          tool: 'exec',
          command: 'echo boom',
        }),
      ).rejects.toThrow('spawn ENOENT');

      const file = activeFilePath(dir);
      const records = readFileSync(file, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
      expect(records).toHaveLength(1);
      // Omitted profile defaults to 'default' (not the misleading 'stub').
      expect(records[0].profile).toBe('default');
      expect(records[0].tool).toBe('exec');
      expect(records[0].exec.exit_code).toBeNull();
      expect(records[0].exec.stderr).toContain('spawn ENOENT');
    } finally {
      delete process.env.SSH_MCP_AUDIT_DIR;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('writes a failure audit record when the command is rejected by sanitization (empty command)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-audit-wrapper-sanitize-'));
    try {
      process.env.SSH_MCP_AUDIT_DIR = dir;
      process.env.SSH_MCP_DISABLE_MAIN = '1';
      const { executeAuditedTransportCommand } = await import('../../index.js');

      let called = false;
      const transport: Pick<ISshTransport, 'exec' | 'execElevated'> = {
        exec: async (): Promise<ExecResult> => {
          called = true;
          return { stdout: '', stderr: '', exitCode: 0 };
        },
        execElevated: async (): Promise<ExecResult> => {
          throw new Error('not used');
        },
      };
      const store = new AuditStore({ auditDir: dir, auditMaxBytes: 1000 });

      // An empty command is rejected by sanitizeCommand *before* the transport
      // runs; the audit contract still requires a record for the rejected call.
      await expect(
        executeAuditedTransportCommand({
          transport,
          store,
          tool: 'exec',
          profile: 'p',
          command: '   ',
        }),
      ).rejects.toThrow(/Command cannot be empty/);

      // The transport must never have been invoked for a rejected command.
      expect(called).toBe(false);

      const file = activeFilePath(dir);
      const records = readFileSync(file, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
      expect(records).toHaveLength(1);
      expect(records[0].tool).toBe('exec');
      expect(records[0].exec.exit_code).toBeNull();
      expect(records[0].exec.stderr).toContain('Command cannot be empty');
    } finally {
      delete process.env.SSH_MCP_AUDIT_DIR;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
