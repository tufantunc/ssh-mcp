/**
 * Optional audit-truth seam tests (Decision D2).
 *
 * On `pr/toml-config` (this lane's base) `src/audit/` is NOT present, so the
 * seam MUST degrade to a safe no-op: `loadAuditSink()` resolves, `.record()`
 * never throws, and the engine remains usable without the audit module. These
 * tests pin that contract so a future refactor can't silently make audit a
 * hard build/runtime prerequisite.
 */
import { describe, it, expect, vi } from 'vitest';

import { isOptionalAuditStoreMissing, loadAuditSink } from '../../src/approval/audit-seam.js';
import type { ApprovalDecision } from '../../src/approval/types.js';

describe('optional audit seam', () => {
  it('loadAuditSink resolves to a usable sink even when src/audit/ is absent', async () => {
    const sink = await loadAuditSink();
    expect(sink).toBeTruthy();
    expect(typeof sink.record).toBe('function');
  });

  it('record() is a no-op (never throws) on the audit-absent path', async () => {
    const sink = await loadAuditSink({ auditDir: '/nonexistent/should-not-be-written' });
    const approval: ApprovalDecision = {
      decision: 'allow',
      reason: 'smart allowed',
      decided_by: 'smart-llm',
      decided_at: new Date().toISOString(),
      mode: 'smart',
    };
    expect(() =>
      sink.record({
        tool: 'exec',
        profile: 'prod',
        command: 'uptime',
        startedAt: Date.now(),
        result: { stdout: 'ok', stderr: '', exitCode: 0 },
        approval,
      }),
    ).not.toThrow();
  });

  it('record() tolerates the error path (no decision, transport failure)', async () => {
    const sink = await loadAuditSink();
    expect(() =>
      sink.record({
        tool: 'sudo-exec',
        profile: 'default',
        command: 'reboot',
        startedAt: Date.now(),
        error: new Error('boom'),
      }),
    ).not.toThrow();
  });

  it('uses an explicit not-run marker instead of yolo allow when no approval decision exists', async () => {
    let appended: any;
    const sink = await loadAuditSink({}, async () => ({
      resolveAuditDir: () => '/tmp/ssh-mcp-audit-test',
      AuditStore: class {
        append(record: unknown): unknown {
          appended = record;
          return record;
        }
      },
    }));

    sink.record({
      tool: 'exec',
      profile: 'default',
      command: 'uptime',
      startedAt: Date.now(),
      error: new Error('transport init failed before approval'),
    });

    expect(appended.approval).toMatchObject({
      mode: 'manual',
      decision: 'deny',
      decided_by: 'approval:not-run',
    });
    expect(appended.approval.reason).toContain('approval gate was not reached');
  });

  it('preserves mapper error context when a failed ExecResult is audited', async () => {
    let appended: any;
    const approval: ApprovalDecision = {
      decision: 'allow',
      reason: 'manual approved',
      decided_by: 'user',
      decided_at: new Date().toISOString(),
      mode: 'manual',
    };
    const sink = await loadAuditSink({}, async () => ({
      resolveAuditDir: () => '/tmp/ssh-mcp-audit-test',
      AuditStore: class {
        append(record: unknown): unknown {
          appended = record;
          return record;
        }
      },
    }));

    sink.record({
      tool: 'exec',
      profile: 'default',
      command: 'false',
      startedAt: Date.now(),
      result: { stdout: '', stderr: '', exitCode: 7 },
      error: new Error('Error (code 7):\nCommand exited with status 7'),
      approval,
    });

    expect(appended.exec).toMatchObject({
      stdout: '',
      exitCode: 7,
    });
    expect(appended.exec.stderr).toContain('execution error:');
    expect(appended.exec.stderr).toContain('Command exited with status 7');
  });

  it('classifies only the optional store module itself as absent', () => {
    const expected = 'file:///repo/build/audit/store.js';
    const absent = Object.assign(
      new Error("Cannot find module '/repo/build/audit/store.js' imported from /repo/build/approval/audit-seam.js"),
      { code: 'ERR_MODULE_NOT_FOUND' },
    );
    const absentRelative = Object.assign(
      new Error("Cannot find module '../audit/store.js' imported from '/repo/src/approval/audit-seam.ts'"),
      { code: 'ERR_MODULE_NOT_FOUND' },
    );
    const brokenNestedImport = Object.assign(
      new Error("Cannot find module '/repo/build/audit/missing.js' imported from /repo/build/audit/store.js"),
      { code: 'ERR_MODULE_NOT_FOUND' },
    );

    expect(isOptionalAuditStoreMissing(absent, expected)).toBe(true);
    expect(isOptionalAuditStoreMissing(absentRelative, expected)).toBe(true);
    expect(isOptionalAuditStoreMissing(brokenNestedImport, expected)).toBe(false);
  });

  it('surfaces broken imports from a present audit module before degrading to no-op', async () => {
    const err = Object.assign(
      new Error("Cannot find module '/repo/build/audit/missing.js' imported from /repo/build/audit/store.js"),
      { code: 'ERR_MODULE_NOT_FOUND' },
    );
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const sink = await loadAuditSink({}, async () => { throw err; });
      expect(typeof sink.record).toBe('function');
      expect(spy).toHaveBeenCalledWith(expect.stringContaining('audit module present but failed to load'));
    } finally {
      spy.mockRestore();
    }
  });
});
