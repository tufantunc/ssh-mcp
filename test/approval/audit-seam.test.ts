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
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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

  it('surfaces a diagnostic (not a silent no-op) when a present audit store fails to construct', async () => {
    // The audit module IS part of this build, so a construction failure here
    // is a real present-but-broken store (e.g. unwritable audit_dir), not the
    // documented missing-module path. It must be visible, not swallowed.
    // Force AuditStore's mkdirSync to fail with ENOTDIR by nesting the audit
    // dir under an existing regular file.
    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-audit-seam-'));
    const filePath = join(dir, 'not-a-dir');
    writeFileSync(filePath, 'x');
    const brokenAuditDir = join(filePath, 'audit'); // child of a file => ENOTDIR

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const sink = await loadAuditSink({ auditDir: brokenAuditDir });
      // Still returns a usable no-op sink (must not throw to callers)...
      expect(typeof sink.record).toBe('function');
      expect(() =>
        sink.record({
          tool: 'exec',
          profile: 'prod',
          command: 'uptime',
          startedAt: Date.now(),
          result: { stdout: 'ok', stderr: '', exitCode: 0 },
        }),
      ).not.toThrow();
      // ...but the failure was surfaced.
      expect(errSpy).toHaveBeenCalled();
      const logged = errSpy.mock.calls.map(c => String(c[0])).join('\n');
      expect(logged).toMatch(/audit module present but failed to initialize/i);
    } finally {
      errSpy.mockRestore();
    }
  });

  it('preserves the configured mode in the not-run marker when no approval decision exists', async () => {
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
      approvalMode: 'smart',
    });

    expect(appended.approval).toMatchObject({
      mode: 'smart',
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

  it('omits exec details for approval denials because no remote execution ran', async () => {
    let appended: any;
    const approval: ApprovalDecision = {
      decision: 'deny',
      reason: 'blocked by policy',
      decided_by: 'manual:user',
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
      profile: 'prod',
      command: 'systemctl restart sshd',
      startedAt: Date.now(),
      error: new Error('approval denied (manual/manual:user): blocked by policy'),
      approval,
    });

    expect(appended.approval).toMatchObject({
      decision: 'deny',
      decided_by: 'manual:user',
    });
    expect(appended.exec).toBeUndefined();
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

  it.each([
    ['missing resolveAuditDir', {
      AuditStore: class { append(): void {} },
    }],
    ['throwing resolveAuditDir', {
      resolveAuditDir: () => { throw new Error('bad audit dir'); },
      AuditStore: class { append(): void {} },
    }],
    ['throwing AuditStore constructor', {
      resolveAuditDir: () => '/tmp/ssh-mcp-audit-test',
      AuditStore: class { constructor() { throw new Error('store init failed'); } },
    }],
    ['store without append', {
      resolveAuditDir: () => '/tmp/ssh-mcp-audit-test',
      AuditStore: class {},
    }],
  ])('degrades an invalid audit module/store shape to a no-op: %s', async (_label, moduleShape) => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const sink = await loadAuditSink({}, async () => moduleShape);
      expect(typeof sink.record).toBe('function');
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining('audit module present but failed to initialize'),
      );
      expect(() => sink.record({
        tool: 'exec',
        profile: 'default',
        command: 'uptime',
        startedAt: Date.now(),
        error: new Error('pre-gate failure'),
        approvalMode: 'yolo',
      })).not.toThrow();
    } finally {
      spy.mockRestore();
    }
  });
});
