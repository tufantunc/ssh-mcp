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

import { loadAuditSink } from '../audit-seam.js';
import type { ApprovalDecision } from '../types.js';

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
      expect(logged).toMatch(/audit store initialization failed/i);
    } finally {
      errSpy.mockRestore();
    }
  });
});
