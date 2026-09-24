import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CommandReviewer, ReviewResult } from '../../../src/reviewer/types.js';
import { createHarness, type Harness } from './harness.js';

let h: Harness;
afterEach(async () => { await h?.close(); });

function reviewer(result: Partial<ReviewResult> = {}): CommandReviewer & { review: ReturnType<typeof vi.fn> } {
  return {
    review: vi.fn().mockResolvedValue({
      status: 'completed',
      verdict: 'approve',
      risk: 'low',
      summary: 'No material risk found.',
      findings: [],
      model: 'fake-model',
      policyVersion: '2',
      durationMs: 2,
      ...result,
    }),
  };
}

describe('contextual reviewer in the tool pipeline', () => {
  it('skips read-only commands', async () => {
    const r = reviewer();
    h = await createHarness({}, { reviewer: r });
    await h.client.callTool({ name: 'read-command', arguments: { command: 'ls -la' } });
    expect(r.review).not.toHaveBeenCalled();
  });

  it('skips commands denied by deterministic policy', async () => {
    const r = reviewer();
    h = await createHarness({}, { reviewer: r });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'rm -rf /' } });
    expect(r.review).not.toHaveBeenCalled();
    expect(h.execCalls).toHaveLength(0);
  });

  it('does not let reviewer or human approval bypass an RBAC denial', async () => {
    const r = reviewer();
    h = await createHarness({ role: 'viewer', group: 'prod' }, { reviewer: r });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/x' } });
    expect(r.review).not.toHaveBeenCalled();
    expect(h.approvalPrompts()).toBe(0);
    expect(h.execCalls).toHaveLength(0);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'role-binding' });
  });

  it('lets an LLM approval discharge the soft approval gate', async () => {
    const r = reviewer();
    h = await createHarness({ approvalPolicy: 'ask-all' }, { reviewer: r });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/x' } });
    expect(r.review).toHaveBeenCalledOnce();
    expect(h.approvalPrompts()).toBe(0);
    expect(h.auditRecords.at(-1)).toMatchObject({
      decision: 'allow', approver: 'llm-reviewer',
      review: { status: 'completed', verdict: 'approve', risk: 'low' },
    });
  });

  it('raises medium risk to approval and shows the findings', async () => {
    const r = reviewer({
      verdict: 'escalate',
      risk: 'medium',
      summary: 'This changes production state.',
      findings: [{ category: 'service-impact', severity: 'medium', message: 'No rollback step.' }],
    });
    h = await createHarness({}, { reviewer: r });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/x' } });
    expect(h.approvalPrompts()).toBe(1);
    expect(h.approvalMessages()[0]).toContain('medium risk');
    expect(h.approvalMessages()[0]).toContain('No rollback step.');
    expect(h.auditRecords.at(-1)).toMatchObject({
      decision: 'require-approval',
      ruleId: 'llm-reviewer-escalate',
      review: { risk: 'medium' },
    });
  });

  it('raises reviewer failure to approval', async () => {
    const r = reviewer({ status: 'unavailable', verdict: 'escalate', risk: 'unknown', unavailableCode: 'timeout' });
    h = await createHarness({}, { reviewer: r });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/x' } });
    expect(h.approvalMessages()[0]).toContain('unavailable (timeout)');
  });

  it('does not call the reviewer after the command quota is exhausted', async () => {
    const r = reviewer();
    h = await createHarness({ commandQuotaPerDay: 1 }, { reviewer: r });

    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/first' } });
    const blocked = await h.client.callTool({
      name: 'run-command', arguments: { command: 'touch /tmp/second' },
    });

    expect(r.review).toHaveBeenCalledOnce();
    expect(blocked.isError).toBe(true);
    expect(h.execCalls).toHaveLength(1);
  });

  it('releases reserved quota when the human declines an escalation', async () => {
    const r = reviewer({ verdict: 'escalate', risk: 'medium' });
    h = await createHarness({ commandQuotaPerDay: 1 }, { reviewer: r });
    h.setApproval(false);

    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/declined' } });
    h.setApproval(true);
    const accepted = await h.client.callTool({
      name: 'run-command', arguments: { command: 'touch /tmp/accepted' },
    });

    expect(accepted.isError).toBeFalsy();
    expect(r.review).toHaveBeenCalledTimes(2);
    expect(h.execCalls).toHaveLength(1);
  });

  it.each([
    ['escalate', 'medium'],
    ['deny', 'high'],
  ] as const)('does not reuse JIT grants for reviewer %s approval', async (verdict, risk) => {
    const r = reviewer({ verdict, risk });
    h = await createHarness({}, { reviewer: r, approvalGrantTtlMs: 60_000 });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/x' } });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/x' } });
    expect(h.approvalPrompts()).toBe(2);
  });

  it('sends an LLM denial to a fresh human approval that can override it', async () => {
    const r = reviewer({ verdict: 'deny', risk: 'high', summary: 'Unsafe target scope.' });
    h = await createHarness({}, { reviewer: r });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/x' } });
    expect(h.approvalPrompts()).toBe(1);
    expect(h.approvalMessages()[0]).toContain('deny (high risk)');
    expect(h.execCalls).toHaveLength(1);
    expect(h.auditRecords.at(-1)).toMatchObject({
      decision: 'require-approval', ruleId: 'llm-reviewer-deny-escalate', approver: 'mcp-client',
      review: { verdict: 'deny', risk: 'high' },
    });
  });

  it('does not execute an LLM denial when the human declines it', async () => {
    const r = reviewer({ verdict: 'deny', risk: 'high', summary: 'Unsafe target scope.' });
    h = await createHarness({}, { reviewer: r });
    h.setApproval(false);
    await h.client.callTool({ name: 'run-command', arguments: { command: 'touch /tmp/x' } });
    expect(h.approvalPrompts()).toBe(1);
    expect(h.execCalls).toHaveLength(0);
    expect(h.auditRecords.at(-1)).toMatchObject({
      decision: 'require-approval', ruleId: 'llm-reviewer-deny-escalate',
      review: { verdict: 'deny', risk: 'high' },
    });
  });

  it('keeps privileged operations human-only after an LLM approval', async () => {
    const r = reviewer();
    h = await createHarness({}, { reviewer: r });
    await h.client.callTool({ name: 'run-command', arguments: { command: 'sudo systemctl restart demo' } });
    expect(h.approvalPrompts()).toBe(1);
    expect(h.auditRecords.at(-1)).toMatchObject({
      decision: 'require-approval', ruleId: 'llm-reviewer-human-only', approver: 'mcp-client',
    });
  });

  it.each([
    ['signal-process', { pid: 42, signal: 'TERM' }],
    ['open-session', { name: 'work', type: 'interactive' }],
  ])('reviews non-read-only synthetic operation %s', async (name, args) => {
    const r = reviewer();
    h = await createHarness({}, { reviewer: r });
    await h.client.callTool({ name, arguments: args });
    expect(r.review).toHaveBeenCalledOnce();
  });

  it.each([
    ['sftp-upload', { remotePath: '/tmp/x.txt', content: 'payload' }, {}],
    ['sftp-upload-file', { localPath: 'missing.bin', remotePath: '/tmp/x.bin' },
      { localPath: { transferRoot: '/tmp/ssh-mcp-review-test' } }],
    ['sftp-download-file', { remotePath: '/etc/hostname', localPath: 'out.bin' },
      { localPath: { transferRoot: '/tmp/ssh-mcp-review-test' } }],
  ])('reviews write-capable transfer %s', async (name, args, opts) => {
    const r = reviewer();
    h = await createHarness({}, { reviewer: r, ...opts });
    await h.client.callTool({ name, arguments: args }).catch(() => {});
    expect(r.review).toHaveBeenCalledOnce();
    expect(r.review.mock.calls[0][0].commandClass).not.toBe('read-only');
  });

  it('never reviews or blocks session release', async () => {
    const r = reviewer();
    h = await createHarness({}, { reviewer: r });
    await h.client.callTool({ name: 'open-session', arguments: { name: 'work', type: 'interactive' } });
    r.review.mockClear();
    await h.client.callTool({ name: 'close-session', arguments: { name: 'work' } });
    expect(r.review).not.toHaveBeenCalled();
  });
});
