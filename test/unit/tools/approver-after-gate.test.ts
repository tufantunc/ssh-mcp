import { describe, it, expect, afterEach } from 'vitest';
import { createHarness, textOf, type Harness } from './harness.js';
import { CLIENT_TOOL_APPROVER } from '../../../src/tools/pipeline.js';

/**
 * Once the approval gate has said who approved a call, every audit record for that
 * call names them, including the record of a call that failed afterwards.
 *
 * The failure record used to drop the approver. The case that matters most is a
 * connection that fails while an approved destructive command runs: it may have
 * changed the host, and the record must still say who let it run.
 */

let h: Harness;

afterEach(async () => { await h?.close(); });

async function call(name: string, args: Record<string, unknown> = {}) {
  return h.client.callTool({ name, arguments: args }) as Promise<any>;
}

const DESTRUCTIVE = 'rm -rf /tmp/build';

describe('audit approver on a call that fails after the approval gate', () => {
  it('keeps the elicitation approver when the approved command fails to run', async () => {
    h = await createHarness();
    h.setApproval(true);
    h.setExecError(new Error('Connection lost'));

    const res = await call('run-command', { command: DESTRUCTIVE });

    expect(res.isError).toBe(true);
    expect(h.approvalPrompts()).toBe(1);
    expect(h.execCalls).toHaveLength(1);
    expect(h.auditRecords).toHaveLength(1);
    expect(h.auditRecords[0]).toMatchObject({
      command: DESTRUCTIVE, error: 'Connection lost', approver: 'mcp-client',
    });
  });

  it('keeps the client-tool approver when the approved command fails to run', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    h.setExecError(new Error('Connection lost'));

    const res = await call('destructive-command', { command: DESTRUCTIVE });

    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(1);
    expect(h.auditRecords).toHaveLength(1);
    expect(h.auditRecords[0]).toMatchObject({
      command: DESTRUCTIVE, error: 'Connection lost', approver: CLIENT_TOOL_APPROVER,
    });
  });

  it('keeps the approver when the quota refuses a call after it was approved', async () => {
    h = await createHarness({ commandQuotaPerDay: 1 });
    h.setApproval(true);
    await call('run-command', { command: 'echo spend-the-quota' });

    const res = await call('run-command', { command: DESTRUCTIVE });

    expect(textOf(res)).toMatch(/QUOTA_EXCEEDED/);
    expect(h.approvalPrompts()).toBe(1);
    expect(h.auditRecords.at(-1)).toMatchObject({
      command: DESTRUCTIVE, decision: 'deny', ruleId: 'command-quota', approver: 'mcp-client',
    });
  });

  it('records no approver for a call refused before anyone approved it', async () => {
    h = await createHarness();
    h.setApproval(false);

    await call('run-command', { command: DESTRUCTIVE });

    expect(h.execCalls).toHaveLength(0);
    expect(h.auditRecords.at(-1).approver).toBeUndefined();
  });
});
