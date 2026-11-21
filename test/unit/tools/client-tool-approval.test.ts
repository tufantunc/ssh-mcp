import { describe, it, expect, afterEach } from 'vitest';
import { createHarness, textOf, type Harness } from './harness.js';
import { CLIENT_CONSENT_TOOLS, CLIENT_TOOL_APPROVER } from '../../../src/tools/pipeline.js';
import { configSchema } from '../../../src/config/schema.js';

/**
 * approvalPolicy = "client-tool": for clients that cannot show an elicitation prompt.
 * The client's own consent prompt for a tool call is the approval, which only means
 * something for a tool that does one gated thing. run-command carries safe and
 * destructive commands alike, so a gated command there is refused and pointed at
 * destructive-command instead of running.
 */

let h: Harness;

afterEach(async () => { await h?.close(); });

async function call(name: string, args: Record<string, unknown> = {}) {
  return h.client.callTool({ name, arguments: args }) as Promise<any>;
}

const DESTRUCTIVE = 'rm -rf /tmp/build';

describe('approvalPolicy = "client-tool"', () => {
  it('refuses a destructive command on run-command, without prompting or running it', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('run-command', { command: DESTRUCTIVE });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^APPROVAL_VIA_TOOL: /);
    expect(textOf(res)).toContain('destructive-command');
    expect(h.execCalls).toHaveLength(0);
    expect(h.approvalPrompts()).toBe(0);
    expect(h.auditRecords.at(-1)).toMatchObject({
      decision: 'deny', ruleId: 'approval-via-tool', command: DESTRUCTIVE,
    });
  });

  it('runs the same command on destructive-command, without an elicitation prompt', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('destructive-command', { command: DESTRUCTIVE });

    expect(res.isError).toBeFalsy();
    expect(h.execCalls.map((c) => c.command)).toEqual([DESTRUCTIVE]);
    expect(h.approvalPrompts()).toBe(0);
    expect(h.auditRecords.at(-1)).toMatchObject({ command: DESTRUCTIVE, approver: CLIENT_TOOL_APPROVER });
  });

  it('runs privileged-command on the tool call alone', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('privileged-command', { command: 'systemctl restart nginx' });

    expect(res.isError).toBeFalsy();
    expect(h.execCalls).toHaveLength(1);
    expect(h.approvalPrompts()).toBe(0);
    expect(h.auditRecords.at(-1)).toMatchObject({ approver: CLIENT_TOOL_APPROVER });
  });

  it('still runs safe commands on run-command', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('run-command', { command: 'echo hi' });

    expect(res.isError).toBeFalsy();
    expect(h.execCalls).toHaveLength(1);
    expect(h.approvalPrompts()).toBe(0);
  });

  it('still refuses what the role, group or denylist refuses', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('destructive-command', { command: 'rm -rf /' });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^POLICY_DENIED: /);
    expect(h.execCalls).toHaveLength(0);
  });

  it('never lets run-command count as consent', () => {
    // The whole design rests on this: run-command is the one tool users always-allow.
    expect(CLIENT_CONSENT_TOOLS.has('run-command')).toBe(false);
    expect(CLIENT_CONSENT_TOOLS.has('read-command')).toBe(false);
  });
});

describe('destructive-command under the other policies', () => {
  it('prompts exactly like run-command under ask-destructive', async () => {
    h = await createHarness({ approvalPolicy: 'ask-destructive' });
    const res = await call('destructive-command', { command: DESTRUCTIVE });

    expect(res.isError).toBeFalsy();
    expect(h.approvalPrompts()).toBe(1);
    expect(h.auditRecords.at(-1).approver).not.toBe(CLIENT_TOOL_APPROVER);
  });

  it('is refused when the user declines the prompt under ask-destructive', async () => {
    h = await createHarness({ approvalPolicy: 'ask-destructive' });
    h.setApproval(false);
    const res = await call('destructive-command', { command: DESTRUCTIVE });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^APPROVAL_DENIED: /);
    expect(h.execCalls).toHaveLength(0);
  });

  it('is refused outright under deny', async () => {
    h = await createHarness({ approvalPolicy: 'deny' });
    const res = await call('destructive-command', { command: DESTRUCTIVE });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^POLICY_DENIED: /);
    expect(h.execCalls).toHaveLength(0);
    expect(h.approvalPrompts()).toBe(0);
  });
});

describe('config', () => {
  it('accepts client-tool as a default and as a per-profile policy', () => {
    const parsed = configSchema.parse({
      defaults: { approvalMode: 'client-tool' },
      profiles: [{ name: 'a', host: 'h', user: 'u', auth: 'agent', approvalPolicy: 'client-tool' }],
    });
    expect(parsed.defaults.approvalMode).toBe('client-tool');
    expect(parsed.profiles[0].approvalPolicy).toBe('client-tool');
  });
});
