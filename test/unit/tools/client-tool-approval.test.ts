import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHarness, textOf, testProfile, type Harness } from './harness.js';
import { CLIENT_CONSENT_TOOLS, CLIENT_TOOL_APPROVER, createPipeline } from '../../../src/tools/pipeline.js';
import { TOOL_DESCRIPTIONS } from '../../../src/tools/descriptions.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import type { Profile } from '../../../src/types.js';
import { configWithDefaults, plant } from '../../helpers/registry.js';
import { tracer } from '../../../src/observability/tracer.js';
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

  it('still refuses what the denylist refuses', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('destructive-command', { command: 'rm -rf /' });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^POLICY_DENIED: /);
    expect(h.execCalls).toHaveLength(0);
  });

  it('still refuses what the role refuses', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool', role: 'viewer' });
    const res = await call('destructive-command', { command: DESTRUCTIVE });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^POLICY_DENIED: /);
    expect(h.execCalls).toHaveLength(0);
    expect(h.approvalPrompts()).toBe(0);
  });

  it('still counts against the daily command quota', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool', commandQuotaPerDay: 1 });
    expect((await call('destructive-command', { command: DESTRUCTIVE })).isError).toBeFalsy();
    const second = await call('destructive-command', { command: DESTRUCTIVE });

    expect(second.isError).toBe(true);
    expect(textOf(second)).toMatch(/^QUOTA_EXCEEDED: /);
    expect(h.execCalls).toHaveLength(1);
  });

  it('records the whole decision for a run the client approved', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    await call('destructive-command', { command: DESTRUCTIVE });

    expect(h.auditRecords).toHaveLength(1);
    expect(h.auditRecords[0]).toMatchObject({
      command: DESTRUCTIVE, commandClass: 'destructive', decision: 'require-approval',
      ruleId: 'approval-policy', approver: 'client-tool-consent',
    });
  });

  it('points a gated command on read-command at destructive-command', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('read-command', { command: DESTRUCTIVE });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^APPROVAL_VIA_TOOL: /);
    expect(textOf(res)).toContain('Call destructive-command with the same arguments');
    expect(h.execCalls).toHaveLength(0);
  });

  // A trace has to tell a call the client's prompt approved from one refused for
  // arriving on the wrong tool: both reach the same branch with the same decision.
  it.each([
    ['destructive-command', 'client-tool'],
    ['run-command', 'client-tool-refused'],
  ])('marks the policy span of a gated %s call as %s', async (tool, approval) => {
    const attributes: Record<string, unknown>[] = [];
    const startSpan = vi.spyOn(tracer, 'startSpan').mockImplementation(() => {
      const seen: Record<string, unknown> = {};
      attributes.push(seen);
      return {
        setAttribute: (key: string, value: unknown) => { seen[key] = value; },
        setAttributes: () => {}, setStatus: () => {}, recordException: () => {}, addEvent: () => {}, end: () => {},
        isRecording: () => true, spanContext: () => ({}), updateName: () => {},
      } as any;
    });
    try {
      h = await createHarness({ approvalPolicy: 'client-tool' });
      await call(tool, { command: DESTRUCTIVE });
    } finally {
      startSpan.mockRestore();
    }

    const policySpans = attributes.filter((a) => a['tool.name'] === tool);
    expect(policySpans.map((a) => a['policy.approval'])).toEqual([approval]);
  });

  it('never lets run-command count as consent', () => {
    // The whole design rests on this: run-command is the one tool users always-allow.
    expect(CLIENT_CONSENT_TOOLS.has('run-command')).toBe(false);
    expect(CLIENT_CONSENT_TOOLS.has('read-command')).toBe(false);
  });

  // A tool counts as consent only if each call does one gated kind of thing and the
  // client is expected to ask for it. A tool that clients are told is read-only, or that
  // carries commands of every class, is not one.
  it('lists exactly the tools whose call is the approval, each registered and none read-only', async () => {
    expect([...CLIENT_CONSENT_TOOLS].sort()).toEqual([
      'destructive-command', 'privileged-command', 'sftp-download-file', 'sftp-upload', 'sftp-upload-file',
    ]);
    h = await createHarness();
    const { tools } = await h.client.listTools();
    for (const name of CLIENT_CONSENT_TOOLS) {
      const tool = tools.find((t) => t.name === name);
      expect(tool, name).toBeDefined();
      expect(tool!.annotations?.readOnlyHint, name).not.toBe(true);
    }
  });
});

describe('each tool under client-tool', () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'client-tool-'));
    await chmod(root, 0o700);
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  // The SFTP stubs fail after the gate, so these read the gate's own decision off the
  // record: the approval policy's, not a refusal, with no prompt shown.
  const passedTheGate = () => {
    expect(h.approvalPrompts()).toBe(0);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'require-approval', ruleId: 'approval-policy' });
    expect(String(h.auditRecords.at(-1).error ?? '')).not.toMatch(/APPROVAL_VIA_TOOL/);
  };

  it('sftp-upload passes the gate on the tool call', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    await call('sftp-upload', { remotePath: '/srv/x', content: 'x' });
    passedTheGate();
  });

  it('sftp-upload-file passes the gate on the tool call', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' }, { localPath: { transferRoot: root } });
    await writeFile(join(root, 'x.bin'), 'payload');
    await call('sftp-upload-file', { localPath: 'x.bin', remotePath: '/tmp/x.bin' });
    passedTheGate();
  });

  it('sftp-download-file passes the gate on the tool call', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' }, { localPath: { transferRoot: root } });
    await call('sftp-download-file', { remotePath: '/etc/hostname', localPath: 'out.bin' });
    passedTheGate();
  });

  it('opens an interactive session on the tool call', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('open-session', { name: 'sh1', type: 'interactive' });

    expect(res.isError).toBeFalsy();
    expect(h.openSessionCalls).toHaveLength(1);
    passedTheGate();
    expect(h.auditRecords.at(-1).approver).toBe('client-tool-consent');
  });

  // A background session runs a command of any class, as run-command does, and a user
  // who always-allows open-session for tailing a log has not approved a destructive one.
  it('refuses a gated command in a background session', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('open-session', { name: 'bg', type: 'background', command: DESTRUCTIVE });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^APPROVAL_VIA_TOOL: /);
    expect(textOf(res)).not.toContain('same arguments');
    expect(h.openSessionCalls).toHaveLength(0);
    expect(h.approvalPrompts()).toBe(0);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'approval-via-tool' });
  });

  // sftp-download is annotated read-only, which clients take as a reason not to ask.
  it('refuses a download whose path raises its class', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('sftp-download', { remotePath: '/tmp/a; rm -rf /x' });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/^APPROVAL_VIA_TOOL: /);
    expect(textOf(res)).not.toContain('same arguments');
    expect(h.approvalPrompts()).toBe(0);
  });

  it('describes destructive-command as the tool for gated commands, flagged destructive', async () => {
    h = await createHarness();
    const { tools } = await h.client.listTools();
    const tool = tools.find((t) => t.name === 'destructive-command')!;

    expect(tool.annotations?.destructiveHint).toBe(true);
    expect(tool.description).toBe(TOOL_DESCRIPTIONS['destructive-command']);
  });

  it('runs destructive-command in a session when one is named', async () => {
    h = await createHarness({ approvalPolicy: 'client-tool' });
    const res = await call('destructive-command', { command: DESTRUCTIVE, session: 'missing' });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/Session "missing" not found/);
    expect(h.execCalls).toHaveLength(0);
  });
});

/**
 * destructive-command exists for every installation, and a rule written for run-command
 * (an OPA policy on `input.action.tool`, a client's per-tool permission) does not match
 * it. So on a profile that did not choose client-tool it runs nothing at all, whatever
 * the command, and says where the command belongs.
 */
describe('destructive-command on a profile that did not opt in', () => {
  const POLICIES = ['auto', 'ask-destructive', 'ask-all', 'deny'] as const;
  const COMMANDS = [DESTRUCTIVE, 'echo hi'];

  it.each(POLICIES.flatMap((policy) => COMMANDS.map((command) => [policy, command] as const)))(
    'is refused under %s (%s) and points at run-command',
    async (policy, command) => {
      h = await createHarness({ approvalPolicy: policy });
      const res = await call('destructive-command', { command });

      expect(res.isError).toBe(true);
      expect(textOf(res)).toMatch(/^CLIENT_TOOL_ONLY: /);
      expect(textOf(res)).toContain('Call run-command with the same arguments');
      expect(h.execCalls).toHaveLength(0);
      expect(h.approvalPrompts()).toBe(0);
      expect(h.auditRecords).toEqual([expect.objectContaining({ command, decision: 'deny', ruleId: 'client-tool-only' })]);
    },
  );

  // OPA sees the tool name, and the point of the refusal is that a policy written for
  // run-command is never asked about a tool it was not written for.
  it('is refused before OPA is asked', async () => {
    const profile: Profile = { ...testProfile, approvalPolicy: 'auto' };
    const registry = new ConnectionRegistry(configWithDefaults({}, profile));
    const conn = plant(registry, profile);
    vi.spyOn(conn, 'isConnected').mockReturnValue(true);
    const exec = vi.spyOn(conn, 'exec');
    const policy = new PolicyEngine(DEFAULT_RULES);
    const opa = vi.spyOn(policy, 'evaluateWithOpa');
    const pipeline = createPipeline({
      server: {} as any, registry, policy, audit: { record: async () => {} } as any,
    });

    await expect(pipeline.runAudited(
      DESTRUCTIVE,
      { toolName: 'destructive-command', failureClass: 'safe', profile: profile.name, extra: {} },
      pipeline.execAndReport(),
    )).rejects.toThrow(/^CLIENT_TOOL_ONLY: /);
    expect(opa).not.toHaveBeenCalled();
    expect(exec).not.toHaveBeenCalled();
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
