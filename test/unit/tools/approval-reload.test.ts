import { describe, it, expect, vi, beforeEach } from 'vitest';
import { requestApproval } from '../../../src/guard/elicitation.js';
import { createPipeline } from '../../../src/tools/pipeline.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { SSHConnection } from '../../../src/ssh/connection.js';
import { defaultsFromArgv } from '../../../src/cli.js';
import type { AppConfig, PolicyEvaluation, Profile } from '../../../src/types.js';
import { testProfile } from './harness.js';

/**
 * A human approval can take minutes, and a config reload can land inside that wait.
 * The approval was given under the old rules, so it is re-checked against the new
 * ones before the command runs — and a grant from before the reload stops counting.
 *
 * The prompt is faked so the test can reload at the exact point the human is
 * deciding; the registry is real, because `generation` and the in-place profile
 * swap are what is under test.
 */
vi.mock('../../../src/guard/elicitation.js', () => ({ requestApproval: vi.fn() }));
const approve = vi.mocked(requestApproval);

const COMMAND = 'rm -rf /tmp/build';

const configOf = (profile: Profile): AppConfig => ({
  defaults: { ...defaultsFromArgv({}), approvalGrantTtlMs: 60_000 },
  profiles: [profile],
});

function setup(profile: Profile = testProfile, policy: PolicyEngine = new PolicyEngine(DEFAULT_RULES)) {
  const registry = new ConnectionRegistry(configOf(profile));
  // A real SSHConnection, never connected, planted as if it were — the registry hands it
  // out and swaps its profile on reload exactly as it would a live one.
  const conn = new SSHConnection(profile, { password: 'x' } as never, new Map(), 'insecure');
  vi.spyOn(conn, 'isConnected').mockReturnValue(true);
  const exec = vi.spyOn(conn, 'exec').mockImplementation(async (command: string) => ({
    stdout: '', stderr: '', exitCode: 0, durationMs: 1, profile: profile.name, command,
  }));
  (registry as any).connections.set(profile.name, conn);

  const records: any[] = [];
  const pipeline = createPipeline({
    server: {} as any,
    registry,
    policy,
    audit: { record: async (r: any) => { records.push(r); } } as any,
  });
  const run = () => pipeline.runAudited(
    COMMAND,
    { toolName: 'run-command', failureClass: 'safe', profile: profile.name, extra: {} },
    pipeline.execAndReport(),
  );
  return { registry, conn, exec, records, pipeline, run };
}

describe('an approval that completes after a config reload', () => {
  beforeEach(() => {
    approve.mockReset();
  });

  it('is refused when the reload denies the command', async () => {
    const { registry, exec, records, pipeline, run } = setup();
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile, approvalPolicy: 'deny' }));
      return { approved: true, approver: 'elicitation' };
    });

    await expect(run()).rejects.toThrow(/reloaded/i);

    expect(exec).not.toHaveBeenCalled();
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded', command: COMMAND });
    expect(pipeline.grants.has(testProfile.name, COMMAND, 'destructive')).toBe(false);
  });

  it('proceeds when the posture is unchanged across the reload', async () => {
    const { registry, exec, records, pipeline, run } = setup();
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile }));
      return { approved: true, approver: 'elicitation' };
    });

    await run();

    expect(exec).toHaveBeenCalledTimes(1);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ decision: 'require-approval', commandClass: 'destructive', approver: 'elicitation' });
    expect(pipeline.grants.has(testProfile.name, COMMAND, 'destructive')).toBe(true);
  });

  // A connection-field change closes the connection the human approved running on.
  it('is refused when the connection was closed by the reload', async () => {
    const { registry, exec, records, pipeline, run } = setup();
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile, host: 'elsewhere' }));
      return { approved: true, approver: 'elicitation' };
    });

    await expect(run()).rejects.toThrow(/reloaded/i);

    expect(exec).not.toHaveBeenCalled();
    expect(records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded' });
    expect(pipeline.grants.has(testProfile.name, COMMAND, 'destructive')).toBe(false);
  });

  it('is refused when the profile was removed by the reload', async () => {
    const { registry, exec, records, run } = setup();
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile, name: 'other' }));
      return { approved: true, approver: 'elicitation' };
    });

    await expect(run()).rejects.toThrow(/reloaded/i);

    expect(exec).not.toHaveBeenCalled();
    expect(records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded' });
  });
});

describe('the re-check after a reload, against a scripted policy', () => {
  const asks = (commandClass: PolicyEvaluation['commandClass']): PolicyEvaluation =>
    ({ decision: 'require-approval', commandClass, binary: 'rm', ruleId: 'scripted' });

  beforeEach(() => {
    approve.mockReset();
  });

  // The comparison is the new evaluation against the one the human approved.
  it('refuses when the new rules put the command in a different class', async () => {
    const evaluateWithOpa = vi.fn()
      .mockResolvedValueOnce(asks('destructive'))
      .mockResolvedValueOnce(asks('privileged'));
    const { registry, exec, records, pipeline, run } = setup(testProfile, { evaluateWithOpa } as any);
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile }));
      return { approved: true, approver: 'elicitation' };
    });

    await expect(run()).rejects.toThrow(/reloaded/i);

    expect(evaluateWithOpa).toHaveBeenCalledTimes(2);
    expect(exec).not.toHaveBeenCalled();
    expect(records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded' });
    expect(pipeline.grants.has(testProfile.name, COMMAND, 'destructive')).toBe(false);
    expect(pipeline.grants.has(testProfile.name, COMMAND, 'privileged')).toBe(false);
  });

  it('records the new evaluation when the new rules allow the command outright', async () => {
    const evaluateWithOpa = vi.fn()
      .mockResolvedValueOnce(asks('destructive'))
      .mockResolvedValueOnce({ ...asks('destructive'), decision: 'allow', ruleId: 'new-rule' });
    const { registry, exec, records, run } = setup(testProfile, { evaluateWithOpa } as any);
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile }));
      return { approved: true, approver: 'elicitation' };
    });

    await run();

    expect(exec).toHaveBeenCalledTimes(1);
    expect(records[0]).toMatchObject({ decision: 'allow', ruleId: 'new-rule', approver: 'elicitation' });
  });

  it('refuses when another reload lands during the re-evaluation', async () => {
    let registry!: ConnectionRegistry;
    const evaluateWithOpa = vi.fn()
      .mockResolvedValueOnce(asks('destructive'))
      .mockImplementationOnce(async () => {
        registry.applyConfig(configOf({ ...testProfile }));
        return asks('destructive');
      });
    const h = setup(testProfile, { evaluateWithOpa } as any);
    registry = h.registry;
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile }));
      return { approved: true, approver: 'elicitation' };
    });

    await expect(h.run()).rejects.toThrow(/reloaded/i);

    expect(h.exec).not.toHaveBeenCalled();
    expect(h.records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded' });
  });
});

describe('a grant from before a config reload', () => {
  beforeEach(() => {
    approve.mockReset();
  });

  it('is not reused: the next identical command prompts again', async () => {
    const { registry, exec, run } = setup();
    approve.mockResolvedValue({ approved: true, approver: 'elicitation' });

    await run();
    await run();
    expect(approve).toHaveBeenCalledTimes(1);

    registry.applyConfig(configOf({ ...testProfile }));
    await run();

    expect(approve).toHaveBeenCalledTimes(2);
    expect(exec).toHaveBeenCalledTimes(3);
  });

  it('takes its TTL from the live config', async () => {
    const { registry, run } = setup();
    approve.mockResolvedValue({ approved: true, approver: 'elicitation' });

    await run();
    await run();
    expect(approve).toHaveBeenCalledTimes(1);

    // Grants switched off by the reload: the approval after it records nothing, so the
    // command after that prompts too.
    registry.applyConfig({ ...configOf({ ...testProfile }), defaults: { ...defaultsFromArgv({}), approvalGrantTtlMs: 0 } });
    await run();
    await run();

    expect(approve).toHaveBeenCalledTimes(3);
  });
});
