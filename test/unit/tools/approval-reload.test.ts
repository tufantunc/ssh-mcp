import { describe, it, expect, vi, beforeEach } from 'vitest';
import { requestApproval } from '../../../src/guard/elicitation.js';
import { createPipeline } from '../../../src/tools/pipeline.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import type { AppConfig, PolicyEvaluation, Profile } from '../../../src/types.js';
import { testProfile } from './harness.js';
import { configWithDefaults, plant } from '../../helpers/registry.js';

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

const configOf = (profile: Profile): AppConfig => configWithDefaults({ approvalGrantTtlMs: 60_000 }, profile);

function setup(profile: Profile = testProfile, policy: PolicyEngine = new PolicyEngine(DEFAULT_RULES)) {
  const registry = new ConnectionRegistry(configOf(profile));
  // Planted as if connected: the registry hands it out and swaps its profile on reload
  // exactly as it would a live one.
  const conn = plant(registry, profile);
  vi.spyOn(conn, 'isConnected').mockReturnValue(true);
  const exec = vi.spyOn(conn, 'exec').mockImplementation(async (command: string) => ({
    stdout: '', stderr: '', exitCode: 0, durationMs: 1, profile: profile.name, command,
  }));

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

  // The refusal carries a fixed reason, never one built from the old or new config.
  it('refuses with a fixed reason', async () => {
    const { registry, pipeline } = setup();
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile, approvalPolicy: 'deny' }));
      return { approved: true, approver: 'elicitation' };
    });

    const err: any = await pipeline.runAudited(
      COMMAND,
      { toolName: 'run-command', failureClass: 'safe', profile: testProfile.name, extra: {} },
      pipeline.execAndReport(),
    ).catch((e) => e);

    expect(err.evaluation).toMatchObject({
      decision: 'deny',
      ruleId: 'config-reloaded',
      reason: 'The configuration was reloaded while waiting for approval; the command was not run.',
    });
  });

  // A reload that lands while the connection is being resolved has to trigger the
  // re-check too: the evaluation that follows is not the one the reload would see.
  it('is re-checked when the reload lands during connection resolution', async () => {
    const { registry, conn, exec, records, run } = setup();
    vi.spyOn(registry, 'getOrCreate').mockImplementation(async () => {
      // The reload closes the very connection being handed back.
      registry.applyConfig(configOf({ ...testProfile, host: 'elsewhere' }));
      return conn;
    });
    approve.mockResolvedValue({ approved: true, approver: 'elicitation' });

    await expect(run()).rejects.toThrow(/reloaded/i);

    expect(exec).not.toHaveBeenCalled();
    expect(records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded' });
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

  it('does not run the command when the re-evaluation itself fails', async () => {
    const evaluateWithOpa = vi.fn()
      .mockResolvedValueOnce(asks('destructive'))
      .mockRejectedValueOnce(new Error('OPA unreachable'));
    const { registry, exec, records, pipeline, run } = setup(testProfile, { evaluateWithOpa } as any);
    approve.mockImplementation(async () => {
      registry.applyConfig(configOf({ ...testProfile }));
      return { approved: true, approver: 'elicitation' };
    });

    await expect(run()).rejects.toThrow('OPA unreachable');

    expect(exec).not.toHaveBeenCalled();
    expect(pipeline.grants.has(testProfile.name, COMMAND, 'destructive')).toBe(false);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ decision: 'deny', error: 'OPA unreachable' });
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

describe('the generation a grant is tagged with', () => {
  beforeEach(() => {
    approve.mockReset();
  });

  /** Land a reload just before the grant is written, as if it arrived in that gap. */
  function reloadBeforeGrantWrite(h: ReturnType<typeof setup>) {
    const write = h.pipeline.grants.record.bind(h.pipeline.grants);
    vi.spyOn(h.pipeline.grants, 'record').mockImplementation((...args) => {
      h.registry.applyConfig(configOf({ ...testProfile }));
      write(...args);
    });
  }

  it('is the one the approval was evaluated under, on the plain path', async () => {
    const h = setup();
    approve.mockResolvedValue({ approved: true, approver: 'elicitation' });
    reloadBeforeGrantWrite(h);

    await h.run();

    expect(h.exec).toHaveBeenCalledTimes(1);
    expect(h.pipeline.grants.has(testProfile.name, COMMAND, 'destructive')).toBe(false);
  });

  it('is the one the re-check ran under, after a reload during approval', async () => {
    const h = setup();
    approve.mockImplementation(async () => {
      h.registry.applyConfig(configOf({ ...testProfile }));
      return { approved: true, approver: 'elicitation' };
    });
    reloadBeforeGrantWrite(h);

    await h.run();

    expect(h.exec).toHaveBeenCalledTimes(1);
    expect(h.pipeline.grants.has(testProfile.name, COMMAND, 'destructive')).toBe(false);
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
    registry.applyConfig(configWithDefaults({ approvalGrantTtlMs: 0 }, { ...testProfile }));
    await run();
    await run();

    expect(approve).toHaveBeenCalledTimes(3);
  });
});

/**
 * A reload can land while the policy decision itself is being made: the connection
 * resolve and an OPA round-trip are both awaits. A decision that came back `allow`, or
 * found a grant, was made under rules that are no longer live, so it is re-checked the
 * way an approval is, and stands only if the new rules allow the command outright with
 * the same class.
 */
describe('a decision made while a reload landed', () => {
  const RECHECK_REASON = 'The configuration was reloaded while the command was being checked; the command was not run.';

  beforeEach(() => {
    approve.mockReset();
  });

  /** The engine is real; the first evaluation lands `reload` before it returns. */
  function reloadDuringEvaluation(policy: PolicyEngine, reload: () => void) {
    const evaluate = policy.evaluateWithOpa.bind(policy);
    let first = true;
    return vi.spyOn(policy, 'evaluateWithOpa').mockImplementation(async (...args) => {
      const result = await evaluate(...args);
      if (first) {
        first = false;
        reload();
      }
      return result;
    });
  }

  const runRead = (h: ReturnType<typeof setup>, command = 'ls /') => h.pipeline.runAudited(
    command,
    { toolName: 'run-command', failureClass: 'safe', profile: testProfile.name, extra: {} },
    h.pipeline.execAndReport(),
  );

  it('refuses an allow when the new rules deny the command', async () => {
    const policy = new PolicyEngine(DEFAULT_RULES);
    // Allowed without a prompt under `auto`; refused outright under `deny`.
    const h = setup({ ...testProfile, approvalPolicy: 'auto' }, policy);
    const spy = reloadDuringEvaluation(policy, () => {
      h.registry.applyConfig(configOf({ ...testProfile, approvalPolicy: 'deny' }));
    });

    const err: any = await h.run().catch((e) => e);

    expect(err).toBeInstanceOf(Error);
    expect(err.message).toMatch(/^CONFIG_RELOADED: /);
    expect(spy).toHaveBeenCalledTimes(2);
    expect(h.exec).not.toHaveBeenCalled();
    expect(h.records).toHaveLength(1);
    expect(h.records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded' });
    expect(err.evaluation.reason).toBe(RECHECK_REASON);
  });

  it('refuses an allow when the new rules ask for approval instead', async () => {
    const policy = new PolicyEngine(DEFAULT_RULES);
    const h = setup(testProfile, policy);
    reloadDuringEvaluation(policy, () => {
      h.registry.applyConfig(configOf({ ...testProfile, approvalPolicy: 'ask-all' }));
    });

    await expect(runRead(h)).rejects.toThrow(/^CONFIG_RELOADED: /);

    expect(approve).not.toHaveBeenCalled();
    expect(h.exec).not.toHaveBeenCalled();
  });

  it('refuses an allow when the reload closed the connection', async () => {
    const policy = new PolicyEngine(DEFAULT_RULES);
    const h = setup(testProfile, policy);
    reloadDuringEvaluation(policy, () => {
      h.registry.applyConfig(configOf({ ...testProfile, host: 'elsewhere' }));
    });

    await expect(runRead(h)).rejects.toThrow(/^CONFIG_RELOADED: /);

    expect(h.exec).not.toHaveBeenCalled();
    expect(h.records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded' });
  });

  it('proceeds when the new rules still allow it with the same class', async () => {
    const policy = new PolicyEngine(DEFAULT_RULES);
    const h = setup(testProfile, policy);
    const spy = reloadDuringEvaluation(policy, () => {
      h.registry.applyConfig(configOf({ ...testProfile, workdir: '/srv' }));
    });

    await runRead(h);

    expect(spy).toHaveBeenCalledTimes(2);
    expect(h.exec).toHaveBeenCalledTimes(1);
    expect(h.records[0]).toMatchObject({ decision: 'allow' });
  });

  it('refuses a grant reuse when the new rules deny the command', async () => {
    const policy = new PolicyEngine(DEFAULT_RULES);
    const h = setup(testProfile, policy);
    reloadDuringEvaluation(policy, () => {
      h.registry.applyConfig(configOf({ ...testProfile, approvalPolicy: 'deny' }));
      // A grant under the new generation, as another call's approval would leave: the
      // evaluation in hand still says require-approval, so the grant would be reused.
      h.pipeline.grants.record(testProfile.name, COMMAND, 'destructive');
    });

    await expect(h.run()).rejects.toThrow(/^CONFIG_RELOADED: /);

    expect(approve).not.toHaveBeenCalled();
    expect(h.exec).not.toHaveBeenCalled();
    expect(h.records[0]).toMatchObject({ decision: 'deny', ruleId: 'config-reloaded' });
  });

  it('proceeds on a grant reuse when the new rules allow the command outright', async () => {
    const policy = new PolicyEngine(DEFAULT_RULES);
    const h = setup(testProfile, policy);
    reloadDuringEvaluation(policy, () => {
      h.registry.applyConfig(configOf({ ...testProfile, approvalPolicy: 'auto' }));
      h.pipeline.grants.record(testProfile.name, COMMAND, 'destructive');
    });

    await h.run();

    expect(approve).not.toHaveBeenCalled();
    expect(h.exec).toHaveBeenCalledTimes(1);
    expect(h.records[0]).toMatchObject({ decision: 'allow', commandClass: 'destructive' });
  });

  // The quota limit is read from the live profile, after every await: a reload that
  // lowered it while the decision was being made applies to this very call.
  it('charges the quota against the profile as the reload left it', async () => {
    const policy = new PolicyEngine(DEFAULT_RULES);
    const h = setup({ ...testProfile, commandQuotaPerDay: 5 }, policy);
    await runRead(h);
    expect(h.exec).toHaveBeenCalledTimes(1);

    reloadDuringEvaluation(policy, () => {
      h.registry.applyConfig(configOf({ ...testProfile, commandQuotaPerDay: 1 }));
    });

    await expect(runRead(h)).rejects.toThrow(/^QUOTA_EXCEEDED: /);
    expect(h.exec).toHaveBeenCalledTimes(1);
  });
});
