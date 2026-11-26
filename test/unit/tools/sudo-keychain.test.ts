import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { requestApproval } from '../../../src/guard/elicitation.js';
import { resolveSudoKeychainPassword } from '../../../src/config/credential-resolver.js';
import { createPipeline } from '../../../src/tools/pipeline.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { configWithDefaults, plant } from '../../helpers/registry.js';
import { createHarness, testProfile, textOf, type Harness } from './harness.js';
import type { Profile } from '../../../src/types.js';

vi.mock('../../../src/guard/elicitation.js', () => ({ requestApproval: vi.fn() }));
vi.mock('../../../src/config/credential-resolver.js', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/config/credential-resolver.js')>(),
  resolveSudoKeychainPassword: vi.fn(),
}));

const approve = vi.mocked(requestApproval);
const lookup = vi.mocked(resolveSudoKeychainPassword);
const password = 'dummy password';
const profile: Profile = {
  ...testProfile, approvalPolicy: 'ask-all', sudoKeychainEntry: 'ssh-mcp/test-sudo', tty: true,
};
let h: Harness | undefined;

beforeEach(() => {
  approve.mockReset();
  approve.mockResolvedValue({ approved: true, approver: 'mcp-client' });
  lookup.mockReset();
  lookup.mockResolvedValue(password);
});
afterEach(async () => { await h?.close(); h = undefined; vi.restoreAllMocks(); });

function setup(overrides: Partial<Profile> = {}) {
  const current = { ...profile, ...overrides };
  const config = (p: Profile) => configWithDefaults({ approvalGrantTtlMs: 0 }, p);
  const registry = new ConnectionRegistry(config(current));
  const conn = plant(registry, current);
  vi.spyOn(conn, 'isConnected').mockReturnValue(true);
  const legacy = vi.spyOn(conn, 'getSudoPassword').mockReturnValue('legacy-secret');
  const notifications: any[] = [];
  const records: any[] = [];
  const exec = vi.spyOn(conn, 'exec').mockImplementation(async (_command, opts) => {
    opts?.onProgress?.(10, password.slice(0, 5));
    opts?.onProgress?.(20, password);
    return { stdout: password, stderr: password, exitCode: 0, durationMs: 1, profile: current.name };
  });
  const pipeline = createPipeline({
    server: {} as any, registry, policy: new PolicyEngine(DEFAULT_RULES),
    audit: { record: async (r: any) => { records.push(r); } } as any,
  });
  const run = (signal?: AbortSignal, sudo = true) => pipeline.runAudited(
    sudo ? `sudo${current.sudoKeychainEntry !== undefined ? ' -k' : ''} -p "" -S sh -c 'exec 0</dev/null; id -u'` : 'hostname',
    { toolName: sudo ? 'privileged-command' : 'run-command', failureClass: sudo ? 'privileged' : 'safe', profile: current.name,
      extra: { signal, _meta: { progressToken: 'test' }, sendNotification: async (n: any) => { notifications.push(n); } } },
    pipeline.execAndReport({ sudo }),
  );
  return { registry, conn, config, current, legacy, exec, notifications, records, run };
}

describe('just-in-time sudo keychain execution', () => {
  it('looks up only after approval and wires the registered privileged tool to stdin', async () => {
    h = await createHarness(profile);
    lookup.mockImplementation(async () => {
      expect(approve).toHaveBeenCalledTimes(1);
      expect(h!.execCalls).toHaveLength(0);
      return password;
    });
    const result = await h.client.callTool({ name: 'privileged-command', arguments: { command: 'id -u' } });
    expect(result.isError).toBeFalsy();
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(h.execCalls[0]).toEqual({ command: `sudo -k -p "" -S sh -c 'exec 0</dev/null; id -u'`, stdin: password + '\n' });
    expect(JSON.stringify(h.auditRecords)).not.toContain(password);
  });

  it('does not look up or execute after a declined approval', async () => {
    const { run, exec } = setup();
    approve.mockResolvedValue({ approved: false });
    await expect(run()).rejects.toThrow(/APPROVAL/);
    expect(lookup).not.toHaveBeenCalled();
    expect(exec).not.toHaveBeenCalled();
  });

  it('does not look up credentials for a policy denial or an ordinary command', async () => {
    const denied = setup({ readOnly: true });
    await expect(denied.run()).rejects.toThrow(/POLICY_DENIED/);
    expect(lookup).not.toHaveBeenCalled();
    expect(denied.exec).not.toHaveBeenCalled();
    const normal = setup();
    await normal.run(undefined, false);
    expect(lookup).not.toHaveBeenCalled();
    expect(normal.exec.mock.calls[0]?.[1]?.stdin).toBeUndefined();
  });

  it('retrieves on each approved invocation without legacy fallback', async () => {
    const { run, exec, legacy } = setup();
    lookup.mockResolvedValueOnce('first-password').mockResolvedValueOnce('second-password');
    await run();
    await run();
    expect(approve).toHaveBeenCalledTimes(2);
    expect(lookup).toHaveBeenCalledTimes(2);
    expect(legacy).not.toHaveBeenCalled();
    expect(exec.mock.calls.map(([, opts]) => opts?.stdin)).toEqual(['first-password\n', 'second-password\n']);
  });

  it('fails closed if lookup fails or returns no credential', async () => {
    const { run, exec, legacy } = setup();
    lookup.mockRejectedValueOnce(new Error('Sudo keychain lookup failed.')).mockResolvedValueOnce(undefined);
    await expect(run()).rejects.toThrow(/keychain/);
    await expect(run()).rejects.toThrow(/keychain/);
    expect(exec).not.toHaveBeenCalled();
    expect(legacy).not.toHaveBeenCalled();
  });

  it('refuses a command if config changes while the lookup is pending', async () => {
    const { run, exec, registry, config, current } = setup();
    lookup.mockImplementation(async () => {
      registry.applyConfig(config({ ...current, approvalPolicy: 'deny' }));
      return password;
    });
    await expect(run()).rejects.toThrow(/Configuration changed/);
    expect(exec).not.toHaveBeenCalled();
  });

  it('refuses a command cancelled during credential lookup', async () => {
    const { run, exec } = setup();
    const controller = new AbortController();
    lookup.mockImplementation(async () => { controller.abort(); return password; });
    await expect(run(controller.signal)).rejects.toThrow(/cancelled/);
    expect(exec).not.toHaveBeenCalled();
  });

  it('isolates stdin, disables PTY and sends no raw preview text', async () => {
    const { run, exec, notifications, records } = setup();
    const result = await run();
    expect(exec.mock.calls[0]?.[1]).toMatchObject({ stdin: password + '\n', tty: false, suppressTruncatedOutput: true });
    expect(textOf(result)).not.toContain(password);
    expect(textOf(result)).toContain('[REDACTED:secret:14]');
    expect(notifications).toHaveLength(2);
    expect(notifications.map(n => n.params.progress)).toEqual([10, 20]);
    expect(notifications.every(n => n.params.message === 'Privileged command output withheld until completion.')).toBe(true);
    expect(JSON.stringify(records)).not.toContain(password);
  });

  it('redacts short keychain credentials from both output streams', async () => {
    const { run, exec } = setup();
    lookup.mockResolvedValue('xyz');
    exec.mockResolvedValue({ stdout: 'xyz', stderr: 'xyz', exitCode: 1, durationMs: 1, profile: profile.name });
    const result = await run();
    expect(result.isError).toBe(true);
    expect(textOf(result)).not.toContain('xyz');
    expect(textOf(result)).toContain('[REDACTED:secret:3]');
  });

  it('does not expose an execution exception containing the credential', async () => {
    const { run, exec, records } = setup();
    exec.mockRejectedValue(new Error('SSH backend: ' + password));
    await expect(run()).rejects.toThrow(/verify remote state/);
    expect(JSON.stringify(records)).not.toContain(password);
    expect(records.at(-1)?.approver).toBe('mcp-client');
  });
});
