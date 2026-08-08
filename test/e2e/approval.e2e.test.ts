import { describe, it, expect, afterEach } from 'vitest';
import { startE2E, e2eAvailable, textOf } from './harness.js';

// The approval gate is the mechanism that makes destructive commands safe, and
// it depends on the *client* answering an elicitation request. Only an
// end-to-end run proves the prompt actually crosses the transport and that the
// answer decides whether the command runs.
let e2e: Awaited<ReturnType<typeof startE2E>>;
const available = await e2eAvailable();

afterEach(async () => { await e2e?.cleanup(); });

describe.skipIf(!available)('E2E — approval gate', () => {
  it('prompts the client and runs the command when approved', async () => {
    e2e = await startE2E();
    e2e.setApproval(true);

    const marker = '/tmp/e2e-approved.txt';
    await e2e.callTool('run-command', { command: `touch ${marker}` });
    const res = await e2e.callTool('run-command', { command: `rm -rf ${marker}` });

    expect(res.isError).toBeFalsy();
    expect(e2e.prompts.length).toBeGreaterThan(0);
    // The prompt has to carry the actual command — a human cannot approve what
    // they cannot see.
    expect(e2e.prompts.at(-1)).toContain(`rm -rf ${marker}`);
    expect(e2e.prompts.at(-1)).toContain('destructive');

    const gone = await e2e.callTool('run-command', { command: `sh -c "test -e ${marker} || echo gone"` });
    expect(textOf(gone)).toContain('gone');
  }, 40000);

  it('refuses the command when the client declines, and it never reaches the host', async () => {
    e2e = await startE2E();

    const marker = '/tmp/e2e-declined.txt';
    e2e.setApproval(true);
    await e2e.callTool('run-command', { command: `touch ${marker}` });

    e2e.setApproval(false);
    const res = await e2e.callTool('run-command', { command: `rm -rf ${marker}` });
    expect(res.isError).toBe(true);

    // The decisive assertion: the file is still there.
    e2e.setApproval(true);
    const still = await e2e.callTool('run-command', { command: `sh -c "test -e ${marker} && echo present"` });
    expect(textOf(still)).toContain('present');

    await e2e.callTool('run-command', { command: `rm -f ${marker}` });
  }, 40000);

  it('never prompts for a forbidden command — it is denied outright', async () => {
    e2e = await startE2E();
    e2e.setApproval(true);

    const res = await e2e.callTool('run-command', { command: 'rm -rf /' });
    expect(res.isError).toBe(true);
    expect(e2e.prompts).toHaveLength(0);
  }, 40000);

  it('ask-all from [defaults] makes even a read-only command prompt', async () => {
    // Proves the [defaults] cascade reaches a real profile through real config
    // loading — the class of bug where a documented key was validated and then
    // silently ignored.
    e2e = await startE2E({ defaults: 'approvalMode = "ask-all"' });
    e2e.setApproval(true);

    const res = await e2e.callTool('read-command', { command: 'whoami' });
    expect(res.isError).toBeFalsy();
    expect(e2e.prompts.length).toBe(1);
    expect(e2e.prompts[0]).toContain('whoami');
  }, 40000);

  it('deny from [defaults] rejects destructive commands without prompting', async () => {
    e2e = await startE2E({ defaults: 'approvalMode = "deny"' });
    e2e.setApproval(true);

    const res = await e2e.callTool('run-command', { command: 'rm -rf /tmp/e2e-deny-test' });
    expect(res.isError).toBe(true);
    expect(e2e.prompts).toHaveLength(0);
  }, 40000);

  it('a just-in-time grant covers a repeat of the same command', async () => {
    e2e = await startE2E({ defaults: 'approvalGrantTtlMs = 60000' });
    e2e.setApproval(true);

    const cmd = 'rm -rf /tmp/e2e-grant-test';
    await e2e.callTool('run-command', { command: cmd });
    await e2e.callTool('run-command', { command: cmd });
    await e2e.callTool('run-command', { command: cmd });

    expect(e2e.prompts).toHaveLength(1);
  }, 40000);

  it('the daily quota stops further commands', async () => {
    e2e = await startE2E({ defaults: 'commandQuotaPerDay = 2' });

    expect((await e2e.callTool('read-command', { command: 'whoami' })).isError).toBeFalsy();
    expect((await e2e.callTool('read-command', { command: 'pwd' })).isError).toBeFalsy();

    const blocked = await e2e.callTool('read-command', { command: 'hostname' });
    expect(blocked.isError).toBe(true);
    expect(textOf(blocked)).toContain('QUOTA_EXCEEDED');
  }, 40000);
});
