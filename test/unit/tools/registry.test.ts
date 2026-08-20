import { describe, it, expect, afterEach } from 'vitest';
import { createHarness, textOf, type Harness } from './harness.js';

let h: Harness;

afterEach(async () => { await h?.close(); });

async function call(name: string, args: Record<string, unknown> = {}) {
  return h.client.callTool({ name, arguments: args }) as Promise<any>;
}

describe('MCP tool surface', () => {
  it('exposes exactly the documented tools', async () => {
    h = await createHarness();
    const { tools } = await h.client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'close-session', 'list-connections', 'list-sessions', 'open-session',
      'privileged-command', 'read-command', 'read-session-output',
      'run-command', 'sftp-download', 'sftp-upload', 'signal-process',
    ]);
  });

  it('does not mark any mutating tool readOnly', async () => {
    h = await createHarness();
    const { tools } = await h.client.listTools();
    const readOnly = tools.filter((t) => t.annotations?.readOnlyHint).map((t) => t.name).sort();
    // A mutating tool advertised as read-only invites auto-approval by clients.
    expect(readOnly).toEqual(['list-connections', 'list-sessions', 'read-command', 'read-session-output', 'sftp-download']);
  });
});

describe('read-command — enforceClass', () => {
  it('runs an allowlisted read-only command', async () => {
    h = await createHarness();
    const res = await call('read-command', { command: 'ls -la' });
    expect(res.isError).toBeFalsy();
    expect(h.execCalls.map((c) => c.command)).toContain('ls -la');
  });

  // The security property of this tool: it is advertised to the model as not
  // modifying the system, so anything not classified read-only must be refused
  // even when the profile's role would allow it via run-command.
  it('refuses a destructive command', async () => {
    h = await createHarness();
    const res = await call('read-command', { command: 'rm -rf /tmp/x' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('refuses a merely "safe" command', async () => {
    h = await createHarness();
    const res = await call('read-command', { command: 'npm install' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('refuses curl, which is not read-only', async () => {
    h = await createHarness();
    const res = await call('read-command', { command: 'curl http://169.254.169.254/latest/meta-data/' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('run-command — approval gate', () => {
  it('executes a destructive command once the client approves', async () => {
    h = await createHarness();
    h.setApproval(true);
    const res = await call('run-command', { command: 'rm -rf /tmp/build' });
    expect(res.isError).toBeFalsy();
    expect(h.execCalls.map((c) => c.command)).toContain('rm -rf /tmp/build');
  });

  it('blocks a destructive command when the client declines', async () => {
    h = await createHarness();
    h.setApproval(false);
    const res = await call('run-command', { command: 'rm -rf /tmp/build' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('denies a forbidden command outright, with no prompt', async () => {
    h = await createHarness();
    h.setApproval(true);
    const res = await call('run-command', { command: 'rm -rf /' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('runs a safe command without prompting', async () => {
    h = await createHarness();
    h.setApproval(false);
    const res = await call('run-command', { command: 'npm install' });
    expect(res.isError).toBeFalsy();
  });
});

describe('privileged-command', () => {
  it('pipes the sudo password over stdin, never in the command line', async () => {
    h = await createHarness();
    const res = await call('privileged-command', { command: 'systemctl restart nginx' });
    expect(res.isError).toBeFalsy();
    const exec = h.execCalls.at(-1)!;
    expect(exec.command).not.toContain('sudo-secret');
    expect(exec.stdin).toBe('sudo-secret\n');
  });

  it('single-quotes the wrapped command so it cannot break out', async () => {
    h = await createHarness();
    await call('privileged-command', { command: "echo 'hi'; id" });
    const exec = h.execCalls.at(-1)!;
    expect(exec.command).toMatch(/^sudo -p "" -S sh -c '/);
    expect(exec.command).toContain("'\\''");
  });

  // The denylist is evaluated against the bare command as well: without that,
  // the sudo wrapper would hide a forbidden command inside a quoted sh -c arg.
  it('denies a forbidden command hidden inside the sudo wrapper', async () => {
    h = await createHarness();
    const res = await call('privileged-command', { command: 'rm -rf /' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('command results carry exit status', () => {
  it('reports a non-zero exit as an error with the code and stderr', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: '', stderr: 'Unit not found', exitCode: 4 });
    const res = await call('run-command', { command: 'systemctl restart nope' });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('Unit not found');
    expect(textOf(res)).toContain('[exit 4]');
  });

  it('does not flag a successful command that wrote to stderr', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: 'done', stderr: 'warning: deprecated', exitCode: 0 });
    const res = await call('run-command', { command: 'npm install' });
    expect(res.isError).toBeFalsy();
    expect(textOf(res)).toContain('done');
  });

  it('reports a signal kill as an error', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: '', stderr: '', exitCode: 0, signal: 'KILL' });
    const res = await call('run-command', { command: 'sleep 100' });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('SIGKILL');
  });

  it('signal-process does not claim success when kill failed', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: '', stderr: 'No such process', exitCode: 1 });
    const res = await call('signal-process', { pid: 4242, signal: 'TERM' });
    expect(res.isError).toBe(true);
    expect(textOf(res)).not.toContain('sent to PID');
  });
});

describe('output redaction', () => {
  it('redacts secrets in command output before the model sees them', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY', exitCode: 0 });
    const res = await call('read-command', { command: 'env' });
    expect(textOf(res)).not.toContain('wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY');
  });
});

describe('audit records', () => {
  it('records an allowed command as allowed', async () => {
    h = await createHarness();
    await call('read-command', { command: 'ls -la' });
    expect(h.auditRecords.at(-1)).toMatchObject({ command: 'ls -la', decision: 'allow', exitCode: 0 });
  });

  it('records a policy denial as denied', async () => {
    h = await createHarness();
    await call('run-command', { command: 'rm -rf /' });
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  // Regression: a command that was allowed, approved and executed but then
  // failed used to be written to the audit log as decision 'deny' — telling an
  // auditor the command was blocked when it had actually run on the host.
  it('records an executed-but-failed command with its real decision', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: '', stderr: 'boom', exitCode: 7 });
    await call('run-command', { command: 'npm install' });
    const record = h.auditRecords.at(-1);
    expect(record.decision).toBe('allow');
    expect(record.exitCode).toBe(7);
  });

  // Regression: sanitizeCommand ran outside the try, so a rejected payload left
  // no trace at all — a client could probe with malformed input unaudited.
  it('records an input rejected by the sanitizer', async () => {
    h = await createHarness({ maxChars: 10 });
    const res = await call('run-command', { command: 'x'.repeat(50) });
    expect(res.isError).toBe(true);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'input-rejected' });
  });

  it('records a declined approval', async () => {
    h = await createHarness();
    h.setApproval(false);
    await call('run-command', { command: 'rm -rf /tmp/build' });
    const record = h.auditRecords.at(-1);
    expect(record.decision).toBe('require-approval');
    expect(record.error).toMatch(/APPROVAL_DENIED/);
  });
});

describe('just-in-time approval grants', () => {
  // Approving the same destructive command every few seconds trains the
  // operator to click through prompts, which is worse than a bounded grant.
  it('skips the prompt for an identical command within the grant window', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    h.setApproval(true);

    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });

    expect(h.approvalPrompts()).toBe(1);
    expect(h.execCalls).toHaveLength(3);
  });

  // Bound to the exact command: a grant must not widen to a similar one.
  it('still prompts for a different command', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    h.setApproval(true);

    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build-prod' });

    expect(h.approvalPrompts()).toBe(2);
  });

  it('records the grant as the approver in the audit log', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    h.setApproval(true);
    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });

    // The second run is attributable to the grant, not to a fresh human answer.
    expect(h.auditRecords.at(-2).approver).toBe('mcp-client');
    expect(h.auditRecords.at(-1).approver).toBe('jit-grant');
  });

  // Off by default: auto-approval weakens the gate that makes destructive
  // commands safe, so it must be an explicit decision.
  it('is disabled by default — every destructive command prompts', async () => {
    h = await createHarness();
    h.setApproval(true);
    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });
    expect(h.approvalPrompts()).toBe(2);
  });

  it('does not grant anything when the client declines', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    h.setApproval(false);
    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });
    expect(h.approvalPrompts()).toBe(2);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('command quota', () => {
  // The approval gate stops destructive commands and the HTTP limiter caps
  // request rate, but neither bounds total work: an agent looping over allowed
  // commands stays under both. The quota is the circuit breaker for that.
  it('refuses further commands once the daily quota is spent', async () => {
    h = await createHarness({ commandQuotaPerDay: 3 });

    for (let i = 0; i < 3; i++) {
      const ok = await call('read-command', { command: `ls dir-${i}` });
      expect(ok.isError).toBeFalsy();
    }

    const blocked = await call('read-command', { command: 'ls again' });
    expect(blocked.isError).toBe(true);
    expect(textOf(blocked)).toMatch(/QUOTA_EXCEEDED/);
    // The refused command must not reach the host.
    expect(h.execCalls).toHaveLength(3);
  });

  it('audits a quota refusal with its own rule id', async () => {
    h = await createHarness({ commandQuotaPerDay: 1 });
    await call('read-command', { command: 'ls' });
    await call('read-command', { command: 'ls' });

    const record = h.auditRecords.at(-1);
    expect(record.decision).toBe('deny');
    expect(record.ruleId).toBe('command-quota');
  });

  it('does not count commands the policy already refused', async () => {
    h = await createHarness({ commandQuotaPerDay: 2 });
    // Denied by the forbidden list — should not spend budget.
    await call('run-command', { command: 'rm -rf /' });
    await call('run-command', { command: 'rm -rf /' });

    const ok = await call('read-command', { command: 'ls' });
    expect(ok.isError).toBeFalsy();
  });

  it('is unlimited when the quota is zero', async () => {
    h = await createHarness({ commandQuotaPerDay: 0 });
    for (let i = 0; i < 12; i++) {
      const res = await call('read-command', { command: `ls ${i}` });
      expect(res.isError).toBeFalsy();
    }
  });
});

describe('sessions', () => {
  it('opens, lists and closes a session, auditing the open', async () => {
    h = await createHarness();
    const opened = await call('open-session', { name: 'work', type: 'interactive' });
    expect(opened.isError).toBeFalsy();
    // Opening a stateful shell is a security-relevant event and must be audited.
    expect(h.auditRecords.at(-1).command).toContain('session:open');

    const listed = await call('list-sessions', {});
    expect(textOf(listed)).toContain('work');

    const closed = await call('close-session', { name: 'work' });
    expect(closed.isError).toBeFalsy();
    // And the close, too. Closing a *background* session signals its command on the host —
    // INT, then TERM, then KILL — and this tool used to reach the connection directly,
    // around the pipeline, so a caller-invoked SIGKILL on a production host produced no
    // audit row at all. Every other path to a remote signal is audited.
    expect(h.auditRecords.at(-1).command).toContain('session:close');
  });

  it('audits closing a background session as destructive', async () => {
    h = await createHarness();
    await call('open-session', { name: 'logs', type: 'background', command: 'tail -f /var/log/syslog' });
    const closed = await call('close-session', { name: 'logs' });
    expect(closed.isError).toBeFalsy();
    const record = h.auditRecords.at(-1);
    expect(record.command).toContain('session:close');
    expect(record.decision).toBe('allow');
  });

  it('rejects a session name with shell metacharacters', async () => {
    h = await createHarness();
    const res = await call('open-session', { name: 'a; rm -rf /', type: 'interactive' });
    expect(res.isError).toBe(true);
  });

  it('redacts secrets in background session output', async () => {
    h = await createHarness();
    await call('open-session', { name: 'logs', type: 'background', command: 'tail -f /var/log/syslog' });
    const res = await call('read-session-output', { name: 'logs', lines: 5 });
    expect(res.isError).toBeFalsy();
  });
});

describe('resources', () => {
  it('lists the documented resources', async () => {
    h = await createHarness();
    const { resources } = await h.client.listResources();
    expect(resources.map((r) => r.uri)).toContain('ssh://connections');
  });

  it('returns connection data as JSON', async () => {
    h = await createHarness();
    const res = await h.client.readResource({ uri: 'ssh://connections' });
    const body = JSON.parse((res.contents[0] as any).text);
    expect(JSON.stringify(body)).toContain('dev');
  });
});
