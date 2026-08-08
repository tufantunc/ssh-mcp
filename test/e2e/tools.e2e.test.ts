import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startE2E, e2eAvailable, textOf } from './harness.js';

// §5 of the readiness report: exercise all 11 tools through a real MCP client
// over a real transport against a real SSH server. This is the check that would
// have caught open-session being registered without a handler — the in-process
// harness found it, but only because it too went through the MCP layer.
let e2e: Awaited<ReturnType<typeof startE2E>>;
const available = await e2eAvailable();

beforeAll(async () => {
  if (!available) return;
  e2e = await startE2E();
}, 30000);

afterAll(async () => { await e2e?.cleanup(); });

describe.skipIf(!available)('E2E — tool surface over stdio', () => {
  it('advertises all 11 tools to a real client', async () => {
    const { tools } = await e2e.client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'close-session', 'list-connections', 'list-sessions', 'open-session',
      'privileged-command', 'read-command', 'read-session-output',
      'run-command', 'sftp-download', 'sftp-upload', 'signal-process',
    ]);
  });

  it('list-connections reports the configured profiles', async () => {
    const res = await e2e.callTool('list-connections');
    expect(textOf(res)).toContain('admin');
    expect(textOf(res)).toContain('viewer');
  });

  it('read-command returns real output from the host', async () => {
    const res = await e2e.callTool('read-command', { command: 'whoami' });
    expect(res.isError).toBeFalsy();
    expect(textOf(res).trim()).toBe('admin');
  });

  it('read-command refuses curl — not read-only despite the allowlist shape', async () => {
    const res = await e2e.callTool('read-command', { command: 'curl http://169.254.169.254/' });
    expect(res.isError).toBe(true);
  });

  it('run-command reports a non-zero exit as an error with the code', async () => {
    const res = await e2e.callTool('run-command', { command: 'sh -c "echo to-stderr >&2; exit 7"' });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('to-stderr');
    expect(textOf(res)).toContain('[exit 7]');
  });

  it('privileged-command elevates without the password reaching the output', async () => {
    const res = await e2e.callTool('privileged-command', { command: 'id -u' });
    expect(res.isError).toBeFalsy();
    // uid 0 — the command really ran as root.
    expect(textOf(res)).toContain('0');
    // The sudo password must never appear in what the model sees. (Note: sudo's
    // first-use lecture does arrive on stderr and is surfaced as [stderr],
    // which is the intended behaviour — stderr is not swallowed.)
    expect(textOf(res)).not.toContain('secret');
  });

  it('interactive sessions keep CWD and environment between commands', async () => {
    const opened = await e2e.callTool('open-session', { name: 'e2e-shell', type: 'interactive' });
    expect(opened.isError).toBeFalsy();

    await e2e.callTool('run-command', { session: 'e2e-shell', command: 'cd /tmp' });
    await e2e.callTool('run-command', { session: 'e2e-shell', command: 'export E2E_VAR=persisted' });

    const pwd = await e2e.callTool('run-command', { session: 'e2e-shell', command: 'pwd' });
    expect(textOf(pwd).trim()).toBe('/tmp');

    const env = await e2e.callTool('run-command', { session: 'e2e-shell', command: 'echo $E2E_VAR' });
    expect(textOf(env).trim()).toBe('persisted');

    const listed = await e2e.callTool('list-sessions');
    expect(textOf(listed)).toContain('e2e-shell');

    const closed = await e2e.callTool('close-session', { name: 'e2e-shell' });
    expect(closed.isError).toBeFalsy();
  }, 30000);

  it('background sessions stream output that read-session-output can poll', async () => {
    await e2e.callTool('run-command', { command: 'echo first-line > /tmp/e2e-bg.log' });
    await e2e.callTool('open-session', {
      name: 'e2e-bg', type: 'background', command: 'tail -f /tmp/e2e-bg.log',
    });

    await new Promise((r) => setTimeout(r, 800));
    const out = await e2e.callTool('read-session-output', { name: 'e2e-bg', lines: 10 });
    expect(textOf(out)).toContain('first-line');

    await e2e.callTool('close-session', { name: 'e2e-bg' });
  }, 30000);

  it('sftp-upload and sftp-download round-trip a file', async () => {
    const remotePath = '/tmp/e2e-transfer.txt';
    const content = 'round-trip through SFTP';

    const up = await e2e.callTool('sftp-upload', { remotePath, content });
    expect(up.isError).toBeFalsy();

    const down = await e2e.callTool('sftp-download', { remotePath });
    expect(textOf(down)).toContain(content);

    await e2e.callTool('run-command', { command: `rm -f ${remotePath}` });
  }, 30000);

  it('signal-process kills a real remote process', async () => {
    // The process reports its own PID before exec'ing sleep, so the test does
    // not have to pattern-match a process list — `pgrep -f "sleep 120"` also
    // matches the shell running the pgrep, which made this flaky and wrong.
    await e2e.callTool('open-session', {
      name: 'e2e-victim',
      type: 'background',
      command: 'sh -c \'echo PID=$$; exec sleep 120\'',
    });
    await new Promise((r) => setTimeout(r, 800));

    const out = await e2e.callTool('read-session-output', { name: 'e2e-victim', lines: 5 });
    const pid = parseInt(textOf(out).match(/PID=(\d+)/)?.[1] ?? '');
    expect(pid).toBeGreaterThan(0);

    const alive = await e2e.callTool('run-command', { command: `sh -c "kill -0 ${pid} && echo alive"` });
    expect(textOf(alive)).toContain('alive');

    const killed = await e2e.callTool('signal-process', { pid, signal: 'TERM' });
    expect(killed.isError).toBeFalsy();

    await new Promise((r) => setTimeout(r, 500));
    const gone = await e2e.callTool('run-command', { command: `sh -c "kill -0 ${pid} 2>/dev/null || echo gone"` });
    expect(textOf(gone)).toContain('gone');

    await e2e.callTool('close-session', { name: 'e2e-victim' }).catch(() => {});
  }, 30000);

  it('serves the connection resource', async () => {
    const { resources } = await e2e.client.listResources();
    expect(resources.map((r) => r.uri)).toContain('ssh://connections');

    const read = await e2e.client.readResource({ uri: 'ssh://connections' });
    const body = JSON.parse((read.contents[0] as any).text);
    expect(JSON.stringify(body)).toContain('admin');
  });

  it('enforces the readOnly profile through a real connection', async () => {
    const res = await e2e.callTool('run-command', { profile: 'viewer', command: 'npm install' });
    expect(res.isError).toBe(true);
  }, 30000);
});
