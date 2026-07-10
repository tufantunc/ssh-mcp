import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { EventEmitter } from 'node:events';
import { spawn } from 'node:child_process';
import { OpenSshTransport } from '../src/transports/openssh';

// These tests drive the private runSuViaPty PTY state machine with a mocked
// `spawn`, so they need no live sshd. They cover:
//   - finding 3: large EXEC output must not be truncated to the ~4KB scan window
//   - finding 4: the overall hard deadline must equal opts.timeoutMs (no +30000)

vi.mock('node:child_process', () => ({
  spawn: vi.fn(),
  execFile: vi.fn(),
}));

const spawnMock = spawn as unknown as Mock;

class FakeChild extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  writes: string[] = [];
  killed = false;
  stdin = {
    write: (s: string) => {
      this.writes.push(s);
      return true;
    },
  };
  kill = vi.fn((_sig?: string) => {
    this.killed = true;
    return true;
  });
}

function emit(fc: FakeChild, s: string) {
  fc.stdout.emit('data', Buffer.from(s, 'utf8'));
}

/** Parse the random nonce out of the `export PS1='__SSH_MCP_READY_<nonce>...'` line. */
function nonceFromWrites(fc: FakeChild): string {
  const line = fc.writes.find((w) => w.includes('export PS1='));
  if (!line) throw new Error('PS1 export not written: ' + JSON.stringify(fc.writes));
  const m = line.match(/__SSH_MCP_READY_([0-9a-f]+)__/);
  if (!m) throw new Error('no nonce in PS1 line: ' + line);
  return m[1];
}

/** Drive the state machine SU_PROMPT -> PASSWORD_SENT -> ROOT_SHELL -> EXEC. */
function driveToExec(fc: FakeChild): { readyMark: string; endMark: string } {
  emit(fc, 'Password: ');           // SU_PROMPT -> PASSWORD_SENT
  emit(fc, '\nLast login: today\n'); // PASSWORD_SENT -> ROOT_SHELL (writes PS1 export)
  const nonce = nonceFromWrites(fc);
  const readyMark = `__SSH_MCP_READY_${nonce}__`;
  const endMark = `__SSH_MCP_END_${nonce}__`;
  emit(fc, readyMark + '$ ');       // ROOT_SHELL -> EXEC (writes command + echo endMark)
  return { readyMark, endMark };
}

beforeEach(() => {
  spawnMock.mockReset();
});

describe('runSuViaPty large output (finding 3: no ~4KB truncation)', () => {
  it('preserves the full head of command output exceeding the scan window', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });

    const p = (t as any).runSuViaPty('big', 'pw', { timeoutMs: 60000 }) as Promise<any>;

    const { endMark } = driveToExec(fc);

    const big = 'A'.repeat(20000); // >> the 8KB/4KB scan-buffer cap
    emit(fc, big);
    emit(fc, `\n${endMark}0\n`);
    fc.emit('close', 0, null);

    const res = await p;
    expect(res.exitCode).toBe(0);
    // Old code derived stdout from the truncated ~4KB scan buffer and would lose
    // the head. The fix keeps an unbounded EXEC capture, so all 20000 bytes survive.
    expect(res.stdout.length).toBeGreaterThanOrEqual(20000);
    expect(res.stdout.startsWith(big)).toBe(true);
  });
});

describe('OpenSSH command sentinels', () => {
  it('puts the su closing subshell and sentinel after a command comment', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });
    const p = (t as any).runSuViaPty('echo ok # described command', 'pw', { timeoutMs: 60000 });

    const { endMark } = driveToExec(fc);
    const execInput = fc.writes.at(-1)!;
    expect(execInput).toContain('echo ok # described command\n)\necho ' + endMark);
    emit(fc, execInput.replace(/\n$/, '') + '\n' + 'ok\n' + endMark + '0\n');
    fc.emit('close', 0, null);

    await expect(p).resolves.toMatchObject({ exitCode: 0, stdout: 'ok\n' });
  });

  it('uses the remote sentinel to classify a command exit 255 as remote_exit', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u' });
    const p = (t as any).runSsh("echo Permission denied >&2; exit 255", { timeoutMs: 60000 });

    const command = spawnMock.mock.calls[0][1].at(-1) as string;
    const endMark = command.match(/(__SSH_MCP_END_[0-9a-f]+__)/)![1];
    fc.stderr.emit('data', Buffer.from('Permission denied\n'));
    emit(fc, `\n${endMark}255\n`);
    fc.emit('close', 0, null);

    await expect(p).resolves.toMatchObject({
      exitCode: 255,
      category: 'remote_exit',
      stderr: 'Permission denied\n',
    });
  });
});

describe('runSuViaPty overall deadline (finding 4: timeoutMs is the hard ceiling)', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('kills the process at exactly opts.timeoutMs (not timeoutMs + 30000)', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });

    const p = (t as any).runSuViaPty('sleep 999', 'pw', { timeoutMs: 5000 }) as Promise<any>;

    // Advance to exactly the contract deadline. Under the old +30000 budget the
    // overall timer would not have fired yet (and the 10s state timer is also
    // still pending), so the process would NOT be killed at 5000ms.
    vi.advanceTimersByTime(5000);
    expect(fc.kill).toHaveBeenCalledWith('SIGTERM');

    // Process exits in response to the signal; resolve as a timeout.
    fc.emit('close', null, 'SIGTERM');
    const res = await p;
    expect(res.category).toBe('timeout');
  });

  it('escalates to SIGKILL when the process ignores SIGTERM past the grace window (P2: track real exit, not child.killed)', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });

    (t as any).runSuViaPty('sleep 999', 'pw', { timeoutMs: 5000 });

    // Hit the overall deadline → SIGTERM sent.
    vi.advanceTimersByTime(5000);
    expect(fc.kill).toHaveBeenCalledWith('SIGTERM');
    // The process does NOT exit (no close event). The old code gated the
    // fallback on `child.killed`, which FakeChild.kill sets true, so SIGKILL
    // was wrongly skipped. The fix gates on a real `exited` flag.
    vi.advanceTimersByTime(2000);
    expect(fc.kill).toHaveBeenCalledWith('SIGKILL');
  });
});

describe('runSuViaPty echo stripping (finding 1: strip echoed PTY input from su results)', () => {
  it('removes the echoed combined command+sentinel input line from captured stdout', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });

    const p = (t as any).runSuViaPty('id -un', 'pw', { timeoutMs: 60000 }) as Promise<any>;

    const { endMark } = driveToExec(fc);

    // `ssh -tt` echoes the multiline input written to the root shell.
    const execInput = fc.writes.find((w) => w.includes(endMark) && w.includes('id -un'))!;
    emit(fc, execInput.replace(/\n$/, '') + '\r\n');
    emit(fc, 'root\n');
    emit(fc, `${endMark}0\n`);
    fc.emit('close', 0, null);

    const res = await p;
    expect(res.exitCode).toBe(0);
    // Only the real command output should remain — no echoed input.
    expect(res.stdout.trim()).toBe('root');
    expect(res.stdout).not.toContain('id -un');
    expect(res.stdout).not.toContain(`echo ${endMark}`);
  });

  it('wraps the user command in a subshell so its own exit does not kill the sentinel (P2)', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });

    const p = (t as any).runSuViaPty('echo ok; exit 0', 'pw', { timeoutMs: 60000 }) as Promise<any>;

    const { endMark } = driveToExec(fc);

    // The EXEC input written to the root shell must run the command in a
    // subshell `( ... )` so a command that exits/exec-replaces its shell only
    // terminates the subshell; the control shell survives to emit the sentinel.
    const execInput = fc.writes.find((w) => w.includes(endMark) && w.includes('echo'));
    expect(execInput).toBeDefined();
    expect(execInput!.trim()).toBe(`(\necho ok; exit 0\n)\necho ${endMark}$?`);

    emit(fc, execInput!.replace(/\n$/, '') + '\r\n');
    emit(fc, 'ok\n');
    emit(fc, `${endMark}0\n`);
    fc.emit('close', 0, null);

    const res = await p;
    // Because the sentinel still runs, the real exit status is reported and the
    // output is preserved instead of being dropped as a transport failure.
    expect(res.exitCode).toBe(0);
    expect(res.category).toBeUndefined();
    expect(res.stdout.trim()).toBe('ok');
  });

  it('strips the echoed sentinel even when command output is unterminated (P2: printf foo)', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });

    const p = (t as any).runSuViaPty('printf foo', 'pw', { timeoutMs: 60000 }) as Promise<any>;

    const { endMark } = driveToExec(fc);

    // The multiline command wrapper is echoed first. The real `printf foo`
    // output remains unterminated and therefore glues directly to the marker.
    const execInput = fc.writes.find((w) => w.includes(endMark) && w.includes('printf foo'))!;
    emit(fc, execInput.replace(/\n$/, '') + '\r\n');
    emit(fc, `foo${endMark}0\r\n`);
    fc.emit('close', 0, null);

    const res = await p;
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toBe('foo');
    expect(res.stdout).not.toContain(endMark);
    expect(res.stdout).not.toContain('echo ');
  });
});

describe('runSuViaPty auth-failure scoping (finding 5: limit failRe to login phase)', () => {
  it('does NOT treat command output containing "authentication failure" as an auth error during EXEC', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });

    const p = (t as any).runSuViaPty('grep failure /var/log/auth.log', 'pw', { timeoutMs: 60000 }) as Promise<any>;

    const { endMark } = driveToExec(fc);

    // Legitimate root command output that literally contains the failure
    // phrases. The old unconditional failRe match killed SSH here and reported
    // an auth error; the fix scopes failRe to the pre-EXEC login states.
    emit(fc, 'grep failure /var/log/auth.log\n');
    emit(fc, 'pam_unix(su:auth): authentication failure; logname=...\n');
    emit(fc, 'sshd: incorrect password attempt for baduser\n');
    emit(fc, `${endMark}0\n`);
    fc.emit('close', 0, null);

    const res = await p;
    expect(res.exitCode).toBe(0);
    expect(res.category).toBeUndefined();
    expect(res.stdout).toContain('authentication failure');
  });

  it('preserves merged PTY diagnostics as stderr on non-zero command exit', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'pw' });

    const p = (t as any).runSuViaPty('ls /missing', 'pw', { timeoutMs: 60000 }) as Promise<any>;

    const { endMark } = driveToExec(fc);
    emit(fc, 'ls /missing\n');
    emit(fc, "ls: cannot access '/missing': No such file or directory\n");
    emit(fc, `${endMark}2\n`);
    fc.emit('close', 0, null);

    const res = await p;
    expect(res.exitCode).toBe(2);
    expect(res.category).toBe('remote_exit');
    expect(res.stderr).toContain("ls: cannot access '/missing'");
  });

  it('still detects an auth failure during the su login phase', async () => {
    const fc = new FakeChild();
    spawnMock.mockReturnValue(fc);
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', suPassword: 'wrong' });

    const p = (t as any).runSuViaPty('whoami', 'wrong', { timeoutMs: 60000 }) as Promise<any>;

    // SU_PROMPT: send password, then the remote rejects it before any EXEC.
    emit(fc, 'Password: ');
    emit(fc, '\nsu: Authentication failure\n');
    expect(fc.kill).toHaveBeenCalledWith('SIGTERM');

    fc.emit('close', 1, null);
    const res = await p;
    expect(res.category).toBe('auth');
  });
});
