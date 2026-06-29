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
});
