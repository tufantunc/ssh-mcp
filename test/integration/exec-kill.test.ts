import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';

/**
 * #146: a timed-out or cancelled exec must not leave the command running on the host.
 *
 * The existing cancellation test asserts that the promise rejects with "timed out",
 * which it always did — the defect was never in the error, it was in what happened
 * on the other end of the connection. So every assertion here is about the remote
 * process table, observed over a second channel.
 *
 * Distinctive sleep durations act as process names: `pgrep -f "^sleep 4711"` matches
 * the command and nothing else, including not the shell that sshd wraps it in.
 */
let status: ServerStatus;
let env: ReturnType<typeof setupEnv>;
let conn: SSHConnection;

const TIMEOUT_MARKER = 4711;
const ABORT_MARKER = 4712;
const PRE_ABORT_MARKER = 4714;

beforeAll(async () => {
  status = await checkAllServers();
  if (!allServersUp(status)) return;
  env = setupEnv();
  conn = await createConnection('admin');
});

afterAll(async () => { await conn?.close(); env?.restore(); });

afterEach(async () => {
  // A leaked process would otherwise sit in the container for its full duration and
  // make the next run's count wrong rather than the next run's *behaviour* wrong.
  await conn?.exec('pkill -9 -f "^sleep 47" || true', { timeoutMs: 5000 }).catch(() => {});
});

/** How many copies of the marker command are running, seen over a fresh channel. */
async function running(marker: number): Promise<number> {
  const { stdout } = await conn.exec(`pgrep -f "^sleep ${marker}" | wc -l`, { timeoutMs: 5000 });
  return Number(stdout.trim());
}

/**
 * Polls, because the kill ladder is asynchronous by design: INT now, TERM at +1s, KILL
 * at +2s, the channel closed at +3s. The 8000ms budget below covers all three gaps plus
 * polling.
 */
async function goneWithin(marker: number, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  for (;;) {
    // The deadline is checked before the next round trip, not after, so the loop cannot
    // overrun its budget by a full `running()` timeout and surface as an opaque vitest
    // timeout instead of the assertion that was actually failing.
    if (await treeSize(marker) === 0) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 250));
  }
}

/** Every process mentioning the marker, wrapper shells included. */
async function treeSize(marker: number): Promise<number> {
  const { stdout } = await conn.exec(`ps -ef | grep -c "[s]leep ${marker}"`, { timeoutMs: 5000 });
  return Number(stdout.trim());
}

describe.skipIf(!allServersUp(await checkAllServers()))('a stopped exec stops on the host too', () => {
  it('kills the remote process when the command times out', async () => {
    const started = conn.exec(`sleep ${TIMEOUT_MARKER}`, { timeoutMs: 1500 });
    // Sampled while the command is in flight, not after the timeout. Checking
    // afterwards raced the fix and lost: the signal goes out synchronously with the
    // rejection, so by the time a second channel is open the process is already
    // gone — and a `0` there is indistinguishable from a marker that never matched.
    await new Promise((r) => setTimeout(r, 400));
    expect(await running(TIMEOUT_MARKER), 'the marker never matched the running command')
      .toBeGreaterThan(0);

    const err = await started.then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/timed out/i);
    // The other half of the contract: a stop that worked must not warn. A warning
    // on every timeout would be as useless as the silence it replaced.
    expect(err?.message).not.toMatch(/may still be running/);

    expect(await goneWithin(TIMEOUT_MARKER, 8000), 'the remote process outlived the timeout').toBe(true);
  }, 30000);

  it('kills the remote process when the caller aborts', async () => {
    const ac = new AbortController();
    const started = conn.exec(`sleep ${ABORT_MARKER}`, { timeoutMs: 60000, abortSignal: ac.signal });
    await new Promise((r) => setTimeout(r, 400));
    expect(await running(ABORT_MARKER), 'the marker never matched the running command')
      .toBeGreaterThan(0);

    ac.abort();
    const err = await started.then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/abort/i);
    expect(err?.message).not.toMatch(/may still be running/);

    expect(await goneWithin(ABORT_MARKER, 8000), 'the remote process outlived the cancellation').toBe(true);
  }, 30000);

  it('kills the remote process when the signal was already aborted', async () => {
    // The third rewired settle path, and the one with the highest leak risk: the abort
    // lands between `client.exec()` dispatching the command and its callback, so the
    // command is already running on the host. Nothing in the suite passed a pre-aborted
    // signal before, so this branch could have been deleted and everything stayed green.
    const ac = new AbortController();
    ac.abort();
    const err = await conn
      .exec(`sleep ${PRE_ABORT_MARKER}`, { timeoutMs: 60000, abortSignal: ac.signal })
      .then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/aborted before execution/);
    expect(err?.message).not.toMatch(/may still be running/);

    // No in-flight sample here — the command may never become visible — so this asserts
    // only that nothing is left behind.
    expect(await goneWithin(PRE_ABORT_MARKER, 8000), 'the remote process outlived the cancellation').toBe(true);
  }, 30000);
});

describe.skipIf(!allServersUp(await checkAllServers()))('a command that ignores the gentle signals', () => {
  /**
   * The reason the KILL rung exists, against a command that traps INT and TERM.
   *
   * This replaces a test that asserted the opposite — that the ladder kills the signalled
   * process and orphans its children. That was wrong twice over. OpenSSH answers a signal
   * request with `killpg()` on the process group (session.c, `session_signal_req`), so the
   * tree dies; and the "orphan" the old test measured was debris leaked by an earlier
   * experiment, which is also why it was red on a clean container and green on its second
   * run. Measured on 10.3p1: shell and child share one pgid, and one KILL request removes
   * both.
   *
   * The trailing `; true` matters — without it the shell exec-replaces itself with `sleep`
   * (SIG_IGN survives exec, so it has no reason to stay), and there is no tree to test.
   */
  const MARKER = 4718;

  /** Every process in the tree. The bracket keeps the searching shell out of its own count. */
  async function alive(): Promise<number> {
    const { stdout } = await conn.exec(`ps -ef | grep -c "[s]leep ${MARKER}"`, { timeoutMs: 5000 });
    return Number(stdout.trim());
  }

  afterEach(async () => {
    // `kill -9`, not the default: anything left here inherited SIG_IGN for TERM from the
    // trap, so `pkill` without `-9` reports success and reaps nothing — which is how a
    // single red run used to poison the fixture for the marker's full duration.
    await conn?.exec(`pkill -9 -f "sleep ${MARKER}" || true`, { timeoutMs: 5000 }).catch(() => {});
  });

  it('kills the whole process group, trap or no trap', async () => {
    const started = conn.exec(`sh -c 'trap "" INT TERM; sleep ${MARKER}; true'`, { timeoutMs: 1500 });
    await new Promise((r) => setTimeout(r, 400));
    expect(await alive(), 'the two-process tree never appeared').toBe(2);

    const err = await started.then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/timed out/i);
    expect(err?.message).not.toMatch(/may still be running/);

    // INT and TERM are trapped, so nothing happens until KILL at +2s.
    expect(await goneWithin(MARKER, 8000), 'the trapping command outlived the ladder').toBe(true);
    expect(await alive(), 'a member of the process group survived').toBe(0);
  }, 30000);
});
