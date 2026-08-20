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
const TRAPPING_MARKER = 4716;

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
  await conn?.exec('pkill -f "^sleep 47" || true', { timeoutMs: 5000 }).catch(() => {});
});

/** How many copies of the marker command are running, seen over a fresh channel. */
async function running(marker: number): Promise<number> {
  const { stdout } = await conn.exec(`pgrep -f "^sleep ${marker}" | wc -l`, { timeoutMs: 5000 });
  return Number(stdout.trim());
}

/**
 * Every process whose command line mentions the marker — the shell wrapper included.
 *
 * `grep "[s]leep N"` rather than `pgrep -f N`: the shell sshd wraps this very command in
 * carries the marker in its own argv, so `pgrep -f` counted itself and reported one
 * survivor too many. The bracket makes the pattern not match the literal text of the
 * command that is searching.
 */
async function tree(marker: number): Promise<number> {
  const { stdout } = await conn.exec(`ps -ef | grep -c "[s]leep ${marker}"`, { timeoutMs: 5000 });
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
    if (await running(marker) === 0) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 250));
  }
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

describe.skipIf(!allServersUp(await checkAllServers()))('what the ladder cannot do', () => {
  /**
   * A signal request reaches the command's session leader, not its process group. This
   * test exists so that limitation is a recorded fact rather than a surprise: it pins
   * what actually happens to a process tree whose root ignores INT and TERM.
   *
   * If a future change makes the whole tree die — a process-group signal, or a server
   * that kills the group — this test fails, and that failure is good news to be acted
   * on rather than a regression.
   */
  it('kills the signalled process but not the children it left behind', async () => {
    const started = conn.exec(
      `sh -c 'trap "" INT TERM; sleep ${TRAPPING_MARKER}'`,
      { timeoutMs: 1500 },
    );
    await new Promise((r) => setTimeout(r, 400));
    // The shell and its child: `pgrep -f` matches both, so this counts the tree.
    expect(await tree(TRAPPING_MARKER), 'the command tree never appeared').toBeGreaterThanOrEqual(2);

    const err = await started.then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/timed out/i);
    // The request was dispatched, so nothing warns — which is exactly why the warning's
    // absence must not be read as "the process is gone".
    expect(err?.message).not.toMatch(/may still be running/);

    // INT and TERM are trapped; KILL takes the shell at +2s. Measured in the container:
    // the `sh` wrapper is gone and `sleep` is left reparented to PID 1.
    await new Promise((r) => setTimeout(r, 4000));
    const left = await tree(TRAPPING_MARKER);
    expect(left, 'the signalled shell survived KILL').toBeLessThan(2);
    expect(left, 'the orphaned child died too — the ladder reaches the process group now, so update this test')
      .toBe(1);
  }, 30000);
});
