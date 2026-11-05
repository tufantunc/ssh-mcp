import type { SSHConnection } from '../../src/ssh/connection.js';

/**
 * Reading and clearing the remote process table for the tests that check a stopped
 * command is gone from the host (#146).
 *
 * A distinctive `sleep` duration acts as the process name, and one matcher serves both
 * counting and killing, so what a test kills is what it counted:
 *
 *  - `[s]leep` keeps the shell running the check out of its own match. An unbracketed
 *    `pkill -f "sleep N"` matches that shell too and kills it (exit 137).
 *  - `([^0-9]|$)` ends the number, so `sleep 4713` is not reached by a cleanup for
 *    `sleep 471` and a marker cannot collide with another that starts the same way.
 *  - Unanchored at the front, so a wrapper such as `sh -c 'trap "" INT TERM; sleep N;
 *    true'` is counted and killed along with its child.
 *
 * The leak checks pass on a count of 0, so a table that could not be read must not come
 * back as 0. `ps -ef | grep -c` printed 0 when ps failed, because a pipe reports only
 * grep's status, which read as "the process is gone": a leak test that passed because it
 * saw nothing. The count here keeps ps's status and throws on anything that is not a
 * count.
 */
function matcher(marker: number): string {
  return `[s]leep ${marker}([^0-9]|$)`;
}

/** Every process running `sleep <marker>`, wrapper shells included. */
export async function treeSize(conn: SSHConnection, marker: number): Promise<number> {
  // ps's own failure exits 90 before grep runs; grep -c exits 0 (matched), 1 (matched
  // nothing) or 2 (error). Only the first two carry a count.
  const { stdout, stderr, exitCode } = await conn.exec(
    `out=$(ps -ef) || exit 90; printf '%s\\n' "$out" | grep -cE "${matcher(marker)}"`,
    { timeoutMs: 5000 },
  );
  const text = stdout.trim();
  if ((exitCode !== 0 && exitCode !== 1) || !/^\d+$/.test(text)) {
    throw new Error(
      `could not read the process table (exit ${exitCode}, stdout ${JSON.stringify(stdout)}): ${stderr.trim()}`,
    );
  }
  return Number(text);
}

/**
 * Polls, because the kill ladder is asynchronous by design: INT now, TERM at +1s, KILL
 * at +2s, the channel closed at +3s. Callers pass a budget that covers all three gaps
 * plus polling.
 */
export async function goneWithin(conn: SSHConnection, marker: number, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  for (;;) {
    // The deadline is checked before the next round trip, not after, so the loop cannot
    // overrun its budget by a full `treeSize()` timeout and surface as an opaque vitest
    // timeout instead of the assertion that was actually failing.
    if (await treeSize(conn, marker) === 0) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 250));
  }
}

/**
 * Kills everything `treeSize` would count for these markers. `-9`, because a command
 * that trapped INT and TERM survives anything gentler, and a survivor sits in the
 * fixture for its full duration and corrupts the next run's count.
 */
export async function killMarkers(conn: SSHConnection | undefined, markers: number[]): Promise<void> {
  const script = markers.map((m) => `pkill -9 -f "${matcher(m)}"`).join('; ');
  await conn?.exec(`${script}; true`, { timeoutMs: 5000 }).catch(() => {});
}
