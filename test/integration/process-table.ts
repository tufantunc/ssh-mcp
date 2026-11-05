import type { SSHConnection } from '../../src/ssh/connection.js';

/**
 * Reading the remote process table for the kill tests (#146).
 *
 * Every count here answers "is it still running?", and those tests pass on `0`. So a
 * table that could not be read must not come back as `0`: `pgrep … | wc -l` printed
 * `0` when pgrep was missing, and `ps -ef | grep -c` printed `0` when ps failed, which
 * read as "the process is gone" — a leak test that passes because it saw nothing.
 * Each command here keeps the exit status of the step that reads the table, and a
 * status that is not "matched" or "matched nothing" throws.
 *
 * Distinctive sleep durations act as process names: `^sleep 4711` matches the command
 * and nothing else, including not the shell that sshd wraps it in.
 */

/** Exit status the tree count uses for "ps itself failed". */
const PS_FAILED = 90;

/** How many copies of `sleep <marker>` are running, seen over a fresh channel. */
export async function running(conn: SSHConnection, marker: number): Promise<number> {
  // pgrep: 0 = matched, 1 = matched nothing, anything else = could not look.
  const { stdout, stderr, exitCode } = await conn.exec(`pgrep -f "^sleep ${marker}"`, { timeoutMs: 5000 });
  if (exitCode !== 0 && exitCode !== 1) {
    throw new Error(`pgrep could not read the process table (exit ${exitCode}): ${stderr.trim()}`);
  }
  return stdout.split('\n').filter((line) => line.trim() !== '').length;
}

/**
 * Every process mentioning `sleep <marker>`, wrapper shells included. The bracket
 * keeps the searching shell out of its own count.
 */
export async function treeSize(conn: SSHConnection, marker: number): Promise<number> {
  // grep -c: 0 = matched, 1 = matched nothing, 2 = error; ps's own failure is mapped
  // to PS_FAILED, because a pipe would otherwise report only grep's status.
  const { stdout, stderr, exitCode } = await conn.exec(
    `out=$(ps -ef) || exit ${PS_FAILED}; printf '%s\\n' "$out" | grep -c "[s]leep ${marker}"`,
    { timeoutMs: 5000 },
  );
  if (exitCode !== 0 && exitCode !== 1) {
    throw new Error(`ps could not read the process table (exit ${exitCode}): ${stderr.trim()}`);
  }
  const count = Number(stdout.trim());
  if (!Number.isInteger(count)) throw new Error(`unreadable process count: ${JSON.stringify(stdout)}`);
  return count;
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
 * Kills exactly these markers. One `pkill` per marker, anchored at both ends, so a
 * prefix such as `^sleep 47` cannot reach another file's marker (4713 belongs to
 * exec-unstoppable) — `fileParallelism: false` was the only thing keeping that safe.
 */
export async function killMarkers(conn: SSHConnection | undefined, markers: number[]): Promise<void> {
  const script = markers.map((m) => `pkill -9 -f "^sleep ${m}$"`).join('; ');
  await conn?.exec(`${script}; true`, { timeoutMs: 5000 }).catch(() => {});
}
