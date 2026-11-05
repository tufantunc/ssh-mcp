import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';
import { BackgroundSession } from '../../src/ssh/session.js';
import { treeSize, killMarkers } from './process-table.js';

let status: ServerStatus;
let env: ReturnType<typeof setupEnv>;
let conn: SSHConnection;

beforeAll(async () => {
  status = await checkAllServers();
  if (!allServersUp(status)) return;
  env = setupEnv();
  conn = await createConnection('admin');
});

afterAll(async () => {
  await conn?.close();
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()))('BackgroundSession', () => {
  it('opens a background session with tail -f and reports running', async () => {
    await conn.exec('echo "line1" > /tmp/bg-test.log');
    const session = await conn.openSession({ name: 'tail-test', type: 'background', command: 'tail -f /tmp/bg-test.log' }) as BackgroundSession;
    expect(session.isRunning()).toBe(true);
    await new Promise((r) => setTimeout(r, 500));
    expect(session.readOutput(10)).toContain('line1');
    await conn.closeSession('tail-test');
  }, 15000);

  it('readOutput sees newly appended lines', async () => {
    await conn.exec('echo "initial" > /tmp/bg-tail.log');
    const session = await conn.openSession({ name: 'tail-append', type: 'background', command: 'tail -f /tmp/bg-tail.log' }) as BackgroundSession;
    await new Promise((r) => setTimeout(r, 1000));
    await conn.exec('echo "appended" >> /tmp/bg-tail.log');
    await new Promise((r) => setTimeout(r, 1500));
    expect(session.readOutput(20)).toContain('appended');
    await conn.closeSession('tail-append').catch(() => {});
  }, 15000);

  it('close marks session as closed and frees channel', async () => {
    const session = await conn.openSession({ name: 'kill-test', type: 'background', command: 'sleep 300' }) as BackgroundSession;
    expect(session.isRunning()).toBe(true);
    await conn.closeSession('kill-test').catch(() => {});
    expect(conn.getSession('kill-test')).toBeUndefined();
  }, 10000);

  // Regression: each chunk was split independently, so a line spanning two
  // chunks was stored as two entries and readOutput's join re-inserted a '\n'
  // that was never in the stream. A chunk ending on '\n' also left a trailing
  // '' entry, inserting a blank line between chunks.
  it('does not break long lines or insert blank lines between chunks', async () => {
    // Lines long enough to be split across SSH channel chunks.
    const command = 'for i in $(seq 1 40); do printf "START-%s-" "$i"; head -c 5000 /dev/zero | tr "\\0" "x"; printf -- "-END-%s\\n" "$i"; done';
    const session = await conn.openSession({ name: 'longline-test', type: 'background', command }) as BackgroundSession;
    await new Promise((r) => setTimeout(r, 3000));

    const out = session.readOutput(200);
    const lines = out.split('\n');

    // No blank lines between records.
    expect(lines.filter((l) => l === '')).toHaveLength(0);

    // Every record must be intact on a single line: same index at both ends.
    const records = lines.filter((l) => l.includes('START-'));
    expect(records.length).toBeGreaterThan(5);
    for (const line of records) {
      const start = line.match(/START-(\d+)-/);
      const end = line.match(/-END-(\d+)$/);
      expect(start, `line lost its END marker: ${line.slice(0, 40)}...`).toBeTruthy();
      expect(end, `line lost its END marker: ${line.slice(0, 40)}...`).toBeTruthy();
      expect(start![1]).toBe(end![1]);
      expect(line.length).toBeGreaterThan(5000);
    }

    await conn.closeSession('longline-test').catch(() => {});
  }, 20000);

  it('ring buffer handles overflow — last N lines returned', async () => {
    const session = await conn.openSession({ name: 'ring-test', type: 'background', command: 'for i in $(seq 1 5000); do echo "line-$i"; done' }) as BackgroundSession;
    await new Promise((r) => setTimeout(r, 3000));
    const lines = session.readOutput(10).split('\n').filter(Boolean);
    expect(lines.length).toBeLessThanOrEqual(10);
    expect(lines[lines.length - 1]).toContain('line-5000');
    await conn.closeSession('ring-test').catch(() => {});
  }, 15000);
});

describe.skipIf(!allServersUp(await checkAllServers()))('closing a background session stops it on the host', () => {
  /**
   * `close()` used to be `stream.close()` alone — the rung this project measured as
   * stopping nothing on a non-tty exec channel (#146). So `close-session` reported
   * `status: 'closed'` while the command kept running on the host: the same false claim
   * `exec` stopped making, in the sibling path the fix did not reach.
   *
   * How the process table is read and cleared is in ./process-table.ts.
   */
  const MARKER = 4820;
  const TRAPPING_MARKER = 4821;

  afterEach(async () => {
    // Both markers: a failed run used to leave a `sleep` in the fixture for its full 80
    // minutes, and nothing reaped it. In the hook rather than an in-body `finally` —
    // measured, a vitest test *timeout* runs the hook and skips the `finally`, which is
    // exactly how one red run poisons every later one.
    await killMarkers(conn, [MARKER, TRAPPING_MARKER]);
  });

  it('waits for the escalation instead of tearing the transport down mid-ladder', async () => {
    // A command that ignores INT and TERM only dies to the KILL rung at +2s. Those rungs are
    // timers, so if `close()` returned as soon as INT was dispatched, the caller's next move
    // — `SSHConnection.close()` calling `client.end()`, or the process exiting — cancelled
    // the rest of the ladder and the command survived. That is the case KILL exists for, so
    // it is the case worth testing.
    const trapping = TRAPPING_MARKER;
    {
      await conn.openSession({
        name: 'bg-trap',
        type: 'background',
        command: `sh -c 'trap "" INT TERM; sleep ${trapping}; true'`,
      });
      await new Promise((r) => setTimeout(r, 400));
      expect(await treeSize(conn, trapping), 'the trapping tree never appeared').toBe(2);

      await conn.closeSession('bg-trap');

      expect(await treeSize(conn, trapping), 'the trapping command outlived close-session').toBe(0);
    }
  }, 30000);

  it('kills the command instead of only dropping the channel', async () => {
    const session = await conn.openSession({ name: 'bg-kill', type: 'background', command: `sleep ${MARKER}` });
    expect(session).toBeInstanceOf(BackgroundSession);
    await new Promise((r) => setTimeout(r, 400));
    expect(await treeSize(conn, MARKER), 'the background command never started').toBeGreaterThan(0);

    const started = Date.now();
    const outcome = await conn.closeSession('bg-kill');
    const elapsed = Date.now() - started;
    // The reported outcome, not just the process table: `'closed'` is the only value that
    // means the channel actually closed, and hardcoding it was invisible before this.
    expect(outcome).toBe('closed');

    // Asserted on elapsed time, not on a poll budget. The stream's stdin is never ended, so
    // ssh2's own `signal()` sends INT on the public path and the command dies in one round
    // trip — measured at 2-5ms. The ceiling is 500ms rather than 5000: every reachable
    // outcome is under 3.5s (the ladder's own bound), so a 5000ms ceiling discriminated
    // nothing, while 500ms still leaves a 100x margin and fails the moment this command
    // starts surviving to the TERM rung at +1s.
    expect(await treeSize(conn, MARKER), 'the background command outlived close-session').toBe(0);
    expect(elapsed, 'the command survived INT and had to be escalated').toBeLessThan(500);
  }, 30000);
});
