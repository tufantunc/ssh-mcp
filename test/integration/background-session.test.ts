import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';
import { BackgroundSession } from '../../src/ssh/session.js';

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
   * A distinctive `sleep` duration acts as the process name; `grep "[s]leep N"` so the
   * shell that runs the check does not match its own command line.
   */
  const MARKER = 4820;

  async function alive(): Promise<number> {
    const { stdout } = await conn.exec(`ps -ef | grep -c "[s]leep ${MARKER}"`, { timeoutMs: 5000 });
    return Number(stdout.trim());
  }

  it('kills the command instead of only dropping the channel', async () => {
    const session = await conn.openSession({ name: 'bg-kill', type: 'background', command: `sleep ${MARKER}` });
    expect(session).toBeInstanceOf(BackgroundSession);
    await new Promise((r) => setTimeout(r, 400));
    expect(await alive(), 'the background command never started').toBeGreaterThan(0);

    await conn.closeSession('bg-kill');

    // A generous budget on purpose: the ladder itself needs up to 3s, and each poll is a
    // real exec round trip, which slows down measurably when the whole suite is running
    // against the same container. 8s passed in isolation and failed inside `npm test`.
    const deadline = Date.now() + 20000;
    for (;;) {
      if (await alive() === 0) break;
      if (Date.now() > deadline) break;
      await new Promise((r) => setTimeout(r, 250));
    }
    expect(await alive(), 'the background command outlived close-session').toBe(0);
  }, 30000);
});
