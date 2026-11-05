import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';
import { goneWithin, killMarkers } from './process-table.js';

/**
 * The other half of #146: what the caller is told when the command *cannot* be
 * stopped.
 *
 * `terminateChannel` reports failure only when ssh2 offers neither a usable public
 * method nor the internals to route around it — which is what a future ssh2 could
 * introduce, and is precisely the shape of this bug (a stop that silently did
 * nothing). So the warning has to be wired, and a wired-but-untested warning is the
 * same class of defect one layer up.
 *
 * It is forced here rather than waited for: the real `terminateChannel` still runs,
 * so the command is really killed, but it reports failure. That makes this a test of
 * the message, which is the only part a real ssh2 change would leave to us. "Really
 * killed" is asserted, not assumed: if the mock stopped delegating, every run would
 * leave its `sleep` behind and the message tests would still pass.
 */
vi.mock('../../src/ssh/channel-signal.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/ssh/channel-signal.js')>(
    '../../src/ssh/channel-signal.js',
  );
  return { ...actual, terminateChannel: (channel: never) => { actual.terminateChannel(channel); return false; } };
});

/** One marker per test, so a leak in one cannot fail the other's leak check. */
const TIMEOUT_MARKER = 4713;
const ABORT_MARKER = 4715;

let status: ServerStatus;
let env: ReturnType<typeof setupEnv>;
let conn: SSHConnection;

beforeAll(async () => {
  status = await checkAllServers();
  if (!allServersUp(status)) return;
  env = setupEnv();
  conn = await createConnection('admin');
});

afterEach(async () => { await killMarkers(conn, [TIMEOUT_MARKER, ABORT_MARKER]); });

afterAll(async () => {
  await conn?.close();
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()))('when the command cannot be signalled', () => {
  it('says so instead of reporting a bare timeout', async () => {
    const err = await conn.exec(`sleep ${TIMEOUT_MARKER}`, { timeoutMs: 1000 }).then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/timed out/i);
    expect(err?.message).toMatch(/may still be running on the host/);
    expect(await goneWithin(conn, TIMEOUT_MARKER, 8000), 'the forced failure leaked the command').toBe(true);
  }, 30000);

  it('says so instead of reporting a bare cancellation', async () => {
    const ac = new AbortController();
    const started = conn.exec(`sleep ${ABORT_MARKER}`, { timeoutMs: 60000, abortSignal: ac.signal });
    await new Promise((r) => setTimeout(r, 300));
    ac.abort();
    const err = await started.then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/abort/i);
    expect(err?.message).toMatch(/may still be running on the host/);
    expect(await goneWithin(conn, ABORT_MARKER, 8000), 'the forced failure leaked the command').toBe(true);
  }, 30000);
});
