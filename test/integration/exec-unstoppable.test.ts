import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createConnection, type ServerStatus } from './fixtures.js';
import type { SSHConnection } from '../../src/ssh/connection.js';

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
 * so the command is really killed and nothing leaks, but it reports failure. That
 * makes this a test of the message, which is the only part a real ssh2 change would
 * leave to us.
 */
vi.mock('../../src/ssh/channel-signal.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/ssh/channel-signal.js')>(
    '../../src/ssh/channel-signal.js',
  );
  return { ...actual, terminateChannel: (channel: never) => { actual.terminateChannel(channel); return false; } };
});

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
  await conn?.exec('pkill -f "^sleep 4713" || true', { timeoutMs: 5000 }).catch(() => {});
  await conn?.close();
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()))('when the command cannot be signalled', () => {
  it('says so instead of reporting a bare timeout', async () => {
    const err = await conn.exec('sleep 4713', { timeoutMs: 1000 }).then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/timed out/i);
    expect(err?.message).toMatch(/may still be running on the host/);
  }, 30000);

  it('says so instead of reporting a bare cancellation', async () => {
    const ac = new AbortController();
    const started = conn.exec('sleep 4713', { timeoutMs: 60000, abortSignal: ac.signal });
    await new Promise((r) => setTimeout(r, 300));
    ac.abort();
    const err = await started.then(() => null, (e: Error) => e);
    expect(err?.message).toMatch(/abort/i);
    expect(err?.message).toMatch(/may still be running on the host/);
  }, 30000);
});
