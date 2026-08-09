import { describe, it, expect, afterEach } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';
import { PORTS, profiles } from './fixtures.js';
import type { BackgroundSession } from '../../src/ssh/session.js';

/**
 * Opening a session has to survive the connection being gone underneath it.
 *
 * Channel opens are already wrapped in openWithRetry, but the callbacks reached
 * for the client directly: with the link dropped, every attempt threw "SSH
 * connection not established" for the same reason, so the retry re-ran a dead
 * connection three times and gave up. SftpClient had already learned this and
 * re-establishes inside its retry; the session paths had not.
 *
 * Dropbear drops the whole connection under channel churn, which is how CI kept
 * seeing this as an intermittent failure on that target rather than as the bug
 * it is. Closing the connection reproduces the same state deterministically.
 */
const up = await isSshServerUp(SSH_HOST, PORTS.admin);
assertAvailable(up, `admin (${SSH_HOST}:${PORTS.admin})`);

describe.skipIf(!up)('opening a session after the connection dropped', () => {
  let conn: SSHConnection;
  const saved = { ...process.env };

  afterEach(async () => {
    await conn?.close().catch(() => {});
    process.env = { ...saved };
  });

  async function connect(): Promise<SSHConnection> {
    process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';
    const c = new SSHConnection(profiles.admin, await resolveCredentials(profiles.admin), new Map(), 'insecure');
    await c.ensureConnected();
    return c;
  }

  it('re-establishes for an interactive session', async () => {
    conn = await connect();
    await conn.close();
    expect(conn.isConnected()).toBe(false);

    const session = await conn.openSession({ name: 'reconnect-interactive', type: 'interactive' });
    expect(session).toBeTruthy();

    const result = await (session as any).run('echo reconnected');
    expect(result.stdout.trim()).toBe('reconnected');
  }, 40000);

  it('re-establishes for a background session', async () => {
    conn = await connect();
    await conn.close();

    const session = await conn.openSession({
      name: 'reconnect-background',
      type: 'background',
      command: "sh -c 'echo bg-alive; sleep 1'",
    }) as BackgroundSession;

    await new Promise((r) => setTimeout(r, 1200));
    expect(session.readOutput(10)).toContain('bg-alive');
  }, 40000);

  // The real failure mode. openSession calls ensureConnected() first, so a link
  // that is already gone gets rebuilt there — that is why closing the
  // connection is not enough to reproduce it. What CI hit on Dropbear is the
  // link dying *after* that check, while the channel is being opened. Reaching
  // past openSession into the session manager puts us in exactly that state.
  it('re-establishes when the link dies after the pre-check', async () => {
    conn = await connect();
    (conn as any).client = null;

    const session = await (conn as any).sessions.open({
      name: 'reconnect-midflight',
      type: 'background',
      command: "sh -c 'echo survived'",
    });

    await new Promise((r) => setTimeout(r, 800));
    expect(session.readOutput(10)).toContain('survived');
  }, 40000);

  it('re-establishes for a one-shot command', async () => {
    conn = await connect();
    await conn.close();

    const result = await conn.exec('id -un');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('admin');
  }, 40000);
});
