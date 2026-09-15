import { describe, it, expect, afterEach } from 'vitest';
import { connect as tcpConnect, createServer, type Server } from 'node:net';
import { SSHConnection } from '../../../src/ssh/connection.js';
import type { Profile } from '../../../src/types.js';
import type { HostKeyMode } from '../../../src/ssh/host-key.js';
import { sshAvailable, SSH_HOST, SSH_PORT } from '../../integration/helpers.js';

/**
 * Recovering from a handshake that was cut short.
 *
 * Reported as #197: after one failure every later call on the profile failed
 * too, including trivial read-only ones, and restarting the MCP server by hand
 * was the only way out. The reporter's own diagnosis — that `exec()` arms its
 * timeout after `ensureConnected()`, leaving connection setup unbounded — is
 * not what does it: `connect()` carries its own 20s bound. The defect is next
 * door. A failed handshake was cached and replayed forever, so the profile
 * could never reconnect even once the server was healthy again.
 *
 * No SSH server here on purpose: a plain TCP listener that answers with a
 * banner and then drops is the shape of an sshd restarting under a running
 * command, and it makes the failure exact rather than timing-dependent.
 */

const profileFor = (port: number): Profile => ({
  name: 'p',
  host: '127.0.0.1',
  port,
  user: 'u',
  auth: 'password',
  tty: false,
  timeout: 2000,
  maxChars: 5000,
  maxOutputBytes: 1_048_576,
  role: 'admin',
  readOnly: false,
  approvalPolicy: 'auto',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60_000,
  sessionBackgroundMaxMs: 3_600_000,
  commandQuotaPerDay: 0,
});

let server: Server | undefined;

afterEach(async () => {
  if (server) await new Promise<void>((r) => server!.close(() => r()));
  server = undefined;
});

/** Answers with an SSH banner, then drops the socket while `drop` is true. */
async function dropperServer(state: { drop: boolean }): Promise<number> {
  server = createServer((sock) => {
    sock.write('SSH-2.0-dropper\r\n');
    if (state.drop) setTimeout(() => sock.destroy(), 40);
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  return (server!.address() as { port: number }).port;
}

const SSH_AVAILABLE = await sshAvailable();

/**
 * Drops the handshake while `state.drop` is true, and proxies to the real SSH
 * server once it is false — an sshd that was restarting and then came back.
 */
async function flakyProxy(state: { drop: boolean }): Promise<number> {
  server = createServer((sock) => {
    if (state.drop) {
      sock.write('SSH-2.0-dropper\r\n');
      setTimeout(() => sock.destroy(), 40);
      return;
    }
    const upstream = tcpConnect(SSH_PORT, SSH_HOST);
    upstream.on('error', () => sock.destroy());
    sock.on('error', () => upstream.destroy());
    sock.pipe(upstream).pipe(sock);
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  return (server!.address() as { port: number }).port;
}

describe('a connection whose handshake was cut short', () => {
  it('tries again instead of replaying the first failure forever', async () => {
    const state = { drop: true };
    const port = await dropperServer(state);
    const conn = new SSHConnection(
      profileFor(port),
      { password: 'x' },
      new Map(),
      'insecure' as HostKeyMode,
    );

    await expect(conn.ensureConnected()).rejects.toThrow(/during handshake/);

    // The second attempt has to reach the server rather than return the first
    // attempt's rejected promise. A replay is instant and identical; a real
    // attempt takes a round-trip, so the elapsed time is what separates them.
    const started = Date.now();
    await expect(conn.ensureConnected()).rejects.toThrow(/during handshake/);
    expect(
      Date.now() - started,
      'second attempt returned instantly, so it replayed the cached failure',
    ).toBeGreaterThan(5);

    await conn.close().catch(() => {});
  }, 20000);

  it('leaves no cached attempt behind after a failure', async () => {
    const state = { drop: true };
    const port = await dropperServer(state);
    const conn = new SSHConnection(
      profileFor(port),
      { password: 'x' },
      new Map(),
      'insecure' as HostKeyMode,
    );

    await expect(conn.ensureConnected()).rejects.toThrow(/during handshake/);

    // The state the next call reads. Holding a settled promise here is the
    // whole defect: `ensureConnected` returns it before it ever tries again.
    expect(
      (conn as unknown as { connecting: unknown }).connecting,
      'a failed attempt stayed cached and would be replayed',
    ).toBeNull();

    await conn.close().catch(() => {});
  }, 20000);

  // The property an operator actually has: once the server is back, the profile
  // works again without anyone restarting the MCP process. Skipped when the
  // Docker SSH servers are not up, since only a real handshake proves recovery.
  it.skipIf(!SSH_AVAILABLE)('connects once the server comes back', async () => {
    const state = { drop: true };
    const port = await flakyProxy(state);
    const profile = { ...profileFor(port), user: 'admin' };
    process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';
    const conn = new SSHConnection(
      profile,
      { password: 'secret' },
      new Map(),
      'insecure' as HostKeyMode,
    );

    await expect(conn.ensureConnected()).rejects.toThrow(/during handshake/);
    expect(conn.isConnected()).toBe(false);

    state.drop = false;
    await conn.ensureConnected();

    expect(conn.isConnected()).toBe(true);
    const result = await conn.exec('echo recovered');
    expect(result.stdout.trim()).toBe('recovered');

    await conn.close().catch(() => {});
  }, 30000);
});
