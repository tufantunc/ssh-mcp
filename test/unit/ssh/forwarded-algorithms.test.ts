import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { ClientChannel } from 'ssh2';
import type { Profile } from '../../../src/types.js';
import { FROZEN_ALGORITHMS, FORWARDED_ALGORITHMS } from '../../../src/ssh/algorithms.js';

/**
 * #315: a `via` profile never connected when both hops negotiated chacha20-poly1305 and
 * ssh2's optional native crypto binding was absent — the published Docker image, and
 * any install that could not build it. The cause is in ssh2 (mscdex/ssh2#1523): its
 * JavaScript chacha20 cipher keeps the nonce in one module-level buffer and writes the
 * packet length before encrypting the payload, so the inner hop's write runs the outer
 * hop's `encrypt()` in the middle of its own and the payload goes out under the outer
 * hop's sequence number. test/integration/via-chacha.test.ts drives the real thing.
 *
 * These pin what this side does about it: a connection carried over another connection
 * prefers any other cipher, and nothing else about the policy moves.
 */

const CHACHA = 'chacha20-poly1305@openssh.com';

describe('FORWARDED_ALGORITHMS', () => {
  it('offers chacha20-poly1305 last, so any other common cipher is chosen first', () => {
    expect(FORWARDED_ALGORITHMS.cipher.at(-1)).toBe(CHACHA);
    expect(FORWARDED_ALGORITHMS.cipher.slice(0, -1))
      .toEqual(FROZEN_ALGORITHMS.cipher.filter((c) => c !== CHACHA));
  });

  it('removes nothing, so a server that only speaks chacha20 is still reachable', () => {
    expect([...FORWARDED_ALGORITHMS.cipher].sort()).toEqual([...FROZEN_ALGORITHMS.cipher].sort());
  });

  it('leaves every other category exactly as the frozen policy has it', () => {
    const { cipher: _f, ...frozenRest } = FROZEN_ALGORITHMS;
    const { cipher: _w, ...forwardedRest } = FORWARDED_ALGORITHMS;
    expect(forwardedRest).toEqual(frozenRest);
  });
});

describe('the algorithms a connection offers', () => {
  let offered: unknown[];

  beforeEach(() => {
    offered = [];
    vi.resetModules();
    vi.doMock('ssh2', () => {
      class FakeClient extends EventEmitter {
        connect(config: { algorithms: unknown }) {
          offered.push(config.algorithms);
          setTimeout(() => this.emit('ready'), 0);
          return this;
        }
        end() { /* nothing to tear down */ }
      }
      return { Client: FakeClient, default: { Client: FakeClient } };
    });
  });

  afterEach(() => {
    vi.doUnmock('ssh2');
    vi.resetModules();
  });

  const profile = {
    name: 'p', host: 'h', port: 22, user: 'u', role: 'admin', auth: 'password', group: 'dev',
    tty: false, timeout: 1000, maxChars: 100, maxOutputBytes: 1000, readOnly: false,
    approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 1000,
    sessionBackgroundMaxMs: 1000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;

  async function offeredBy(bastionSock?: ClientChannel) {
    const { SSHConnection } = await import('../../../src/ssh/connection.js');
    const { FROZEN_ALGORITHMS: frozen, FORWARDED_ALGORITHMS: forwarded } = await import('../../../src/ssh/algorithms.js');
    const conn = new SSHConnection(profile, { password: 'x' } as never, new Map(), 'insecure', bastionSock);
    // Private, and only the handshake is wanted here: every public method also runs a command.
    await (conn as unknown as { connect(): Promise<void> }).connect();
    return { algorithms: offered[0], frozen, forwarded };
  }

  it('is the frozen policy for a direct connection', async () => {
    const { algorithms, frozen } = await offeredBy();
    expect(algorithms).toBe(frozen);
  });

  it('prefers anything over chacha20 for a connection carried over a bastion', async () => {
    const { algorithms, forwarded } = await offeredBy(new EventEmitter() as unknown as ClientChannel);
    expect(algorithms).toBe(forwarded);
  });
});
