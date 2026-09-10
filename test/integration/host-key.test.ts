import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import { checkAllServers, allServersUp, setupEnv, profiles } from './fixtures.js';

// Every other integration test connects with hostKeyMode 'insecure', so nothing
// proved that ssh2's hostVerifier is actually wired to verifyHostKey during a
// real handshake: a regression that dropped the verifier, or made it always
// return true, would have left the whole suite green.
let env: ReturnType<typeof setupEnv>;

beforeAll(async () => {
  if (!allServersUp(await checkAllServers())) return;
  env = setupEnv();
});

afterAll(() => { env?.restore(); });

async function connect(knownHosts: Map<string, string>, mode: 'tofu' | 'strict', overrides = {}) {
  const profile = { ...profiles.admin, ...overrides };
  const creds = await resolveCredentials(profile);
  return new SSHConnection(profile, creds, knownHosts, mode);
}

describe.skipIf(!allServersUp(await checkAllServers()))('Host key verification (real handshake)', () => {
  it('TOFU records the host key on first connect', async () => {
    const knownHosts = new Map<string, string>();
    const conn = await connect(knownHosts, 'tofu');
    await conn.ensureConnected();

    expect(knownHosts.size).toBe(1);
    const [key, fingerprint] = [...knownHosts.entries()][0];
    expect(key).toBe(`${profiles.admin.host}:${profiles.admin.port}`);
    expect(fingerprint).toMatch(/^SHA256:/);

    await conn.close();
  }, 30000);

  it('TOFU accepts a reconnect with the same key', async () => {
    const knownHosts = new Map<string, string>();
    const first = await connect(knownHosts, 'tofu');
    await first.ensureConnected();
    await first.close();

    const second = await connect(knownHosts, 'tofu');
    await expect(second.ensureConnected()).resolves.not.toThrow();
    expect(knownHosts.size).toBe(1);
    await second.close();
  }, 30000);

  it('rejects a connection when the recorded key no longer matches', async () => {
    // Poison the store: this is the MITM case the whole mechanism exists for.
    const knownHosts = new Map<string, string>([
      [`${profiles.admin.host}:${profiles.admin.port}`, 'SHA256:definitelyNotTheRealHostKeyAAAAAAAAAAAAAAAA'],
    ]);
    const conn = await connect(knownHosts, 'tofu');
    // The code, not just the throw. A bare `rejects.toThrow()` passes for a
    // handshake that failed for any reason at all, so it cannot tell this refusal
    // from a container that was not listening — and it is the only thing proving
    // the message survives ssh2's callback boundary and reaches the operator.
    await expect(conn.ensureConnected()).rejects.toThrow(/HOST_KEY_MISMATCH/);
    await conn.close();
  }, 30000);

  it('strict mode refuses an unknown host', async () => {
    const conn = await connect(new Map(), 'strict');
    await expect(conn.ensureConnected()).rejects.toThrow(/HOST_KEY_UNKNOWN/);
    await conn.close();
  }, 30000);

  it('strict mode connects once the key is known', async () => {
    const knownHosts = new Map<string, string>();
    const seed = await connect(knownHosts, 'tofu');
    await seed.ensureConnected();
    await seed.close();

    const conn = await connect(knownHosts, 'strict');
    await expect(conn.ensureConnected()).resolves.not.toThrow();
    await conn.close();
  }, 30000);

  it('trustedHostKey pinning rejects a key that does not match the pin', async () => {
    const conn = await connect(new Map(), 'tofu', {
      trustedHostKey: 'SHA256:pinnedToSomethingElseAAAAAAAAAAAAAAAAAAAAAA',
    });
    // Named, because the change's whole claim about this path is that it stopped
    // being an anonymous handshake failure. This assertion passed identically
    // before and after while it read `rejects.toThrow()`.
    await expect(conn.ensureConnected()).rejects.toThrow(/HOST_KEY_PIN_MISMATCH/);
    await conn.close();
  }, 30000);

  it('strict mode connects with nothing but a matching pin', async () => {
    // The headline fix, and it had no coverage at this level: both pinning cases
    // here used `tofu`, where a matching pin reached a trust-on-first-use accept
    // on 2.7.0 and so passed before the change as well. This one cannot: an empty
    // store under `strict` is exactly the state that refused every host, so it
    // fails on 2.7.0 and on any regression that stops the pin reaching
    // verifyHostKey.
    const discovered = new Map<string, string>();
    const seed = await connect(discovered, 'tofu');
    await seed.ensureConnected();
    await seed.close();
    const real = discovered.get(`${profiles.admin.host}:${profiles.admin.port}`);
    expect(real).toBeDefined();

    const conn = await connect(new Map(), 'strict', { trustedHostKey: real });
    await expect(conn.ensureConnected()).resolves.not.toThrow();
    await conn.close();
  }, 30000);

  it('trustedHostKey pinning accepts the real key', async () => {
    const discovered = new Map<string, string>();
    const seed = await connect(discovered, 'tofu');
    await seed.ensureConnected();
    await seed.close();
    const realFingerprint = [...discovered.values()][0];

    const conn = await connect(new Map(), 'tofu', { trustedHostKey: realFingerprint });
    await expect(conn.ensureConnected()).resolves.not.toThrow();
    await conn.close();
  }, 30000);
});
