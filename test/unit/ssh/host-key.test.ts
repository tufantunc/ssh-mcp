import { describe, it, expect } from 'vitest';
import { verifyHostKey, fingerprintPublicKey } from '../../../src/ssh/host-key.js';

describe('verifyHostKey', () => {
  it('accepts a key that matches known_hosts', () => {
    const knownHosts = new Map([['example.com:22', 'SHA256:abc123']]);
    expect(verifyHostKey('example.com', 22, 'SHA256:abc123', knownHosts, 'tofu')).toBe(true);
  });

  it('rejects a key that does not match known_hosts', () => {
    const knownHosts = new Map([['example.com:22', 'SHA256:abc123']]);
    expect(() => verifyHostKey('example.com', 22, 'SHA256:different', knownHosts, 'tofu')).toThrow(
      /HOST_KEY_MISMATCH/,
    );
  });

  it('accepts and records a new key in TOFU mode', () => {
    const knownHosts = new Map<string, string>();
    const result = verifyHostKey('newhost.com', 22, 'SHA256:newkey', knownHosts, 'tofu');
    expect(result).toBe(true);
    expect(knownHosts.get('newhost.com:22')).toBe('SHA256:newkey');
  });

  it('rejects an unknown host in strict mode', () => {
    const knownHosts = new Map<string, string>();
    // Distinct from HOST_KEY_MISMATCH: nothing changed, the host is simply not
    // known yet. The message must also point at a flag that actually exists.
    expect(() => verifyHostKey('newhost.com', 22, 'SHA256:newkey', knownHosts, 'strict')).toThrow(
      /HOST_KEY_UNKNOWN/,
    );
    expect(() => verifyHostKey('newhost.com', 22, 'SHA256:newkey', knownHosts, 'strict')).toThrow(
      /--hostKeyMode=tofu/,
    );
  });

  it('always accepts in insecure mode', () => {
    const knownHosts = new Map<string, string>();
    expect(verifyHostKey('any.com', 22, 'SHA256:whatever', knownHosts, 'insecure')).toBe(true);
  });

  it('uses non-default port in key lookup', () => {
    const knownHosts = new Map([['example.com:2222', 'SHA256:abc']]);
    expect(verifyHostKey('example.com', 2222, 'SHA256:abc', knownHosts, 'tofu')).toBe(true);
  });
});

/**
 * `--hostKeyMode=strict` refused every host on every connection until 2.8.0.
 *
 * The store it consults is in-memory and lives for the process, and the only
 * write to it sat *below* the strict throw — so under strict it started empty
 * and stayed empty. Measured on 2.7.0: two consecutive calls both threw with
 * `knownHosts.size === 0`, while tofu populated it on the first call. A pin did
 * not help either, because it was a reject-only gate in `connection.ts` that
 * fell through to this function and threw anyway. So strict plus a correct pin —
 * the combination that reads like the secure configuration — connected to
 * nothing, and the refusal's own advice ("pin the key with trustedHostKey") was
 * the advice that did not work.
 *
 * A pin is now the authority for the host it names, and is deliberately kept
 * *out* of the shared store rather than seeding it: `knownHostsStore` is one Map
 * for every profile (connection-registry.ts), so seeding meant two profiles
 * pinning different keys for the same host:port produced a false
 * HOST_KEY_MISMATCH against each other's entry. A pinned host needs no
 * trust-on-first-use memory — the pin already is that memory, and it outranks it.
 */
describe('verifyHostKey with a pinned key', () => {
  const PIN = 'SHA256:pinnedkeypinnedkeypinnedkeypinnedkeypinne';
  const OTHER = 'SHA256:otherkeyotherkeyotherkeyotherkeyotherkeyo';

  it('satisfies strict mode, which is the whole point', () => {
    const knownHosts = new Map<string, string>();
    expect(verifyHostKey('pinned.com', 22, PIN, knownHosts, 'strict', PIN)).toBe(true);
  });

  it('still refuses an unpinned unknown host under strict', () => {
    // The fix must not turn strict into tofu for hosts nobody pinned.
    const knownHosts = new Map<string, string>();
    expect(() => verifyHostKey('bare.com', 22, OTHER, knownHosts, 'strict')).toThrow(
      /HOST_KEY_UNKNOWN/,
    );
    expect(knownHosts.size).toBe(0);
  });

  it('refuses a key that contradicts the pin, in every mode including insecure', () => {
    // Ordering, not decoration. The pin check has to run BEFORE the insecure
    // early return: the reject-only gate this replaces sat in connection.ts
    // ahead of this function, so a mismatched pin refused even under insecure.
    // Putting the pin branch after `mode === 'insecure'` would silently drop
    // that, which is the one way this change could have been a regression.
    for (const mode of ['strict', 'tofu', 'insecure'] as const) {
      expect(() => verifyHostKey('pinned.com', 22, OTHER, new Map(), mode, PIN)).toThrow(
        /HOST_KEY_PIN_MISMATCH/,
      );
    }
  });

  it('names the pin as what decided, and does not offer a way to switch it off', () => {
    // Same standard as the two refusals next door (see message-quality.test.ts):
    // a refusal has to say what decided and how to proceed, without pointing at
    // the least safe exit. Here the operator edits the pin or investigates; there
    // is no mode that overrides a pin, and the message must not imply one.
    const refused = () => verifyHostKey('pinned.com', 22, OTHER, new Map(), 'tofu', PIN);
    expect(refused).toThrow(/trustedHostKey/);
    expect(refused).toThrow(new RegExp(PIN));
    expect(refused).toThrow(new RegExp(OTHER));
    expect(refused).not.toThrow(/--insecureHostKey|--hostKeyMode=insecure/);
  });

  it('does not write a pinned host into the shared store', () => {
    // What makes the cross-profile collision impossible. If this ever records,
    // a second profile pinning a different key for the same host:port starts
    // failing with HOST_KEY_MISMATCH against an entry it never agreed to.
    const knownHosts = new Map<string, string>();
    verifyHostKey('pinned.com', 22, PIN, knownHosts, 'strict', PIN);
    expect(knownHosts.size).toBe(0);
  });

  it('lets the pin win over a stale store entry for the same host', () => {
    // Reachable with one shared store: profile A (tofu, no pin) learns a key,
    // profile B pins a different one for the same host:port. B must be judged
    // against its pin, not against A's memory.
    const knownHosts = new Map([['shared.com:22', OTHER]]);
    expect(verifyHostKey('shared.com', 22, PIN, knownHosts, 'strict', PIN)).toBe(true);
    expect(knownHosts.get('shared.com:22')).toBe(OTHER);
  });

  it('is inert when no pin is configured', () => {
    // undefined must not be read as "pin that matches nothing".
    const knownHosts = new Map<string, string>();
    expect(verifyHostKey('plain.com', 22, OTHER, knownHosts, 'tofu', undefined)).toBe(true);
    expect(knownHosts.get('plain.com:22')).toBe(OTHER);
  });
});

describe('fingerprintPublicKey', () => {
  it('produces a deterministic SHA256 fingerprint', () => {
    const key = Buffer.from('fake-key-data');
    const fp = fingerprintPublicKey(key);
    expect(fp).toMatch(/^SHA256:/);
    expect(fp).toBe(fingerprintPublicKey(key));
  });

  it('produces different fingerprints for different keys', () => {
    const fp1 = fingerprintPublicKey(Buffer.from('key-one'));
    const fp2 = fingerprintPublicKey(Buffer.from('key-two'));
    expect(fp1).not.toBe(fp2);
  });
});
