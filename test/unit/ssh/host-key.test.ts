import { describe, it, expect } from 'vitest';
import { verifyHostKey, fingerprintPublicKey } from '../../../src/ssh/host-key.js';

describe('verifyHostKey', () => {
  it('accepts a key that matches known_hosts', () => {
    const knownHosts = new Map([['example.com:22', 'SHA256:abc123']]);
    expect(verifyHostKey('example.com', 22, 'SHA256:abc123', knownHosts, 'tofu', undefined)).toBe(true);
  });

  it('rejects a key that does not match known_hosts', () => {
    const knownHosts = new Map([['example.com:22', 'SHA256:abc123']]);
    expect(() => verifyHostKey('example.com', 22, 'SHA256:different', knownHosts, 'tofu', undefined)).toThrow(
      /HOST_KEY_MISMATCH/,
    );
  });

  it('accepts and records a new key in TOFU mode', () => {
    const knownHosts = new Map<string, string>();
    const result = verifyHostKey('newhost.com', 22, 'SHA256:newkey', knownHosts, 'tofu', undefined);
    expect(result).toBe(true);
    expect(knownHosts.get('newhost.com:22')).toBe('SHA256:newkey');
  });

  it('rejects an unknown host in strict mode', () => {
    const knownHosts = new Map<string, string>();
    // Distinct from HOST_KEY_MISMATCH: nothing changed, the host is simply not
    // known yet. The message must also point at a flag that actually exists.
    expect(() => verifyHostKey('newhost.com', 22, 'SHA256:newkey', knownHosts, 'strict', undefined)).toThrow(
      /HOST_KEY_UNKNOWN/,
    );
    expect(() => verifyHostKey('newhost.com', 22, 'SHA256:newkey', knownHosts, 'strict', undefined)).toThrow(
      /--hostKeyMode=tofu/,
    );
  });

  it('always accepts in insecure mode', () => {
    const knownHosts = new Map<string, string>();
    expect(verifyHostKey('any.com', 22, 'SHA256:whatever', knownHosts, 'insecure', undefined)).toBe(true);
  });

  it('uses non-default port in key lookup', () => {
    const knownHosts = new Map([['example.com:2222', 'SHA256:abc']]);
    expect(verifyHostKey('example.com', 2222, 'SHA256:abc', knownHosts, 'tofu', undefined)).toBe(true);
  });
});

/**
 * `--hostKeyMode=strict` refused every host on every connection until 2.8.0, and a
 * pin could not satisfy it. The history is in .changeset/lucky-keys-pinned.md; what
 * these cases pin is the shape the fix left behind.
 *
 * Two properties here would regress silently if they were not asserted: the pin
 * branch sitting ahead of the `insecure` early return, and the store being written
 * under `tofu` but not under `strict`. Both are measured, not argued — reordering
 * the branch fails the insecure case, and moving the write fails the two store cases.
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
    expect(() => verifyHostKey('bare.com', 22, OTHER, knownHosts, 'strict', undefined)).toThrow(
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

  it('records a pinned key under tofu, so an unpinned sibling profile is still compared', () => {
    // Dropping this write was a draft of the fix and it cost a real refusal.
    // The store is one Map for every profile, so on 2.7.0 a pinned profile seeded
    // it and an unpinned profile on the same host:port was checked against a
    // pin-verified fingerprint. Without the write that profile trust-on-first-uses
    // whatever it is served — and the store then holds the attacker's key, so the
    // next connection served the genuine one is refused with the diagnostic naming
    // the real server as the impostor.
    const knownHosts = new Map<string, string>();
    verifyHostKey('shared.com', 22, PIN, knownHosts, 'tofu', PIN);
    expect(knownHosts.get('shared.com:22')).toBe(PIN);

    // The sibling, unpinned, served something else.
    expect(() => verifyHostKey('shared.com', 22, OTHER, knownHosts, 'tofu', undefined)).toThrow(
      /HOST_KEY_MISMATCH/,
    );
  });

  it('does not record under strict, so one profile\'s pin cannot authorise another', () => {
    // The store is what an *unpinned* profile consults, and under strict that is
    // the only thing that could let it through. Seeding it from a pin would mean
    // pinning one profile silently admitted every other profile to that host —
    // which is the guarantee strict exists to make.
    const knownHosts = new Map<string, string>();
    verifyHostKey('shared.com', 22, PIN, knownHosts, 'strict', PIN);
    expect(knownHosts.size).toBe(0);
    expect(() => verifyHostKey('shared.com', 22, PIN, knownHosts, 'strict', undefined)).toThrow(
      /HOST_KEY_UNKNOWN/,
    );
  });

  it('does not record under insecure either, matching what it replaced', () => {
    const knownHosts = new Map<string, string>();
    verifyHostKey('shared.com', 22, PIN, knownHosts, 'insecure', PIN);
    expect(knownHosts.size).toBe(0);
  });

  it('lets the pin win over a stale store entry for the same host', () => {
    // The store entry has to be stale relative to what the host presents *now* —
    // an earlier tofu connection learned a key the host has since rotated away
    // from, or learned one from an interceptor. Two profiles merely pinning
    // different keys does not reach here: whichever pin disagrees with the served
    // key is stopped by the branch above and never sees the store.
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

  it('treats an empty pin as no pin, not as a pin nothing can match', () => {
    // A regression this change nearly shipped. The gate it replaced tested
    // truthiness, so `trustedHostKey = ""` was inert on 2.7.0; a `!== undefined`
    // predicate turned the same config into "refuse every host on every
    // connection" — fail-closed, but a config that worked would have stopped
    // working. The schema rejects a blank pin now, so this asserts the runtime
    // half of a two-layer guard.
    const knownHosts = new Map<string, string>();
    expect(verifyHostKey('plain.com', 22, OTHER, knownHosts, 'tofu', '')).toBe(true);
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
