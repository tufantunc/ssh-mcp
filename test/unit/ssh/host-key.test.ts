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
