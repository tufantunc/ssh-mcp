import { describe, it, expect } from 'vitest';
import { FROZEN_ALGORITHMS } from '../../../src/ssh/algorithms.js';

describe('FROZEN_ALGORITHMS — security policy', () => {
  it('does not include ssh-rsa in serverHostKey', () => {
    expect(FROZEN_ALGORITHMS.serverHostKey).not.toContain('ssh-rsa');
  });

  it('does not include ssh-dss in serverHostKey', () => {
    expect(FROZEN_ALGORITHMS.serverHostKey).not.toContain('ssh-dss');
  });

  it('includes rsa-sha2-256 and rsa-sha2-512', () => {
    expect(FROZEN_ALGORITHMS.serverHostKey).toContain('rsa-sha2-256');
    expect(FROZEN_ALGORITHMS.serverHostKey).toContain('rsa-sha2-512');
  });

  it('includes ssh-ed25519', () => {
    expect(FROZEN_ALGORITHMS.serverHostKey).toContain('ssh-ed25519');
  });

  it('does not include SHA-1 based MACs', () => {
    for (const mac of FROZEN_ALGORITHMS.hmac) {
      expect(mac).not.toMatch(/sha1/i);
    }
  });

  it('does not include CBC ciphers', () => {
    for (const cipher of FROZEN_ALGORITHMS.cipher) {
      expect(cipher).not.toMatch(/cbc/i);
    }
  });

  it('does not include RC4 or 3DES', () => {
    for (const cipher of FROZEN_ALGORITHMS.cipher) {
      expect(cipher).not.toMatch(/arcfour|3des/i);
    }
  });

  it('includes curve25519-sha256 in kex', () => {
    expect(FROZEN_ALGORITHMS.kex).toContain('curve25519-sha256');
  });

  it('includes diffie-hellman-group14-sha256 in kex', () => {
    expect(FROZEN_ALGORITHMS.kex).toContain('diffie-hellman-group14-sha256');
  });
});
