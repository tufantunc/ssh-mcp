import { describe, it, expect } from 'vitest';
import { redactText, redactRecord } from '../../../src/guard/redactor.js';

describe('redactText', () => {
  it('masks AWS access keys', () => {
    const result = redactText('key=AKIAIOSFODNN7EXAMPLE');
    expect(result).toContain('[REDACTED:aws-access-key');
    expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('masks GitHub tokens', () => {
    const result = redactText('token: ghp_1234567890abcdefghijklmnopqrstuvwxyz');
    expect(result).toContain('[REDACTED:github-token');
  });

  it('masks PEM private key blocks', () => {
    const pem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFakeKey123
-----END PRIVATE KEY-----`;
    const result = redactText(pem);
    expect(result).toContain('[REDACTED:pem-private-key');
  });

  it('masks JWT tokens', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const result = redactText(jwt);
    expect(result).toContain('[REDACTED:jwt');
  });

  it('masks GitLab tokens', () => {
    const result = redactText('token: glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234');
    expect(result).toContain('[REDACTED:gitlab-token');
    expect(result).not.toContain('glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234');
  });

  it('masks Bearer auth headers', () => {
    const result = redactText('Authorization: Bearer dGhpcyBpcyBhIHRva2Vu');
    expect(result).toContain('[REDACTED:bearer-auth');
    expect(result).not.toContain('dGhpcyBpcyBhIHRva2Vu');
  });

  it('masks generic api_key assignments', () => {
    const result = redactText('api_key = "0123456789abcdef0123456789"');
    expect(result).toContain('[REDACTED:generic-api-key');
  });

  it('leaves normal text unchanged', () => {
    expect(redactText('ls -la /var/log/syslog')).toBe('ls -la /var/log/syslog');
  });

  it('entropy scan masks high-entropy strings', () => {
    const random = 'xK7pQ2mNvR4wL8jF3hB6cY1dZ5aG0tS9eU';
    const result = redactText(random, { entropyScan: true });
    expect(result).toContain('[REDACTED:entropy');
  });

  it('entropy scan preserves low-entropy long strings', () => {
    const lowEntropy = 'a'.repeat(40);
    const result = redactText(lowEntropy, { entropyScan: true });
    expect(result).toBe(lowEntropy);
  });

  it('entropy scan off leaves base64 unchanged', () => {
    const base64 = Buffer.from('a'.repeat(50)).toString('base64');
    const result = redactText(base64);
    expect(result).toBe(base64);
  });
});

describe('redactRecord', () => {
  it('redacts sensitive fields', () => {
    const result = redactRecord({
      host: 'example.com',
      password: 'secret123',
      privateKey: '-----BEGIN...',
      user: 'deploy',
    });
    expect(result.password).toBe('[REDACTED]');
    expect(result.privateKey).toBe('[REDACTED]');
    expect(result.host).toBe('example.com');
    expect(result.user).toBe('deploy');
  });

  it('redacts nested objects', () => {
    const result = redactRecord({
      config: { apiKey: 'abc', port: 22 },
    });
    expect(result.config.apiKey).toBe('[REDACTED]');
    expect(result.config.port).toBe(22);
  });

  it('redacts fields matching token/secret/key pattern', () => {
    const result = redactRecord({
      apiToken: 'xyz',
      dbSecret: 'abc',
      signingKey: 'def',
    });
    expect(result.apiToken).toBe('[REDACTED]');
    expect(result.dbSecret).toBe('[REDACTED]');
    expect(result.signingKey).toBe('[REDACTED]');
  });
});

describe('literal secrets (GHSA-9m75-x2ch-j4jr)', () => {
  it('masks a configured secret verbatim regardless of length or entropy', () => {
    // Short, low-entropy, no token shape: nothing else in the redactor could
    // catch it, which is exactly how the sudo password leaked.
    const result = redactText('leak: Canary-PW-77\n', { literalSecrets: ['Canary-PW-77'] });
    expect(result).toBe('leak: [REDACTED:secret:12]\n');
  });

  it('masks every occurrence, in stdout-sized text', () => {
    const result = redactText('a sudo-secret b sudo-secret c', { literalSecrets: ['sudo-secret'] });
    expect(result).toBe('a [REDACTED:secret:11] b [REDACTED:secret:11] c');
  });

  it('ignores values too short to scrub safely', () => {
    // A 1–3 character "secret" would shred ordinary output — every line
    // containing the letter it happens to be. The wrapper, not the redactor,
    // is the layer that keeps such values out of output.
    const result = redactText('cat dog', { literalSecrets: ['dog', 'a', ''] });
    expect(result).toBe('cat dog');
  });
});
