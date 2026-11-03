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

describe('assignment masking (GHSA-95pj-qcm9-m3m9)', () => {
  it('masks short low-entropy credentials under sensitive field names', () => {
    // The reported gap: every value-keyed layer (token shapes, entropy,
    // literals) whiffs on a 6-char value; only the field name says "secret".
    expect(redactText('webhook_token=abc123', { entropyScan: true }))
      .toBe('webhook_token=[REDACTED:assignment:6]');
    expect(redactText('password="demo123"', { entropyScan: true }))
      .toBe('password="[REDACTED:assignment:7]"');
    expect(redactText("option wifi_psk 'sample123'", { entropyScan: true }))
      .toBe("option wifi_psk '[REDACTED:assignment:9]'");
  });

  it('masks env-style and spaced assignments, preserving surroundings', () => {
    const input = [
      '# deployment config',
      'export DB_PASSWORD=hunter2',
      'listen=127.0.0.1',
      "client_secret = 'shhh'",
    ].join('\n');
    const expected = [
      '# deployment config',
      'export DB_PASSWORD=[REDACTED:assignment:7]',
      'listen=127.0.0.1',
      "client_secret = '[REDACTED:assignment:4]'",
    ].join('\n');
    expect(redactText(input)).toBe(expected);
  });

  it('masks UCI option/list lines and the exact wifi key name', () => {
    expect(redactText("option key 'wpa-passphrase'", { entropyScan: true }))
      .toBe("option key '[REDACTED:assignment:14]'");
    expect(redactText("option 'password' 'quoted-name'", { entropyScan: true }))
      .toBe("option 'password' '[REDACTED:assignment:11]'");
    expect(redactText("list server_password 'v@lue!'", { entropyScan: true }))
      .toBe("list server_password '[REDACTED:assignment:6]'");
    expect(redactText('option channel 36')).toBe('option channel 36');
  });

  it('masks known key compounds but not arbitrary key-suffixed settings', () => {
    expect(redactText('private_key="short1"')).toBe('private_key="[REDACTED:assignment:6]"');
    expect(redactText('api-key=topsecret')).toBe('api-key=[REDACTED:assignment:9]');
    expect(redactText('persist_key=no')).toBe('persist_key=no');
    expect(redactText('cache_key=v1')).toBe('cache_key=v1');
  });

  it('masks the field after uci-show dotted paths', () => {
    expect(redactText("wireless.default_radio0.key='secret123'"))
      .toBe("wireless.default_radio0.key='[REDACTED:assignment:9]'");
    expect(redactText("dhcp.lan.password_min_length=8"))
      .toBe("dhcp.lan.password_min_length=8");
  });

  it('masks token query parameters without touching the rest of the URL', () => {
    expect(redactText('https://x.example/cb?token=abc123&state=xyz'))
      .toBe('https://x.example/cb?token=[REDACTED:assignment:6]&state=xyz');
  });

  it('keeps trailing list separators out of the mask', () => {
    expect(redactText('password=abc123, reconnect=true'))
      .toBe('password=[REDACTED:assignment:6], reconnect=true');
  });

  it('leaves advisory-listed false positives untouched', () => {
    const input = [
      'password_min=8',
      'passwordauth=yes',
      'PasswordAuthentication=yes',
      'smtp_sasl_password_maps=hash:/etc/postfix/sasl_passwd',
    ].join('\n');
    expect(redactText(input, { entropyScan: true })).toBe(input);
  });

  it('leaves ordinary config and prose untouched', () => {
    const input = [
      'server_name=example.com',
      "list listen_addr '0.0.0.0'",
      'ssl_verify=on',
      'max_tokens=4096',
      'The option list contains four items.',
    ].join('\n');
    expect(redactText(input, { entropyScan: true })).toBe(input);
  });

  it('skips empty values', () => {
    expect(redactText('password=')).toBe('password=');
    expect(redactText('password=""')).toBe('password=""');
  });

  it('does not double-mask values already caught by earlier layers', () => {
    const patternResult = redactText('api_key = "0123456789abcdef0123456789"');
    expect(patternResult).toContain('[REDACTED:generic-api-key');
    expect(patternResult).not.toContain('assignment');

    const entropyResult = redactText('api_token=xK7pQ2mNvR4wL8jF3hB6cY1dZ5aG0tS9eU', { entropyScan: true });
    expect(entropyResult).toBe('[REDACTED:entropy:44]');
  });

  it('runs after literal secrets so prose occurrences stay masked', () => {
    // If assignment masking ran first, it would hide the only findable copy of
    // the secret and the literal layer would miss the prose mention.
    const result = redactText('password=hunter2 and prose hunter2', { literalSecrets: ['hunter2'] });
    expect(result).toBe('password=[REDACTED:secret:7] and prose [REDACTED:secret:7]');
  });
});
