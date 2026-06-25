import { describe, expect, it } from 'vitest';

import { redact, REDACTED_PLACEHOLDER } from '../redactor.js';

const R = REDACTED_PLACEHOLDER;

describe('audit redactor', () => {
  it('redacts password/token CLI shapes and env assignments', () => {
    const input = ['mysql -u root', '-p hunter2', '--password=secret', '--api-key "abc"', 'API_TOKEN=tok123'].join(' ');
    const out = redact(input);
    expect(out).toContain(`-p ${R}`);
    expect(out).toContain(`--password=${R}`);
    expect(out).toContain(`--api-key ${R}`);
    expect(out).toContain(`API_TOKEN=${R}`);
    expect(out).not.toContain('hunter2');
    expect(out).not.toContain('secret');
    expect(out).not.toContain('tok123');
  });

  it('redacts MySQL and MariaDB attached -pVALUE password args', () => {
    const input = [
      'mysql -uroot -psecret',
      'mysql --password=longsecret',
      'mysqldump -pdumpsecret',
      'mariadb "-pquotedsecret"',
      "mysql '-prepeated1' -prepeated2",
    ].join(' && ');

    const out = redact(input);

    expect(out).toContain(`mysql -uroot -p${R}`);
    expect(out).toContain(`mysql --password=${R}`);
    expect(out).toContain(`mysqldump -p${R}`);
    expect(out).toContain(`mariadb "-p${R}"`);
    expect(out).toContain(`mysql '-p${R}' -p${R}`);
    expect(out).not.toContain('secret');
    expect(out).not.toContain('repeated');
  });

  it('does not redact bare MySQL -p prompt form', () => {
    expect(redact('mysql -p')).toBe('mysql -p');
  });

  it('redacts JSON/TOML-ish secret values', () => {
    const out = redact('{"password":"pw","nested_token":"tok","safe":"ok"}\napi_key = "abc"\ntoken abc');
    expect(out).toContain(`"password":"${R}"`);
    expect(out).toContain(`"nested_token":"${R}"`);
    expect(out).toContain(`api_key = ${R}`);
    expect(out).toContain(`token ${R}`);
    expect(out).toContain('"safe":"ok"');
  });

  it('redacts PEM private keys', () => {
    const pem = [
      '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----',
      'abc123',
      '-----END ' + 'OPENSSH PRIVATE KEY-----',
    ].join('\n');
    const out = redact(`key\n${pem}\nend`);
    expect(out).toContain(R);
    expect(out).not.toContain('abc123');
  });

  it('redacts AWS key id / secret hint and JWT shapes', () => {
    const awsKey = 'AKIA' + 'A'.repeat(16);
    const awsSecret = 'a'.repeat(40);
    const jwt = ['eyJ' + 'a'.repeat(12), 'eyJ' + 'b'.repeat(12), 'c'.repeat(12)].join('.');
    const text = `${awsKey} aws_secret_access_key=${awsSecret} ${jwt}`;
    const out = redact(text);
    expect(out).not.toContain(awsKey);
    expect(out).not.toContain(awsSecret);
    expect(out).not.toContain(jwt);
    expect((out.match(/<redacted>/g) ?? []).length).toBeGreaterThanOrEqual(3);
  });
});
