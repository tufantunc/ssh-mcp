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

  it('redacts quoted attached -p passwords that contain whitespace', () => {
    // Quote *after* -p: `mysql -p"secret with space"` / `-p'secret with space'`.
    const afterDouble = redact('mysql -p"secret with space"');
    expect(afterDouble).toContain(`-p"${R}"`);
    expect(afterDouble).not.toContain('secret with space');

    const afterSingle = redact("mysql -p'secret with space'");
    expect(afterSingle).toContain(`-p'${R}'`);
    expect(afterSingle).not.toContain('secret with space');

    // Whole arg quoted (quote *before* -p): `'-psecret with space'`.
    const wholeSingle = redact("mysql '-psecret with space'");
    expect(wholeSingle).toContain(`'-p${R}'`);
    expect(wholeSingle).not.toContain('secret with space');

    const wholeDouble = redact('mysql "-psecret with space"');
    expect(wholeDouble).toContain(`"-p${R}"`);
    expect(wholeDouble).not.toContain('secret with space');

    // A later plain attached form on the same line still redacts too.
    const mixed = redact('mysql -p"a b" && mysqldump -pplain');
    expect(mixed).not.toContain('a b');
    expect(mixed).not.toContain('plain');
    expect(mixed).toContain(`mysqldump -p${R}`);
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

  it('redacts dangling PEM private keys in command metadata', () => {
    const begin = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----';
    const out = redact(`ssh-add ${begin}\nraw-key-material-without-terminator`);
    expect(out).toContain(R);
    expect(out).not.toContain('raw-key-material');
    expect(out).not.toContain('PRIVATE KEY');
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

  it('redacts classic and fine-grained GitHub PATs', () => {
    const classic = 'ghp_' + 'A'.repeat(36);
    const fineGrained = 'github_pat_' + 'B'.repeat(22) + '_' + 'C'.repeat(59);
    const out = redact(`token ${classic} other ${fineGrained} end`);
    expect(out).not.toContain(classic);
    expect(out).not.toContain(fineGrained);
    expect((out.match(/<redacted>/g) ?? []).length).toBeGreaterThanOrEqual(2);
  });

  it('redacts a fine-grained PAT embedded in a remote URL', () => {
    const fineGrained = 'github_pat_' + 'D'.repeat(22) + '_' + 'E'.repeat(59);
    const url = `https://x-access-token:${fineGrained}@github.com/owner/repo.git`;
    const out = redact(`git clone ${url}`);
    expect(out).not.toContain(fineGrained);
    expect(out).toContain('<redacted>');
  });
});
