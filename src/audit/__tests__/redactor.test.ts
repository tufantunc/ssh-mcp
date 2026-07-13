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

  it('redacts unterminated quoted attached -p passwords', () => {
    const doubleQuoted = redact('mysql -p"unterminated double quote');
    expect(doubleQuoted).toContain(`mysql -p${R}`);
    expect(doubleQuoted).not.toContain('unterminated');

    const singleQuoted = redact("mariadb -p'unterminated single quote");
    expect(singleQuoted).toContain(`mariadb -p${R}`);
    expect(singleQuoted).not.toContain('unterminated');
  });

  it('redacts JSON/TOML-ish secret values', () => {
    const out = redact('{"password":"pw","nested_token":"tok","safe":"ok"}\napi_key = "abc"\ntoken abc');
    expect(out).toContain(`"password":"${R}"`);
    expect(out).toContain(`"nested_token":"${R}"`);
    expect(out).toContain(`api_key = ${R}`);
    expect(out).toContain(`token ${R}`);
    expect(out).toContain('"safe":"ok"');
  });

  it('treats passphrase flags, fields, assignments, and prose as secrets', () => {
    const input = [
      '--passphrase=flag-value',
      'SSH_PASSPHRASE=env-value',
      'key_passphrase = "field-value"',
      '{"passphrase":"json-value"}',
      'passphrase prose-value',
    ].join(' ');
    const out = redact(input);

    expect((out.match(/<redacted>/g) ?? []).length).toBeGreaterThanOrEqual(5);
    for (const value of ['flag-value', 'env-value', 'field-value', 'json-value', 'prose-value']) {
      expect(out).not.toContain(value);
    }
  });

  it('consumes tildes as part of bearer tokens', () => {
    const out = redact('Authorization: Bearer abc~def~ghi next');
    expect(out).toContain(`Authorization: Bearer ${R} next`);
    expect(out).not.toContain('~def');
    expect(out).not.toContain('~ghi');
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
    const url = 'https://' + 'x-access-token' + ':' + fineGrained + '@' + 'github.com/owner/repo.git';
    const out = redact(`git clone ${url}`);
    expect(out).not.toContain(fineGrained);
    expect(out).toContain('<redacted>');
  });

  it('redacts a dangling PEM header with no matching END marker (Codex 3541772951)', () => {
    // A truncated pasted key / here-doc command text carries a BEGIN header
    // without an END terminator; the main redact() path must still scrub it.
    const dangling = [
      'cat <<EOF',
      '-----BEGIN ' + 'RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEA' + 'x'.repeat(40),
      'more-secret-key-bytes-with-no-end-marker',
    ].join('\n');
    const out = redact(dangling);
    expect(out).toContain(R);
    expect(out).not.toContain('MIIEowIBAAKCAQEA');
    expect(out).not.toContain('more-secret-key-bytes-with-no-end-marker');
  });

  it('redacts URL userinfo passwords while preserving scheme/user/host (Codex 3541772956)', () => {
    const httpUrl = 'https://alice:hunter2@example.com/repo.git';
    const dbUrl = 'postgres://dbuser:s3cr3tpw@db.internal:5432/app';
    const out = redact(`git clone ${httpUrl} && psql ${dbUrl}`);
    // Passwords gone.
    expect(out).not.toContain('hunter2');
    expect(out).not.toContain('s3cr3tpw');
    // Structure preserved.
    expect(out).toContain(`https://alice:${R}@example.com/repo.git`);
    expect(out).toContain(`postgres://dbuser:${R}@db.internal:5432/app`);
  });

  it('does not touch a URL with no userinfo credentials', () => {
    const url = 'https://example.com/path?query=1';
    expect(redact(url)).toBe(url);
  });

  it('redacts quoted CLI secrets that contain escaped quotes', () => {
    const input = [
      'ssh --password="abc\\"def"',
      "--api-key 'one\\'two'",
      'token "tok\\"next"',
    ].join(' ');
    const out = redact(input);

    expect(out).toContain(`--password=${R}`);
    expect(out).toContain(`--api-key ${R}`);
    expect(out).toContain(`token ${R}`);
    expect(out).not.toContain('abc');
    expect(out).not.toContain('def');
    expect(out).not.toContain('one');
    expect(out).not.toContain('two');
    expect(out).not.toContain('next');
  });
});
