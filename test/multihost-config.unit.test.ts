import { describe, it, expect } from 'vitest';
import { parseServerConfigJson, validateConfig } from '../src/index';

// Unit tests for the multi-host (--ssh=<JSON>) config layer. Imported from
// src/index, which is safe because the runner sets SSH_MCP_DISABLE_MAIN=1
// (isCliEnabled=false) so no server/CLI side effects run on import.

describe('parseServerConfigJson (happy path)', () => {
  it('parses a password/ssh2 config with name/host/user', () => {
    const cfg = parseServerConfigJson(JSON.stringify({
      name: 'web1', host: 'web1.example', user: 'deploy', auth: 'password', password: 'pw',
    }));
    expect(cfg.name).toBe('web1');
    expect(cfg.transport).toBe('ssh2');
    expect(cfg.authMode).toBe('password');
    expect(cfg.password).toBe('pw');
    expect(cfg.port).toBe(22);
  });

  it('accepts "username" as an alias for "user"', () => {
    const cfg = parseServerConfigJson(JSON.stringify({
      name: 'k', host: 'k.example', username: 'svc', auth: 'kerberos',
    }));
    expect(cfg.username).toBe('svc');
    expect(cfg.transport).toBe('openssh');
    expect(cfg.kerberos).toBe(true);
  });

  it('throws on missing name / host / user / auth', () => {
    expect(() => parseServerConfigJson('{}')).toThrow(/non-empty string "name"/);
    expect(() => parseServerConfigJson(JSON.stringify({ name: 'a' }))).toThrow(/missing required "host"/);
    expect(() => parseServerConfigJson(JSON.stringify({ name: 'a', host: 'h' }))).toThrow(/missing required "user"/);
    expect(() => parseServerConfigJson(JSON.stringify({ name: 'a', host: 'h', user: 'u' }))).toThrow(/requires "auth"/);
  });

  it('throws on invalid JSON', () => {
    expect(() => parseServerConfigJson('{not json')).toThrow(/--ssh JSON parse error/);
  });
});

describe('parseServerConfigJson (finding 4: ssh2 must not silently drop host-key enforcement)', () => {
  it('rejects strictHostKeyChecking on an ssh2 (default) key config', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'h', host: 'h', user: 'u', auth: 'key', keyPath: '/k', strictHostKeyChecking: 'yes',
    }))).toThrow(/require "transport": "openssh"/);
  });

  it('rejects knownHostsFile on an ssh2 (default) password config', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'h', host: 'h', user: 'u', auth: 'password', password: 'pw', knownHostsFile: '/tmp/known',
    }))).toThrow(/require "transport": "openssh"/);
  });

  it('accepts strictHostKeyChecking when transport is explicitly openssh', () => {
    const cfg = parseServerConfigJson(JSON.stringify({
      name: 'h', host: 'h', user: 'u', auth: 'key', keyPath: '/k', transport: 'openssh', strictHostKeyChecking: 'yes',
    }));
    expect(cfg.transport).toBe('openssh');
    expect(cfg.strictHostKeyChecking).toBe('yes');
  });

  it('accepts knownHostsFile for a kerberos config (implies openssh)', () => {
    const cfg = parseServerConfigJson(JSON.stringify({
      name: 'h', host: 'h', user: 'u', auth: 'kerberos', knownHostsFile: '/tmp/known',
    }));
    expect(cfg.transport).toBe('openssh');
    expect(cfg.knownHostsFile).toBe('/tmp/known');
  });
});

describe('parseServerConfigJson (round-2: input validation hardening)', () => {
  it('does not echo the raw config in a JSON parse error (no secret leak)', () => {
    const raw = '{"name":"x","password":"s3cret",}'; // trailing comma -> parse error
    try {
      parseServerConfigJson(raw);
      throw new Error('expected parse to throw');
    } catch (e: any) {
      expect(e.message).toMatch(/--ssh JSON parse error/);
      expect(e.message).not.toMatch(/s3cret/);
    }
  });

  it('requires name to be a non-empty string (rejects numeric name)', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 1, host: 'h', user: 'u', auth: 'password', password: 'pw',
    }))).toThrow(/non-empty string "name"/);
    expect(() => parseServerConfigJson(JSON.stringify({
      name: '', host: 'h', user: 'u', auth: 'password', password: 'pw',
    }))).toThrow(/non-empty string "name"/);
  });

  it('rejects a non-integer / out-of-range port', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'password', password: 'pw', port: 'abc',
    }))).toThrow(/invalid "port"/);
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'password', password: 'pw', port: 70000,
    }))).toThrow(/invalid "port"/);
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'password', password: 'pw', port: 0,
    }))).toThrow(/invalid "port"/);
  });

  it('accepts a valid numeric port (and a numeric-string port)', () => {
    expect(parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'password', password: 'pw', port: 2222,
    })).port).toBe(2222);
    expect(parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'password', password: 'pw', port: '2200',
    })).port).toBe(2200);
  });

  it('rejects an invalid transport value (typo)', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'key', keyPath: '/k', transport: 'opnssh',
    }))).toThrow(/invalid "transport"/);
  });

  it('rejects a kerberos config whose explicit transport is not openssh', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'kerberos', transport: 'ssh2',
    }))).toThrow(/implies transport "openssh"/);
  });

  it('rejects an inline privateKey for an openssh key config (buildArgs ignores it)', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'key', transport: 'openssh', privateKey: '-----BEGIN...',
    }))).toThrow(/inline "privateKey" is not supported for transport "openssh"/);
  });

  it('still accepts an inline privateKey for an ssh2 key config', () => {
    const cfg = parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'key', privateKey: '-----BEGIN...',
    }));
    expect(cfg.transport).toBe('ssh2');
    expect(cfg.privateKey).toBe('-----BEGIN...');
  });

  it('rejects an invalid gssapiDelegateCredentials value', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'kerberos', gssapiDelegateCredentials: 'maybe',
    }))).toThrow(/gssapiDelegateCredentials must be "yes" or "no"/);
  });

  it('rejects gssapiDelegateCredentials on a non-kerberos config', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'password', password: 'pw', gssapiDelegateCredentials: 'yes',
    }))).toThrow(/gssapiDelegateCredentials requires auth "kerberos"/);
  });

  it('accepts a valid gssapiDelegateCredentials on a kerberos config', () => {
    const cfg = parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'kerberos', gssapiDelegateCredentials: 'yes',
    }));
    expect(cfg.gssapiDelegateCredentials).toBe('yes');
  });

  it('rejects an invalid strictHostKeyChecking value (on an openssh config)', () => {
    expect(() => parseServerConfigJson(JSON.stringify({
      name: 'n', host: 'h', user: 'u', auth: 'key', keyPath: '/k', transport: 'openssh', strictHostKeyChecking: 'maybe',
    }))).toThrow(/strictHostKeyChecking must be one of: yes, no, accept-new/);
  });
});

describe('validateConfig multi-host (finding 2: legacy flags must be rejected)', () => {
  it('rejects --port mixed with --ssh', () => {
    expect(() => validateConfig({ port: '2222' }, true)).toThrow(/cannot be mixed with legacy single-host flags/);
  });

  it('rejects --sudoPassword mixed with --ssh', () => {
    expect(() => validateConfig({ sudoPassword: 'x' }, true)).toThrow(/cannot be mixed with legacy single-host flags/);
  });

  it('rejects --suPassword mixed with --ssh', () => {
    expect(() => validateConfig({ suPassword: 'x' }, true)).toThrow(/cannot be mixed with legacy single-host flags/);
  });

  it('names the offending flag(s) in the error', () => {
    expect(() => validateConfig({ port: '2222', sudoPassword: 'x' }, true)).toThrow(/--port/);
    expect(() => validateConfig({ port: '2222', sudoPassword: 'x' }, true)).toThrow(/--sudoPassword/);
  });

  it('passes for a clean multi-host invocation (no legacy flags)', () => {
    expect(() => validateConfig({}, true)).not.toThrow();
  });
});
