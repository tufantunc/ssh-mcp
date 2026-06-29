import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'crypto';
import {
  sanitizeDescription,
  sentinelEcho,
  sshKeyFingerprintSha256,
  matchesFingerprint,
  knownHostsHasKey,
  verifyHostKeySync,
} from '../src/index';

// A fixed, arbitrary "host key" buffer. The verification helpers treat the key as
// opaque bytes, so any buffer exercises the logic faithfully.
const KEY = Buffer.from('this-is-a-fake-host-key-blob-0123456789', 'utf8');
const OTHER_KEY = Buffer.from('a-different-host-key-blob-9876543210', 'utf8');

const sha256b64 = (buf: Buffer) => createHash('sha256').update(buf).digest('base64').replace(/=+$/, '');
const md5hex = (buf: Buffer) => createHash('md5').update(buf).digest('hex');

describe('sanitizeDescription (#5 newline injection)', () => {
  it('strips newlines so the comment cannot break into a new command', () => {
    expect(sanitizeDescription('safe\nrm -rf /')).toBe('safe rm -rf /');
    expect(sanitizeDescription('a\r\nb\nc')).toBe('a b c');
  });

  it('still escapes # and trims', () => {
    expect(sanitizeDescription('  has # hash  ')).toBe('has \\# hash');
  });

  it('contains no CR or LF for any input', () => {
    const out = sanitizeDescription('x\n\n\ry\r\rz\n');
    expect(out).not.toMatch(/[\r\n]/);
  });
});

describe('sentinelEcho (#4 robust command fencing)', () => {
  it('splits the literal so the marker is absent from the echoed input', () => {
    const cmd = sentinelEcho('BEGIN', 'tok1');
    // The literal sentinel must NOT appear in the command text (the PTY echoes this)...
    expect(cmd).not.toContain('SSH_MCP_BEGIN_tok1');
    // ...but the printf output WILL be the joined sentinel.
    expect(cmd).toContain('SSH_MCP""_BEGIN_tok1');
  });

  it('appends a suffix (e.g. the exit code expansion)', () => {
    expect(sentinelEcho('END', 'tok2', ':$__rc')).toContain('_END_tok2:$__rc');
  });
});

describe('sshKeyFingerprintSha256', () => {
  it('matches OpenSSH SHA256 fingerprint format', () => {
    expect(sshKeyFingerprintSha256(KEY)).toBe('SHA256:' + sha256b64(KEY));
  });
});

describe('matchesFingerprint (#1 pinned fingerprint)', () => {
  it('accepts a correct SHA256 fingerprint (with or without prefix)', () => {
    expect(matchesFingerprint(KEY, 'SHA256:' + sha256b64(KEY))).toBe(true);
    expect(matchesFingerprint(KEY, sha256b64(KEY))).toBe(true);
  });

  it('rejects a wrong SHA256 fingerprint', () => {
    expect(matchesFingerprint(KEY, 'SHA256:' + sha256b64(OTHER_KEY))).toBe(false);
  });

  it('accepts a correct legacy MD5 fingerprint', () => {
    const colonHex = md5hex(KEY).match(/.{2}/g)!.join(':');
    expect(matchesFingerprint(KEY, 'MD5:' + colonHex)).toBe(true);
    expect(matchesFingerprint(KEY, colonHex)).toBe(true);
  });
});

describe('knownHostsHasKey (#1 known_hosts matching)', () => {
  const b64 = KEY.toString('base64');

  it('matches a plain entry on default port', () => {
    const content = `127.0.0.1 ssh-ed25519 ${b64}\n`;
    expect(knownHostsHasKey(content, '127.0.0.1', 22, KEY)).toBe(true);
  });

  it('requires the [host]:port form for non-default ports', () => {
    const content = `[127.0.0.1]:2222 ssh-ed25519 ${b64}\n`;
    expect(knownHostsHasKey(content, '127.0.0.1', 2222, KEY)).toBe(true);
    // Same key but recorded for the bare host must NOT satisfy a non-default port.
    const bare = `127.0.0.1 ssh-ed25519 ${b64}\n`;
    expect(knownHostsHasKey(bare, '127.0.0.1', 2222, KEY)).toBe(false);
  });

  it('does not match when the key differs (MITM / changed key)', () => {
    const content = `127.0.0.1 ssh-ed25519 ${OTHER_KEY.toString('base64')}\n`;
    expect(knownHostsHasKey(content, '127.0.0.1', 22, KEY)).toBe(false);
  });

  it('matches comma-separated host patterns and ignores comments', () => {
    const content = `# a comment\nexample.com,127.0.0.1 ssh-rsa ${b64}\n`;
    expect(knownHostsHasKey(content, '127.0.0.1', 22, KEY)).toBe(true);
  });

  it('matches hashed (|1|salt|hash) entries', () => {
    const salt = Buffer.from('0123456789abcdef0123', 'utf8'); // 20 bytes
    const hostHash = createHmac('sha1', salt).update('127.0.0.1').digest('base64');
    const content = `|1|${salt.toString('base64')}|${hostHash} ssh-ed25519 ${b64}\n`;
    expect(knownHostsHasKey(content, '127.0.0.1', 22, KEY)).toBe(true);
  });
});

describe('verifyHostKeySync (#1 decision logic)', () => {
  const opts = { host: '127.0.0.1', port: 22 };

  it('fails closed when no known_hosts and no fingerprint', () => {
    const res = verifyHostKeySync(KEY, opts, undefined);
    expect(res.ok).toBe(false);
  });

  it('accepts when explicitly insecure (with a reason)', () => {
    const res = verifyHostKeySync(KEY, { ...opts, insecure: true });
    expect(res.ok).toBe(true);
    expect(res.reason).toMatch(/disabled/i);
  });

  it('accepts a matching pinned fingerprint and ignores known_hosts', () => {
    const res = verifyHostKeySync(KEY, { ...opts, hostFingerprint: 'SHA256:' + sha256b64(KEY) });
    expect(res.ok).toBe(true);
  });

  it('rejects a mismatched pinned fingerprint even if known_hosts would match', () => {
    const goodKnownHosts = `127.0.0.1 ssh-ed25519 ${KEY.toString('base64')}\n`;
    const res = verifyHostKeySync(KEY, { ...opts, hostFingerprint: 'SHA256:' + sha256b64(OTHER_KEY) }, goodKnownHosts);
    expect(res.ok).toBe(false);
  });

  it('accepts when the key is present in known_hosts', () => {
    const content = `127.0.0.1 ssh-ed25519 ${KEY.toString('base64')}\n`;
    expect(verifyHostKeySync(KEY, opts, content).ok).toBe(true);
  });

  it('rejects when known_hosts lists a different key for the host (MITM)', () => {
    const content = `127.0.0.1 ssh-ed25519 ${OTHER_KEY.toString('base64')}\n`;
    expect(verifyHostKeySync(KEY, opts, content).ok).toBe(false);
  });
});
