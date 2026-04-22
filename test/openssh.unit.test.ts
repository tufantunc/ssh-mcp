import { describe, it, expect } from 'vitest';
import { classifyError, OpenSshTransport } from '../src/transports/openssh';

describe('classifyError', () => {
  it('returns undefined for success (exit 0)', () => {
    expect(classifyError(0, '')).toBeUndefined();
  });

  it('returns transport for null exit code', () => {
    expect(classifyError(null, '')).toBe('transport');
  });

  it('returns remote_exit for non-255 non-zero codes', () => {
    expect(classifyError(1, 'something')).toBe('remote_exit');
    expect(classifyError(127, 'command not found')).toBe('remote_exit');
    expect(classifyError(254, '')).toBe('remote_exit');
  });

  describe('SSH layer (exit 255) classification', () => {
    it('classifies auth failures', () => {
      expect(classifyError(255, 'Permission denied (publickey).')).toBe('auth');
      expect(classifyError(255, 'Authentication failed.')).toBe('auth');
      expect(classifyError(255, 'No credentials cache found')).toBe('auth');
      expect(classifyError(255, 'Ticket expired')).toBe('auth');
      expect(classifyError(255, 'GSSAPI Error: Unspecified GSS failure')).toBe('auth');
      expect(classifyError(255, 'Clock skew too great')).toBe('auth');
      expect(classifyError(255, 'Server not found in Kerberos database')).toBe('auth');
    });

    it('classifies host-key failures', () => {
      expect(classifyError(255, 'Host key verification failed.')).toBe('host_key');
      expect(classifyError(255, 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!')).toBe('host_key');
    });

    it('classifies connectivity failures', () => {
      expect(classifyError(255, 'ssh: connect to host foo port 22: Connection refused')).toBe('connect');
      expect(classifyError(255, 'ssh: connect to host foo port 22: Connection timed out')).toBe('connect');
      expect(classifyError(255, 'ssh: connect to host foo port 22: Connection reset')).toBe('connect');
      expect(classifyError(255, 'ssh: Could not resolve hostname foo')).toBe('connect');
      expect(classifyError(255, 'Name or service not known')).toBe('connect');
      expect(classifyError(255, 'No route to host')).toBe('connect');
      expect(classifyError(255, 'Network unreachable')).toBe('connect');
    });

    it('falls back to transport for unknown 255 stderr', () => {
      expect(classifyError(255, 'some unknown ssh error')).toBe('transport');
      expect(classifyError(255, '')).toBe('transport');
    });
  });
});

describe('OpenSshTransport.buildArgs', () => {
  const baseCfg = {
    host: 'ubuntu-dev.example.internal',
    port: 22,
    username: 'aduser@EXAMPLE.INTERNAL',
  };

  it('emits Kerberos-specific flags when authMode=kerberos', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'kerberos' });
    const args = t.buildArgs({ timeoutMs: 60000 });
    expect(args).toContain('GSSAPIAuthentication=yes');
    expect(args).toContain('GSSAPIDelegateCredentials=no');
    expect(args).toContain('PreferredAuthentications=gssapi-with-mic');
    expect(args).toContain('PubkeyAuthentication=no');
    expect(args).toContain('PasswordAuthentication=no');
    expect(args.at(-1)).toBe('aduser@EXAMPLE.INTERNAL@ubuntu-dev.example.internal');
  });

  it('honors --gssapiDelegateCredentials', () => {
    const t = new OpenSshTransport({
      ...baseCfg,
      authMode: 'kerberos',
      gssapiDelegateCredentials: 'yes',
    });
    const args = t.buildArgs({ timeoutMs: 60000 });
    expect(args).toContain('GSSAPIDelegateCredentials=yes');
  });

  it('emits key-specific flags when authMode=key', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'key', keyPath: '/home/user/.ssh/id_ed25519' });
    const args = t.buildArgs({ timeoutMs: 60000 });
    expect(args).toContain('-i');
    expect(args).toContain('/home/user/.ssh/id_ed25519');
    expect(args).toContain('PreferredAuthentications=publickey');
    expect(args).toContain('PasswordAuthentication=no');
    expect(args).toContain('GSSAPIAuthentication=no');
  });

  it('emits password-specific flags when authMode=password', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'password', password: 'hunter2' });
    const args = t.buildArgs({ timeoutMs: 60000 });
    expect(args).toContain('PreferredAuthentications=password,keyboard-interactive');
    expect(args).toContain('PubkeyAuthentication=no');
    expect(args).toContain('GSSAPIAuthentication=no');
  });

  it('respects custom strictHostKeyChecking and knownHostsFile', () => {
    const t = new OpenSshTransport({
      ...baseCfg,
      authMode: 'kerberos',
      strictHostKeyChecking: 'yes',
      knownHostsFile: '/etc/ssh/managed_known_hosts',
    });
    const args = t.buildArgs({ timeoutMs: 60000 });
    expect(args).toContain('StrictHostKeyChecking=yes');
    expect(args).toContain('UserKnownHostsFile=/etc/ssh/managed_known_hosts');
  });

  it('defaults StrictHostKeyChecking to accept-new', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'kerberos' });
    const args = t.buildArgs({ timeoutMs: 60000 });
    expect(args).toContain('StrictHostKeyChecking=accept-new');
  });

  it('scales ConnectTimeout with opts.timeoutMs', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'kerberos' });
    expect(t.buildArgs({ timeoutMs: 5000 })).toContain('ConnectTimeout=5');
    expect(t.buildArgs({ timeoutMs: 120000 })).toContain('ConnectTimeout=120');
  });

  it('appends -tt when opts.pty is true', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'kerberos' });
    const args = t.buildArgs({ timeoutMs: 60000, pty: true });
    expect(args).toContain('-tt');
  });

  it('includes port via -p', () => {
    const t = new OpenSshTransport({ ...baseCfg, port: 2222, authMode: 'kerberos' });
    const args = t.buildArgs({ timeoutMs: 60000 });
    const pIdx = args.indexOf('-p');
    expect(pIdx).toBeGreaterThanOrEqual(0);
    expect(args[pIdx + 1]).toBe('2222');
  });

  it('includes ServerAlive keepalive options', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'kerberos' });
    const args = t.buildArgs({ timeoutMs: 60000 });
    expect(args).toContain('ServerAliveInterval=30');
    expect(args).toContain('ServerAliveCountMax=3');
  });
});
