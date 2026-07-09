import { describe, it, expect, vi } from 'vitest';
import { buildOpenSshSudoWrapper, classifyError, OpenSshTransport, renderAskpassHelper } from '../src/transports/openssh';

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

    it('falls back to remote_exit for unknown 255 stderr (ssh(1): 255 is also a valid remote command exit)', () => {
      // When no SSH-layer signature matches, a 255 exit is surfaced as the
      // remote command's own non-zero exit (Error (code 255)) rather than a
      // generic SSH transport error, so legitimate remote `exit 255` is not
      // masked. See classifyError + resultToMcpContent.
      expect(classifyError(255, 'some unknown ssh error')).toBe('remote_exit');
      expect(classifyError(255, '')).toBe('remote_exit');
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

  it('forces IdentitiesOnly=yes when an explicit key is supplied (no agent-key spray)', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'key', keyPath: '/home/user/.ssh/id_ed25519' });
    const args = t.buildArgs({ timeoutMs: 60000 });
    expect(args).toContain('IdentitiesOnly=yes');
    // The -i path and IdentitiesOnly=yes must both be present so ssh uses only
    // the chosen key instead of offering every ssh-agent identity first.
    const iIdx = args.indexOf('-i');
    expect(iIdx).toBeGreaterThanOrEqual(0);
    expect(args[iIdx + 1]).toBe('/home/user/.ssh/id_ed25519');
  });

  it('does not emit IdentitiesOnly for non-key auth modes', () => {
    const t = new OpenSshTransport({ ...baseCfg, authMode: 'kerberos' });
    expect(t.buildArgs({ timeoutMs: 60000 })).not.toContain('IdentitiesOnly=yes');
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

describe('renderAskpassHelper (finding 5: Windows metachar-safe password echo)', () => {
  it('does not use a bare `echo %VAR%` on Windows', () => {
    const content = renderAskpassHelper('SSH_MCP_PW_1234', true);
    // The bug was `echo %VAR%`, which CMD re-parses and breaks on & | < > ^ %.
    expect(content).not.toMatch(/echo\s+%SSH_MCP_PW_1234%/);
  });

  it('reads the password via PowerShell $env:VAR (no command-line substitution)', () => {
    const content = renderAskpassHelper('SSH_MCP_PW_1234', true);
    expect(content).toContain('powershell');
    expect(content).toContain('$env:SSH_MCP_PW_1234');
    // Password value itself is never placed in the script text.
    expect(content).not.toContain('hunter2');
  });

  it('emits a metacharacter-safe printf on POSIX', () => {
    const content = renderAskpassHelper('SSH_MCP_PW_1234', false);
    expect(content).toContain('#!/bin/sh');
    expect(content).toContain('printf');
    expect(content).toContain('"$SSH_MCP_PW_1234"');
    // Must NOT interpolate the value unquoted (would break on metacharacters).
    expect(content).not.toMatch(/echo\s+\$SSH_MCP_PW_1234/);
  });
});

describe('OpenSshTransport cleanup listeners (Codex R4 finding 3: unregister on close, no reload leak)', () => {
  // init() registers process.once exit/SIGINT/SIGTERM handlers; close() must
  // remove exactly them so a config hot-reload (close + discard + re-dial per
  // reload) cannot accumulate one dead handler set per reload. Stub the ssh(1)
  // probe so the test needs no real ssh binary.
  function makeInitable() {
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', authMode: 'kerberos' });
    (t as any).verifySshBinary = vi.fn().mockResolvedValue(undefined);
    return t;
  }

  const counts = () => ({
    exit: process.listenerCount('exit'),
    sigint: process.listenerCount('SIGINT'),
    sigterm: process.listenerCount('SIGTERM'),
  });

  it('adds one handler set on init and removes it on close', async () => {
    const before = counts();
    const t = makeInitable();
    await t.init();
    const during = counts();
    expect(during.exit).toBe(before.exit + 1);
    expect(during.sigint).toBe(before.sigint + 1);
    expect(during.sigterm).toBe(before.sigterm + 1);

    await t.close();
    const after = counts();
    expect(after).toEqual(before);
  });

  it('does not accumulate process listeners across repeated init/close cycles (reload leak guard)', async () => {
    const before = counts();
    // Simulate many hot-reloads: each closes + discards the old transport and
    // re-dials a fresh one. Without unregister-on-close this grows unbounded.
    for (let i = 0; i < 25; i++) {
      const t = makeInitable();
      await t.init();
      await t.close();
    }
    expect(counts()).toEqual(before);
  });
});

describe('buildOpenSshSudoWrapper (Codex P1: keep sudo password out of local ssh argv)', () => {
  it('builds a passwordless sudo command without sudo -S', () => {
    expect(buildOpenSshSudoWrapper('id -u', false)).toBe("sudo -n sh -c 'id -u'");
  });

  it('builds a sudo -S command but never embeds the password value', () => {
    const cmd = buildOpenSshSudoWrapper("printf '%s' ok", true);
    expect(cmd).toContain('sudo -p "" -S');
    expect(cmd).toContain("sh -c 'printf '\\''%s'\\'' ok'");
    expect(cmd).not.toContain('sudopw');
  });
});

describe('OpenSshTransport.execElevated sudo mode (finding 6: route via su when only suPassword set)', () => {
  function makeTransport(cfg: any) {
    const t = new OpenSshTransport({
      host: 'h', port: 22, username: 'u', ...cfg,
    });
    const runSuViaPty = vi.fn().mockResolvedValue({ stdout: 'root-out', stderr: '', exitCode: 0 });
    const runSsh = vi.fn().mockResolvedValue({ stdout: 'sudo-out', stderr: '', exitCode: 0 });
    (t as any).runSuViaPty = runSuViaPty;
    (t as any).runSsh = runSsh;
    return { t, runSuViaPty, runSsh };
  }

  it('routes sudo-exec through the su PTY when only suPassword is set (no sudo password)', async () => {
    const { t, runSuViaPty, runSsh } = makeTransport({ suPassword: 'supw' });
    await t.execElevated('whoami', { timeoutMs: 60000, mode: 'sudo' });
    expect(runSuViaPty).toHaveBeenCalledTimes(1);
    expect(runSuViaPty).toHaveBeenCalledWith('whoami', 'supw', expect.objectContaining({ mode: 'sudo' }));
    expect(runSsh).not.toHaveBeenCalled();
  });

  it('uses a stdin-fed sudo wrapper when a sudo password is available (password never in argv)', async () => {
    const { t, runSuViaPty, runSsh } = makeTransport({ suPassword: 'supw', sudoPassword: 'sudopw' });
    await t.execElevated('whoami', { timeoutMs: 60000, mode: 'sudo' });
    expect(runSsh).toHaveBeenCalledTimes(1);
    expect(runSuViaPty).not.toHaveBeenCalled();
    const [wrapped, runOpts] = runSsh.mock.calls[0];
    expect(wrapped).toContain('sudo -p "" -S');
    expect(wrapped).not.toContain('sudopw');
    expect(runOpts.stdin).toBe('sudopw\n');
  });

  it('uses the normal sudo wrapper (passwordless) when neither su nor sudo password is set', async () => {
    const { t, runSuViaPty, runSsh } = makeTransport({});
    await t.execElevated('whoami', { timeoutMs: 60000, mode: 'sudo' });
    expect(runSsh).toHaveBeenCalledTimes(1);
    expect(runSuViaPty).not.toHaveBeenCalled();
    const [wrapped, runOpts] = runSsh.mock.calls[0];
    expect(wrapped).toBe("sudo -n sh -c 'whoami'");
    expect(runOpts.stdin).toBeUndefined();
  });

  it('prefers an explicit per-call sudo password over the su fallback', async () => {
    const { t, runSuViaPty, runSsh } = makeTransport({ suPassword: 'supw' });
    await t.execElevated('whoami', { timeoutMs: 60000, mode: 'sudo', password: 'callpw' });
    expect(runSsh).toHaveBeenCalledTimes(1);
    expect(runSuViaPty).not.toHaveBeenCalled();
    const [wrapped, runOpts] = runSsh.mock.calls[0];
    expect(wrapped).toContain('sudo -p "" -S');
    expect(wrapped).not.toContain('callpw');
    expect(runOpts.stdin).toBe('callpw\n');
  });
});

describe('OpenSshTransport.isConnected (Codex 3541767250: initialized != connected)', () => {
  function makeTransport(cfg: any) {
    const t = new OpenSshTransport({ host: 'h', port: 22, username: 'u', ...cfg });
    const runSsh = vi.fn();
    const runSuViaPty = vi.fn();
    (t as any).runSsh = runSsh;
    (t as any).runSuViaPty = runSuViaPty;
    return { t, runSsh, runSuViaPty };
  }

  it('reports NOT connected before any command runs (init-only, no live session)', () => {
    // OpenSSH init() only verifies the local ssh binary/askpass setup; no SSH
    // session is established until the first exec. A merely-initialized
    // transport must not claim a live connection.
    const { t } = makeTransport({ authMode: 'kerberos' });
    expect(t.isConnected()).toBe(false);
  });

  it('reports connected after a command completes a live session (exit 0)', async () => {
    const { t, runSsh } = makeTransport({ authMode: 'kerberos' });
    runSsh.mockResolvedValue({ stdout: 'ok', stderr: '', exitCode: 0 });
    await t.exec('true', { timeoutMs: 60000 });
    expect(t.isConnected()).toBe(true);
  });

  it('reports connected after a non-zero REMOTE exit (host answered, command failed)', async () => {
    const { t, runSsh } = makeTransport({ authMode: 'kerberos' });
    runSsh.mockResolvedValue({ stdout: '', stderr: 'nope', exitCode: 1, category: 'remote_exit' });
    await t.exec('false', { timeoutMs: 60000 });
    // A remote command's own non-zero exit still proves the host is live.
    expect(t.isConnected()).toBe(true);
  });

  it('stays NOT connected after a connect-layer failure (e.g. connection refused)', async () => {
    const { t, runSsh } = makeTransport({ authMode: 'kerberos' });
    runSsh.mockResolvedValue({ stdout: '', stderr: 'Connection refused', exitCode: 255, category: 'connect' });
    await t.exec('true', { timeoutMs: 60000 });
    expect(t.isConnected()).toBe(false);
  });

  it('stays NOT connected after a transport-layer failure (ssh spawn error)', async () => {
    const { t, runSsh } = makeTransport({ authMode: 'kerberos' });
    runSsh.mockResolvedValue({ stdout: '', stderr: 'spawn error', exitCode: null, category: 'transport' });
    await t.exec('true', { timeoutMs: 60000 });
    expect(t.isConnected()).toBe(false);
  });

  it('stays NOT connected after a bare timeout (no proof the host answered)', async () => {
    const { t, runSsh } = makeTransport({ authMode: 'kerberos' });
    runSsh.mockResolvedValue({ stdout: '', stderr: '', exitCode: null, category: 'timeout' });
    await t.exec('sleep 100', { timeoutMs: 10 });
    expect(t.isConnected()).toBe(false);
  });

  it('reports connected once a later command succeeds after an initial connect failure', async () => {
    const { t, runSsh } = makeTransport({ authMode: 'kerberos' });
    runSsh
      .mockResolvedValueOnce({ stdout: '', stderr: 'Connection refused', exitCode: 255, category: 'connect' })
      .mockResolvedValueOnce({ stdout: 'ok', stderr: '', exitCode: 0 });
    await t.exec('true', { timeoutMs: 60000 });
    expect(t.isConnected()).toBe(false);
    await t.exec('true', { timeoutMs: 60000 });
    expect(t.isConnected()).toBe(true);
  });
});
