import { describe, it, expect } from 'vitest';
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  resultToMcpContent,
  resolveAuthMode,
  buildTransportConfig,
  hasLegacyCliFlags,
  validateConfig,
  resolveCliConfigPath,
} from '../src/index';
import type { ExecResult } from '../src/transports/types';

// Pure-function unit tests for the CLI config/result mapping layer. These
// import from src/index, which is safe because the test runner sets
// SSH_MCP_DISABLE_MAIN=1 (isCliEnabled=false) so no server/CLI side effects run
// on import.

describe('resultToMcpContent (finding 1: exit-0 stderr must not error)', () => {
  it('treats exit 0 as success even when stderr carries an OpenSSH host-key warning', () => {
    const result: ExecResult = {
      stdout: 'ok',
      stderr: "Warning: Permanently added 'h' (ED25519) to the list of known hosts.",
      exitCode: 0,
      category: undefined,
    };
    // Must not throw (exit 0 is success). The benign OpenSSH first-connect
    // host-key warning is filtered out of the success-path stderr, so only
    // stdout is returned — see test/result-mapper.test.ts for the contract.
    const out = resultToMcpContent(result);
    expect(out.content[0]).toEqual({ type: 'text', text: 'ok' });
  });

  it('appends genuine stderr diagnostics on success (exit 0), filtering only the benign host-key warning', () => {
    // Tools like git clone / curl / build systems write progress + warnings to
    // stderr while still exiting 0; that output must reach the caller.
    const out = resultToMcpContent({
      stdout: 'cloned',
      stderr: "Warning: Permanently added 'h' (ED25519) to the list of known hosts.\nCloning into 'repo'...\nReceiving objects: 100%",
      exitCode: 0,
      category: undefined,
    });
    expect(out.content[0].text).toBe("cloned\nCloning into 'repo'...\nReceiving objects: 100%");
  });

  it('returns only stdout when stderr is nothing but the benign host-key warning', () => {
    const out = resultToMcpContent({
      stdout: 'done',
      stderr: "Warning: Permanently added '[h]:2222' (RSA) to the list of known hosts.",
      exitCode: 0,
      category: undefined,
    });
    expect(out.content[0].text).toBe('done');
  });

  it('returns content for a plain success (exit 0, no stderr)', () => {
    const out = resultToMcpContent({ stdout: 'hello', stderr: '', exitCode: 0 });
    expect(out.content[0].text).toBe('hello');
  });

  it('still throws for a genuine non-zero exit with stderr', () => {
    expect(() =>
      resultToMcpContent({ stdout: '', stderr: 'boom', exitCode: 2, category: 'remote_exit' as any }),
    ).toThrow(McpError);
  });

  it('throws for a non-zero exit even without a category set', () => {
    expect(() =>
      resultToMcpContent({ stdout: '', stderr: 'segfault', exitCode: 139 }),
    ).toThrow(/Error \(code 139\)/);
  });

  it('throws for a non-zero exit with EMPTY stderr (e.g. `false`, `test -f missing`)', () => {
    // Regression for the openssh transport: `false` / `test -f missing` exit
    // non-zero with no stderr, and must NOT be reported as success.
    expect(() =>
      resultToMcpContent({ stdout: '', stderr: '', exitCode: 1, category: 'remote_exit' as any }),
    ).toThrow(/Error \(code 1\)[\s\S]*Command exited with status 1/);
  });

  it('treats a null exit code with no error category as success (handshake-less success path)', () => {
    const out = resultToMcpContent({ stdout: 'done', stderr: '', exitCode: null });
    expect(out.content[0].text).toBe('done');
  });

  it('throws on auth/host_key/connect/transport/timeout categories regardless of exit code', () => {
    for (const category of ['auth', 'host_key', 'connect', 'transport', 'timeout'] as const) {
      expect(() =>
        resultToMcpContent({ stdout: '', stderr: 'x', exitCode: 0, category }),
      ).toThrow(McpError);
    }
  });

  it('preserves the timeout context even when stderr was written before the deadline', () => {
    // A build/tool that prints progress or diagnostics to stderr and then hangs
    // must NOT be reported as an ordinary error that hides the timeout; the
    // timeout message stays, with stderr kept as trailing context.
    let caught: unknown;
    try {
      resultToMcpContent({
        stdout: '',
        stderr: 'Building... step 3/9\nlinking objects',
        exitCode: null,
        category: 'timeout',
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(McpError);
    const msg = (caught as McpError).message;
    expect(msg).toMatch(/timed out after \d+ms/);
    // stderr diagnostics are retained as context, not dropped.
    expect(msg).toContain('Building... step 3/9');
    expect(msg).toContain('linking objects');
  });

  it('reports a bare timeout message when no stderr was captured', () => {
    expect(() =>
      resultToMcpContent({ stdout: '', stderr: '', exitCode: null, category: 'timeout' }),
    ).toThrow(/timed out after \d+ms/);
  });
});

describe('resolveAuthMode (finding 2: password-over-key precedence)', () => {
  it('ranks password above key when both are present', () => {
    expect(resolveAuthMode({ password: 'pw', key: '/path/to/key' })).toBe('password');
  });

  it('resolves key when only a key is present', () => {
    expect(resolveAuthMode({ key: '/path/to/key' })).toBe('key');
  });

  it('resolves password when only a password is present', () => {
    expect(resolveAuthMode({ password: 'pw' })).toBe('password');
  });

  it('ranks kerberos above everything', () => {
    expect(resolveAuthMode({ kerberos: true, password: 'pw', key: '/k' })).toBe('kerberos');
  });

  it('returns undefined when no credentials are supplied', () => {
    expect(resolveAuthMode({})).toBeUndefined();
  });
});

describe('buildTransportConfig (finding 2: no unconditional key read for password configs)', () => {
  it('does NOT read the key file when a password config carries a stale --key (ssh2)', async () => {
    const cfg = await buildTransportConfig({
      host: 'h',
      port: 22,
      username: 'u',
      password: 'pw',
      key: '/nonexistent/path/to/stale-key',
      // transport defaults to ssh2
    });
    expect(cfg.authMode).toBe('password');
    expect(cfg.password).toBe('pw');
    // keyPath is still recorded, but the (nonexistent) file must not be read.
    expect(cfg.privateKey).toBeUndefined();
  });

  it('reads the key contents when key is the resolved auth mode (ssh2)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-test-'));
    const keyPath = path.join(dir, 'id_test');
    await fs.writeFile(keyPath, 'KEYDATA');
    try {
      const cfg = await buildTransportConfig({ host: 'h', port: 22, username: 'u', key: keyPath });
      expect(cfg.authMode).toBe('key');
      expect(cfg.privateKey).toBe('KEYDATA');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('does not read the key file for the openssh transport (uses -i path instead)', async () => {
    const cfg = await buildTransportConfig({
      host: 'h',
      port: 22,
      username: 'u',
      key: '/nonexistent/path/to/key',
      transportFlag: 'openssh',
    });
    expect(cfg.transport).toBe('openssh');
    expect(cfg.keyPath).toBe('/nonexistent/path/to/key');
    expect(cfg.privateKey).toBeUndefined();
  });
});

describe('hasLegacyCliFlags (finding 2: --disableSudo is not a legacy trigger)', () => {
  it('returns false for --disableSudo alone (valid in --config / --ssh modes)', () => {
    // --disableSudo only controls sudo-tool registration and is allowed in
    // every mode. It must NOT force the legacy single-host validation branch
    // (which would demand --host/--user). Regression guard for
    // `ssh-mcp --config cfg.toml --disableSudo`.
    expect(hasLegacyCliFlags({ disableSudo: null })).toBe(false);
  });

  it('still returns true for a genuine legacy flag like --host', () => {
    expect(hasLegacyCliFlags({ host: 'h' })).toBe(true);
  });

  it('still returns true for --port (single-host-only flag)', () => {
    expect(hasLegacyCliFlags({ port: '2222' })).toBe(true);
  });

  it('returns false for an empty / config-only argv', () => {
    expect(hasLegacyCliFlags({})).toBe(false);
    expect(hasLegacyCliFlags({ config: '/etc/ssh-mcp/config.toml' })).toBe(false);
  });
});

describe('buildTransportConfig (Codex 3541767256: deferKeyRead keeps legacy key reads lazy)', () => {
  it('does NOT read the ssh2 key file at build time when deferKeyRead is set', async () => {
    // The legacy single-host bootstrap passes deferKeyRead so startup never
    // reads the key file — a key mounted after process launch must still work,
    // matching the pre-registry behavior (read on first tool call, not startup).
    const cfg = await buildTransportConfig(
      { host: 'h', port: 22, username: 'u', key: '/nonexistent/path/to/key' },
      { deferKeyRead: true },
    );
    expect(cfg.transport).toBe('ssh2');
    expect(cfg.authMode).toBe('key');
    // keyPath is recorded so the registry's lazy prepareKeyContents can read it
    // on first use, but the (nonexistent) file must NOT be read now.
    expect(cfg.keyPath).toBe('/nonexistent/path/to/key');
    expect(cfg.privateKey).toBeUndefined();
  });

  it('still reads the ssh2 key eagerly when deferKeyRead is not set (default)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-test-'));
    const keyPath = path.join(dir, 'id_test');
    await fs.writeFile(keyPath, 'KEYDATA');
    try {
      const cfg = await buildTransportConfig({ host: 'h', port: 22, username: 'u', key: keyPath });
      expect(cfg.privateKey).toBe('KEYDATA');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});

describe('validateConfig (Codex P2: reject value-less OpenSSH option flags)', () => {
  const baseCfg = { host: 'h', user: 'u', transport: 'openssh' };

  it('rejects a value-less --strictHostKeyChecking (parsed as null) instead of silently defaulting', () => {
    // parseArgv records `null` for `--strictHostKeyChecking` with no `=value`.
    // A truthiness guard would skip validation and let the option be dropped,
    // silently weakening the host-key policy to the default.
    expect(() =>
      validateConfig({ ...baseCfg, strictHostKeyChecking: null }),
    ).toThrow(/--strictHostKeyChecking must be one of: yes, no, accept-new/);
  });

  it('rejects a value-less --gssapiDelegateCredentials (parsed as null)', () => {
    expect(() =>
      validateConfig({ ...baseCfg, kerberos: null, gssapiDelegateCredentials: null }),
    ).toThrow(/--gssapiDelegateCredentials must be yes or no/);
  });

  it('rejects a value-less --knownHostsFile (parsed as null)', () => {
    expect(() =>
      validateConfig({ ...baseCfg, knownHostsFile: null }),
    ).toThrow(/--knownHostsFile requires a file path/);
  });

  it('rejects an invalid explicit --strictHostKeyChecking value', () => {
    expect(() =>
      validateConfig({ ...baseCfg, strictHostKeyChecking: 'maybe' }),
    ).toThrow(/--strictHostKeyChecking must be one of/);
  });

  it('accepts valid explicit OpenSSH option values', () => {
    expect(() =>
      validateConfig({
        ...baseCfg,
        kerberos: null, // --kerberos alone; required for gssapiDelegateCredentials
        strictHostKeyChecking: 'yes',
        gssapiDelegateCredentials: 'no',
        knownHostsFile: '/etc/ssh/known_hosts',
      }),
    ).not.toThrow();
  });

  it('does not require OpenSSH option values when the flags are absent', () => {
    expect(() => validateConfig({ ...baseCfg })).not.toThrow();
  });

  it('rejects a value-less --transport (parsed as null) instead of silently defaulting to ssh2', () => {
    // parseArgv records `null` for `--transport` with no `=value`; the nullish
    // fallback would treat it as absent and run the default ssh2 transport,
    // silently ignoring a mistyped OpenSSH selection.
    expect(() =>
      validateConfig({ host: 'h', user: 'u', transport: null }),
    ).toThrow(/--transport requires a value/);
  });

  it('rejects --gssapiDelegateCredentials without --kerberos (delegation would be silently dropped)', () => {
    // buildArgs only emits GSSAPIDelegateCredentials in the kerberos auth
    // branch, so accepting it without --kerberos would silently omit it and
    // break second-hop SSO.
    expect(() =>
      validateConfig({ ...baseCfg, gssapiDelegateCredentials: 'yes' }),
    ).toThrow(/--gssapiDelegateCredentials requires --kerberos/);
  });

  it('accepts --gssapiDelegateCredentials when --kerberos is present', () => {
    expect(() =>
      validateConfig({ host: 'h', user: 'u', kerberos: null, gssapiDelegateCredentials: 'yes' }),
    ).not.toThrow();
  });
});

describe('resolveCliConfigPath (Codex R2 P2: reject value-less --config)', () => {
  it('returns undefined when --config is absent', () => {
    expect(resolveCliConfigPath({})).toBeUndefined();
    expect(resolveCliConfigPath({ host: 'h', user: 'u' })).toBeUndefined();
  });

  it('returns the path for --config=<path>', () => {
    expect(resolveCliConfigPath({ config: '/etc/ssh-mcp/config.toml' }))
      .toBe('/etc/ssh-mcp/config.toml');
  });

  it('rejects a present-but-value-less --config (parsed as null) instead of silently ignoring it', () => {
    // parseArgv records `null` for `--config` with no `=path`. Coercing that to
    // undefined would fall back to SSH_MCP_CONFIG/default discovery, so a
    // mistyped explicit flag could start against the wrong configured source.
    expect(() => resolveCliConfigPath({ config: null }))
      .toThrow(/--config requires a value/);
  });

  it('rejects an empty --config= (parsed as "") the same as a value-less --config (Codex 3541772406)', () => {
    // `--config=` parses as an empty string; resolveConfig treats it as the
    // explicit path but skips loadTomlFile because it is falsy, silently
    // dropping the intended TOML settings. Fail fast instead.
    expect(() => resolveCliConfigPath({ config: '' }))
      .toThrow(/--config requires a value/);
  });
});
