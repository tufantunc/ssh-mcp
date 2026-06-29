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
    // Must not throw (exit 0 is success). Since pr/multi-host, substantive
    // stderr is surfaced alongside stdout in a [stderr] block rather than
    // dropped — see test/result-mapper.test.ts for the success-path contract.
    const out = resultToMcpContent(result);
    expect(out.content[0].type).toBe('text');
    expect(out.content[0].text).toBe(
      "ok\n[stderr]\nWarning: Permanently added 'h' (ED25519) to the list of known hosts.",
    );
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

  it('throws on auth/host_key/connect/transport/timeout categories regardless of exit code', () => {
    for (const category of ['auth', 'host_key', 'connect', 'transport', 'timeout'] as const) {
      expect(() =>
        resultToMcpContent({ stdout: '', stderr: 'x', exitCode: 0, category }),
      ).toThrow(McpError);
    }
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
