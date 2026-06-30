import { describe, it, expect, vi } from 'vitest';
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  resultToMcpContent,
  resolveAuthMode,
  buildTransportConfig,
  getOrCreateInitializedTransport,
} from '../src/index';
import type { ExecResult, ISshTransport } from '../src/transports/types';

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
    const out = resultToMcpContent(result);
    expect(out.content[0]).toEqual({ type: 'text', text: 'ok' });
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

describe('getOrCreateInitializedTransport (Codex P2: do not publish before init resolves)', () => {
  function fakeTransport(): ISshTransport {
    return {
      name: 'openssh',
      init: vi.fn(),
      exec: vi.fn(),
      execElevated: vi.fn(),
      close: vi.fn(),
    };
  }

  it('shares an in-flight initialization promise and publishes only after it resolves', async () => {
    const cache = { activeTransport: null as ISshTransport | null, initPromise: null as Promise<ISshTransport> | null };
    const transport = fakeTransport();
    let resolveInit!: (value: ISshTransport) => void;
    const createInitializedTransport = vi.fn(() => new Promise<ISshTransport>((resolve) => {
      resolveInit = resolve;
    }));

    const p1 = getOrCreateInitializedTransport(cache, createInitializedTransport);
    const p2 = getOrCreateInitializedTransport(cache, createInitializedTransport);

    expect(createInitializedTransport).toHaveBeenCalledTimes(1);
    expect(p2).toBe(p1);
    // Critical regression guard: no half-initialized transport is visible while
    // init is still pending, so concurrent OpenSSH/password calls cannot enter
    // runSsh before SSH_ASKPASS exists.
    expect(cache.activeTransport).toBeNull();
    expect(cache.initPromise).toBe(p1);

    resolveInit(transport);
    await expect(p1).resolves.toBe(transport);
    await expect(p2).resolves.toBe(transport);
    expect(cache.activeTransport).toBe(transport);
    expect(cache.initPromise).toBeNull();
  });

  it('clears the cached init promise after initialization failure so a retry can initialize', async () => {
    const cache = { activeTransport: null as ISshTransport | null, initPromise: null as Promise<ISshTransport> | null };
    const createInitializedTransport = vi
      .fn<() => Promise<ISshTransport>>()
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(fakeTransport());

    await expect(getOrCreateInitializedTransport(cache, createInitializedTransport)).rejects.toThrow('boom');
    expect(cache.activeTransport).toBeNull();
    expect(cache.initPromise).toBeNull();

    await expect(getOrCreateInitializedTransport(cache, createInitializedTransport)).resolves.toMatchObject({ name: 'openssh' });
    expect(createInitializedTransport).toHaveBeenCalledTimes(2);
    expect(cache.activeTransport?.name).toBe('openssh');
  });
});
