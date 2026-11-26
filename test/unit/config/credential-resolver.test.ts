import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { writeFile } from 'fs/promises';
import { join } from 'path';
import { useConfigDir } from './helpers.js';
import { initKeychain, resolveCredentials, resolveSudoKeychainPassword } from '../../../src/config/credential-resolver.js';
import type { Profile } from '../../../src/types.js';

const keyring = vi.hoisted(() => ({ entry: vi.fn(), getPassword: vi.fn() }));
vi.mock('@napi-rs/keyring', () => ({
  Entry: class {
    constructor(service: string, account: string) { keyring.entry(service, account); }
    getPassword() { return keyring.getPassword(); }
  },
}));

const cfg = useConfigDir('ssh-mcp-cred-');
let savedEnv: NodeJS.ProcessEnv;

function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'test',
    host: 'localhost',
    port: 22,
    user: 'test',
    auth: 'password',
    tty: false,
    timeout: 60000,
    maxChars: 5000,
    maxOutputBytes: 1048576,
    outputTruncation: 'head',
    role: 'operator',
    readOnly: false,
    announceAgent: true,
    approvalPolicy: 'ask-destructive',
    cert: false,
    sessionMaxPerConnection: 5,
    sessionIdleTimeoutMs: 600000,
    sessionBackgroundMaxMs: 3600000,
    commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
    ...overrides,
  };
}

beforeEach(async () => {
  savedEnv = { ...process.env };
});

afterEach(async () => {
  process.env = savedEnv;
});

describe('resolveCredentials', () => {
  it('resolves password from profile-specific env var', async () => {
    process.env.SSH_MCP_TEST_PASSWORD = 'secret123';
    const creds = await resolveCredentials(makeProfile());
    expect(creds.password).toBe('secret123');
  });

  it('resolves password from generic env var', async () => {
    process.env.SSH_MCP_PASSWORD = 'generic';
    const creds = await resolveCredentials(makeProfile());
    expect(creds.password).toBe('generic');
  });

  it('profile-specific env var takes priority over generic', async () => {
    process.env.SSH_MCP_PASSWORD = 'generic';
    process.env.SSH_MCP_TEST_PASSWORD = 'specific';
    const creds = await resolveCredentials(makeProfile());
    expect(creds.password).toBe('specific');
  });

  it('resolves sudo password from env', async () => {
    process.env.SSH_MCP_PASSWORD = 'main-pw';
    process.env.SSH_MCP_SUDO_PASSWORD = 'sudo-pw';
    const creds = await resolveCredentials(makeProfile());
    expect(creds.password).toBe('main-pw');
    expect(creds.sudoPassword).toBe('sudo-pw');
  });

  it('resolves agent socket when auth=agent', async () => {
    process.env.SSH_AUTH_SOCK = '/tmp/agent.sock';
    const creds = await resolveCredentials(makeProfile({ auth: 'agent' }));
    expect(creds.agentSocket).toBe('/tmp/agent.sock');
  });

  it('resolves private key from keyRef path', async () => {
    const keyPath = join(cfg.dir, 'id_ed25519');
    await writeFile(keyPath, '-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n');
    const creds = await resolveCredentials(makeProfile({ auth: 'key', keyRef: keyPath }));
    expect(creds.privateKey).toContain('BEGIN PRIVATE KEY');
  });

  it('resolves private key from env var path', async () => {
    const keyPath = join(cfg.dir, 'env_key');
    await writeFile(keyPath, 'key-content');
    process.env.SSH_MCP_TEST_KEY = keyPath;
    const creds = await resolveCredentials(makeProfile());
    expect(creds.privateKey).toBe('key-content');
  });

  it('throws when no credentials found', async () => {
    delete process.env.SSH_MCP_PASSWORD;
    delete process.env.SSH_MCP_TEST_PASSWORD;
    delete process.env.SSH_MCP_KEY;
    delete process.env.SSH_MCP_TEST_KEY;
    delete process.env.SSH_AUTH_SOCK;
    await expect(resolveCredentials(makeProfile())).rejects.toThrow(/No credentials/);
  });
});

describe('resolveSudoKeychainPassword', () => {
  const profile = makeProfile({ auth: 'password', sudoKeychainEntry: 'ssh-mcp/test-sudo' });

  beforeEach(async () => {
    keyring.entry.mockClear();
    keyring.getPassword.mockReset();
    expect(await initKeychain()).toBe(true);
    process.env.SSH_MCP_TEST_PASSWORD = 'ssh-password';
    process.env.SSH_MCP_TEST_SUDO_PASSWORD = 'profile-fallback';
    process.env.SSH_MCP_SUDO_PASSWORD = 'global-fallback';
  });

  it('does not retrieve or cache sudo credentials during SSH authentication', async () => {
    const creds = await resolveCredentials(profile);
    expect(creds.password).toBe('ssh-password');
    expect(creds.sudoPassword).toBeUndefined();
    expect(keyring.getPassword).not.toHaveBeenCalled();
  });

  it('retrieves the configured service/account on every lookup without caching', async () => {
    keyring.getPassword.mockResolvedValueOnce('first-test-secret').mockResolvedValueOnce('second-test-secret');
    expect(await resolveSudoKeychainPassword(profile)).toBe('first-test-secret');
    expect(await resolveSudoKeychainPassword(profile)).toBe('second-test-secret');
    expect(keyring.entry).toHaveBeenNthCalledWith(1, 'ssh-mcp', 'test-sudo');
    expect(keyring.entry).toHaveBeenNthCalledWith(2, 'ssh-mcp', 'test-sudo');
    expect(keyring.getPassword).toHaveBeenCalledTimes(2);
  });

  it.each([null, '', 'first\nsecond', 'first\rsecond', 'first\0second'])(
    'rejects missing or invalid credential %j without falling back', async (password) => {
      keyring.getPassword.mockResolvedValue(password);
      await expect(resolveSudoKeychainPassword(profile)).rejects.toThrow(/Missing or invalid sudo keychain credential/);
    },
  );

  it('does not expose backend exception details or use an environment fallback', async () => {
    keyring.getPassword.mockRejectedValue(new Error('fictional-secret-in-backend-error'));
    await expect(resolveSudoKeychainPassword(profile)).rejects.toThrow(
      /^Sudo keychain lookup failed for profile "test"\.$/,
    );
  });

  it('leaves environment credentials unchanged for profiles without a keychain entry', async () => {
    const legacy = makeProfile();
    expect(await resolveSudoKeychainPassword(legacy)).toBeUndefined();
    expect((await resolveCredentials(legacy)).sudoPassword).toBe('profile-fallback');
    expect(keyring.getPassword).not.toHaveBeenCalled();
  });
});
