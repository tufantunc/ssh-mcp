import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, chmod, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { loadConfig, getProfile, checkPermissions } from '../../../src/config/loader.js';
import type { AppConfig } from '../../../src/types.js';

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'ssh-mcp-test-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

async function writeConfig(content: string, mode = 0o600): Promise<string> {
  const path = join(tempDir, 'config.toml');
  await writeFile(path, content, 'utf8');
  await chmod(path, mode);
  return path;
}

describe('loadConfig', () => {
  it('loads a valid config with defaults applied', async () => {
    const path = await writeConfig(`
[defaults]
defaultProfile = "dev"

[[profiles]]
name = "dev"
host = "localhost"
port = 2222
user = "test"
auth = "password"
`);
    const config = await loadConfig(path);
    expect(config.defaults.defaultProfile).toBe('dev');
    expect(config.defaults.sessionMaxPerConnection).toBe(5);
    expect(config.profiles).toHaveLength(1);
    expect(config.profiles[0].name).toBe('dev');
    expect(config.profiles[0].port).toBe(2222);
    expect(config.profiles[0].sessionMaxPerConnection).toBe(5);
  });

  // Regression: [defaults] used to be validated but only two session keys were
  // ever merged into profiles, so a documented default silently did nothing —
  // an approvalMode that never applies is a security downgrade, not a papercut.
  it('cascades every [defaults] key into profiles that omit it', async () => {
    const path = await writeConfig(`
[defaults]
approvalMode = "ask-all"
commandTimeoutMs = 30000
commandMaxChars = 1234
commandMaxOutputBytes = 2048
sessionBackgroundMaxMs = 111000
sessionMaxPerConnection = 9
sessionIdleTimeoutMs = 222000

[[profiles]]
name = "dev"
host = "localhost"
user = "test"
`);
    const config = await loadConfig(path);
    const p = config.profiles[0];
    expect(p.approvalPolicy).toBe('ask-all');
    expect(p.timeout).toBe(30000);
    expect(p.maxChars).toBe(1234);
    expect(p.maxOutputBytes).toBe(2048);
    expect(p.sessionBackgroundMaxMs).toBe(111000);
    expect(p.sessionMaxPerConnection).toBe(9);
    expect(p.sessionIdleTimeoutMs).toBe(222000);
  });

  it('lets an explicit profile value override [defaults]', async () => {
    const path = await writeConfig(`
[defaults]
approvalMode = "ask-all"
commandTimeoutMs = 30000

[[profiles]]
name = "dev"
host = "localhost"
user = "test"
approvalPolicy = "auto"
timeout = 5000
`);
    const config = await loadConfig(path);
    expect(config.profiles[0].approvalPolicy).toBe('auto');
    expect(config.profiles[0].timeout).toBe(5000);
  });

  it('falls back to schema defaults when [defaults] is absent', async () => {
    const path = await writeConfig(`
[[profiles]]
name = "dev"
host = "localhost"
user = "test"
`);
    const config = await loadConfig(path);
    const p = config.profiles[0];
    expect(p.approvalPolicy).toBe('ask-destructive');
    expect(p.timeout).toBe(60_000);
    expect(p.maxOutputBytes).toBe(1_048_576);
  });

  it('rejects unknown profile keys instead of silently dropping them', async () => {
    const path = await writeConfig(`
[[profiles]]
name = "dev"
host = "localhost"
user = "test"
hostFingerprint = "SHA256:abc"
`);
    // hostFingerprint was accepted-but-unimplemented; a user pinning with it
    // got plain TOFU. Unknown keys must now fail loudly.
    await expect(loadConfig(path)).rejects.toThrow(/hostFingerprint|Config validation/);
  });

  it('rejects config with no profiles', async () => {
    const path = await writeConfig(`
[defaults]
defaultProfile = "dev"
`);
    await expect(loadConfig(path)).rejects.toThrow(/profiles/);
  });

  it('rejects invalid approval mode', async () => {
    const path = await writeConfig(`
[[profiles]]
name = "dev"
host = "localhost"
user = "test"
approvalPolicy = "yolo"
`);
    await expect(loadConfig(path)).rejects.toThrow();
  });

  it('rejects world-readable config', async () => {
    const path = await writeConfig(`
[[profiles]]
name = "dev"
host = "localhost"
user = "test"
`, 0o644);
    await expect(loadConfig(path)).rejects.toThrow(/group\/world accessible/);
  });

  it('rejects malformed TOML', async () => {
    const path = await writeConfig(`this is not = valid = toml [[[[`);
    await expect(loadConfig(path)).rejects.toThrow(/Failed to parse TOML/);
  });

  it('applies per-profile overrides for session limits', async () => {
    const path = await writeConfig(`
[defaults]
sessionMaxPerConnection = 5

[[profiles]]
name = "prod"
host = "prod.example.com"
user = "deploy"
sessionMaxPerConnection = 2
`);
    const config = await loadConfig(path);
    expect(config.profiles[0].sessionMaxPerConnection).toBe(2);
  });
});

describe('getProfile', () => {
  let config: AppConfig;

  beforeEach(async () => {
    const path = await writeConfig(`
[defaults]
defaultProfile = "dev"

[[profiles]]
name = "dev"
host = "localhost"
user = "test"

[[profiles]]
name = "prod"
host = "prod.example.com"
user = "deploy"
`);
    config = await loadConfig(path);
  });

  it('returns default profile when no name given', () => {
    const p = getProfile(config);
    expect(p.name).toBe('dev');
  });

  it('returns named profile', () => {
    const p = getProfile(config, 'prod');
    expect(p.name).toBe('prod');
  });

  it('throws for unknown profile', () => {
    expect(() => getProfile(config, 'staging')).toThrow(/not found/);
  });
});

describe('checkPermissions', () => {
  it('passes for 0600 file', async () => {
    const path = await writeConfig(``, 0o600);
    await expect(checkPermissions(path)).resolves.not.toThrow();
  });

  it('fails for 0644 file', async () => {
    const path = await writeConfig(``, 0o644);
    await expect(checkPermissions(path)).rejects.toThrow(/accessible/);
  });

  it('fails for world-readable directory', async () => {
    const subdir = join(tempDir, 'insecure-dir');
    await mkdtemp(subdir).catch(async () => {
      await import('fs/promises').then((fs) => fs.mkdir(subdir, { recursive: true }));
    });
    const cfgPath = join(tempDir, 'config.toml');
    await writeFile(cfgPath, '', 'utf8');
    await chmod(cfgPath, 0o600);
    await chmod(tempDir, 0o777);
    await expect(checkPermissions(cfgPath)).rejects.toThrow(/directory.*accessible/i);
    await chmod(tempDir, 0o700);
  });
});
