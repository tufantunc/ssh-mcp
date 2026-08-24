import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmod } from 'fs/promises';
import { platform } from 'os';
import { makeConfigDir, MINIMAL_CONFIG, type ConfigDir } from './helpers.js';
import { loadConfig, getProfile, checkPermissions } from '../../../src/config/loader.js';
import type { AppConfig } from '../../../src/types.js';
import { defaultsFromArgv } from '../../../src/cli.js';
import { OperatorError } from '../../../src/errors.js';

let cfg: ConfigDir;
let tempDir: string;

beforeEach(async () => {
  cfg = await makeConfigDir();
  tempDir = cfg.dir;
});

afterEach(async () => {
  await cfg.cleanup();
});

const writeConfig = (content: string, mode = 0o600): Promise<string> => cfg.write(content, mode);

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

  // POSIX only. Windows has no mode bits — Node synthesises 0o666 for every
  // file there, chmod cannot change it, and the check is skipped as a result
  // (#138). Running the assertion on Windows would test the emulation layer.
  it.skipIf(platform() === 'win32')('rejects world-readable config', async () => {
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

  // Reported in #54: with several hosts configured and no default chosen, the
  // old fallback ran the command against profiles[0] — no argument, no warning,
  // and typically the first host written down, which tends to be production.
  describe('ambiguous selection', () => {
    async function configWithoutDefault(...names: string[]): Promise<AppConfig> {
      const path = await writeConfig(
        names.map((n) => `\n[[profiles]]\nname = "${n}"\nhost = "${n}.example.com"\nuser = "test"\n`).join(''),
      );
      return loadConfig(path);
    }

    it('refuses to guess between several profiles', async () => {
      const c = await configWithoutDefault('prod', 'staging', 'dev');
      expect(() => getProfile(c)).toThrow(/No profile selected/);
    });

    it('names the candidates and both ways out', async () => {
      const c = await configWithoutDefault('prod', 'staging');
      // An error that does not say what to do next just moves the guessing.
      expect(() => getProfile(c)).toThrow(/prod, staging/);
      expect(() => getProfile(c)).toThrow(/defaultProfile/);
    });

    it('still resolves when only one profile exists', async () => {
      const c = await configWithoutDefault('only');
      expect(getProfile(c).name).toBe('only');
    });

    it('still resolves when the caller names one', async () => {
      const c = await configWithoutDefault('prod', 'staging');
      expect(getProfile(c, 'staging').name).toBe('staging');
    });
  });
});

describe('checkPermissions', () => {
  // The reproduction for #138, and the reason the Windows CI job exists: this
  // is the exact shape of config that used to be rejected there — a normal
  // file, created normally, in the documented location.
  it.runIf(platform() === 'win32')('accepts an ordinary Windows file', async () => {
    const path = await writeConfig(MINIMAL_CONFIG);
    await expect(checkPermissions(path)).resolves.toBeUndefined();
    // Asserts the config was actually parsed, and — via inspectAcl — that the ACL
    // check produced a verdict rather than being waved through. `toBeTruthy()`
    // was satisfied by the fail-open path, so this test used to pass whether or
    // not the check ran at all.
    const { inspectAcl } = await import('../../../src/config/windows-acl.js');
    expect((await inspectAcl(path)).status).toBe('restricted');
    expect((await loadConfig(path)).profiles[0].host).toBe('localhost');
  });

  it('passes for 0600 file', async () => {
    const path = await writeConfig(``, 0o600);
    await expect(checkPermissions(path)).resolves.not.toThrow();
  });

  it.skipIf(platform() === 'win32')('fails for 0644 file', async () => {
    const path = await writeConfig(``, 0o644);
    await expect(checkPermissions(path)).rejects.toThrow(/accessible/);
  });

  it.skipIf(platform() === 'win32')('fails for world-readable directory', async () => {
    const cfgPath = await writeConfig('', 0o600);
    await chmod(tempDir, 0o777);
    try {
      await expect(checkPermissions(cfgPath)).rejects.toThrow(/directory.*accessible/i);
      // A directory nobody can chmod is the Docker case: the message has to say
      // what to do when tightening it is not an option.
      await expect(checkPermissions(cfgPath)).rejects.toThrow(/bind-mount|--config/);
    } finally {
      await chmod(tempDir, 0o700);
    }
  });
});

describe('getProfile with nothing configured', () => {
  /**
   * The invariant, not the product rule.
   *
   * A lookup helper must not hand back `undefined` typed as `Profile`, which is what an
   * empty list fell through to before — a TypeError somewhere downstream instead of an
   * explanation. Note that an empty list is a state *this change introduced*:
   * `configSchema` requires `profiles` to have at least one entry, so no config file could
   * ever produce one, and before the server learned to start unconfigured nothing else
   * could either.
   *
   * The decision that an unconfigured server refuses work lives one layer up, in
   * `ConnectionRegistry` — see test/unit/ssh/unconfigured-registry.test.ts. It has to,
   * because the check here can only sit in the no-profile-named branch, which is why the
   * named branch below still answers as a pure lookup.
   */
  const empty = (): AppConfig => ({ defaults: defaultsFromArgv({}), profiles: [] });

  it('refuses with the operator message rather than returning undefined', () => {
    expect(() => getProfile(empty())).toThrow(/No config file found/);
    expect(() => getProfile(empty())).toThrow(OperatorError);
  });

  it('still names a profile that was asked for and does not exist', () => {
    // Pure lookup: the registry is what turns this into the unconfigured explanation
    // before a caller can ever get here.
    expect(() => getProfile(empty(), 'prod')).toThrow(/Profile "prod" not found/);
  });
});
