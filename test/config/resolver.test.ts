import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { resolveConfig } from '../../src/config/resolver.js';
import type { ServerConfig } from '../../src/transports/types.js';

function cliSource(name = 'cli'): ServerConfig {
  return {
    name,
    host: `${name}.example`,
    port: 22,
    username: 'cli-user',
    authMode: 'kerberos',
    kerberos: true,
    transport: 'openssh',
  };
}

function writeToml(dir: string, name: string, body: string): string {
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
  return file;
}

const basicToml = `
[[sources]]
id = "toml"
host = "toml.example"
user = "toml-user"
auth = "kerberos"
default = true
`;

describe('resolveConfig precedence', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-resolver-'));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('returns CLI sources when provided and no TOML exists', () => {
    const cfg = resolveConfig({ cliSources: [cliSource('a'), cliSource('b')], env: {} });
    expect(cfg.sources.map(s => s.name)).toEqual(['a', 'b']);
    expect(cfg.defaultName).toBe('a');
    // The first --ssh source is a positional fallback, NOT a user-chosen
    // default: defaultExplicit must be false so the multi-source omit-name
    // guard still fires (the security fix).
    expect(cfg.defaultExplicit).toBe(false);
    expect(cfg.configPath).toBeUndefined();
  });

  it('loads --config TOML when no CLI sources exist', () => {
    const p = writeToml(tmp, 'explicit.toml', basicToml);
    const cfg = resolveConfig({ cliSources: [], cliConfigPath: p, env: {} });
    expect(cfg.sources).toHaveLength(1);
    expect(cfg.sources[0]).toMatchObject({
      name: 'toml',
      host: 'toml.example',
      username: 'toml-user',
      transport: 'openssh',
    });
    expect(cfg.defaultName).toBe('toml');
    // basicToml marks the source `default = true` → an explicit user choice.
    expect(cfg.defaultExplicit).toBe(true);
    expect(cfg.configPath).toBe(p);
  });

  it('CLI > TOML: CLI sources suppress TOML sources but keep top-level TOML sections', () => {
    const p = writeToml(tmp, 'explicit.toml', `
[server]
audit_dir = "~/audit-test"

[[sources]]
id = "toml"
host = "toml.example"
user = "toml-user"
auth = "kerberos"
`);
    const cfg = resolveConfig({ cliSources: [cliSource('cli')], cliConfigPath: p, env: {} });
    expect(cfg.sources).toHaveLength(1);
    expect(cfg.sources[0].name).toBe('cli');
    expect(cfg.sources[0].host).toBe('cli.example');
    expect(cfg.defaultName).toBe('cli');
    // CLI sources suppress the TOML source list; the surviving default is a
    // positional CLI fallback, so the explicit-default marker (even if the
    // suppressed TOML had `default = true`) does NOT carry over.
    expect(cfg.defaultExplicit).toBe(false);
    expect(cfg.server?.audit_dir).toContain('audit-test');
    expect(cfg.configPath).toBe(p);
  });

  it('CLI source + a TOML with ONLY top-level sections (no [[sources]]) resolves', () => {
    // R1 finding 1: the resolver doc-comment promises "legacy flags AND a TOML
    // just for [webui]". A --config TOML carrying no [[sources]] must not throw
    // when CLI sources are present; it should keep the CLI source and expose
    // the top-level sections.
    const p = writeToml(tmp, 'webui-only.toml', `
[webui]
enabled = true
host = "127.0.0.1"
port = 9099

[server]
audit_dir = "~/audit-only"
`);
    const cfg = resolveConfig({ cliSources: [cliSource('cli')], cliConfigPath: p, env: {} });
    expect(cfg.sources.map(s => s.name)).toEqual(['cli']);
    expect(cfg.defaultName).toBe('cli');
    expect(cfg.defaultExplicit).toBe(false);
    expect(cfg.webui?.enabled).toBe(true);
    expect(cfg.webui?.port).toBe(9099);
    expect(cfg.server?.audit_dir).toContain('audit-only');
    expect(cfg.configPath).toBe(p);
  });

  it('--webui resolves a token from a TOML section whose enabled flag is false', () => {
    const p = writeToml(tmp, 'cli-webui.toml', `
[webui]
enabled = false
host = "0.0.0.0"
auth_token = "env:WEBUI_TOKEN"
`);
    const cfg = resolveConfig({
      cliSources: [cliSource('cli')],
      cliConfigPath: p,
      env: { WEBUI_TOKEN: 'resolved-token' },
      webuiEnabled: true,
    });
    expect(cfg.webui?.enabled).toBe(false);
    expect(cfg.webui?.auth_token).toBe('resolved-token');
  });

  it('still rejects a TOML with no [[sources]] when there are NO CLI sources', () => {
    // Without CLI sources the empty-sources tolerance must NOT apply — an
    // otherwise-empty config is a user error.
    const p = writeToml(tmp, 'empty.toml', `
[webui]
enabled = true
`);
    expect(() => resolveConfig({ cliSources: [], cliConfigPath: p, env: {} }))
      .toThrow(/at least one \[\[sources\]\]/);
  });

  it('--config wins over SSH_MCP_CONFIG when no CLI sources exist', () => {
    const explicit = writeToml(tmp, 'explicit.toml', `
[[sources]]
id = "explicit"
host = "explicit.example"
user = "u"
auth = "kerberos"
`);
    const envPath = writeToml(tmp, 'from-env.toml', `
[[sources]]
id = "env"
host = "env.example"
user = "u"
auth = "kerberos"
`);
    const cfg = resolveConfig({ cliSources: [], cliConfigPath: explicit, env: { SSH_MCP_CONFIG: envPath } });
    expect(cfg.sources[0].name).toBe('explicit');
    expect(cfg.configPath).toBe(explicit);
  });

  it('SSH_MCP_CONFIG is used when --config is absent', () => {
    const envPath = writeToml(tmp, 'from-env.toml', `
[[sources]]
id = "env"
host = "env.example"
user = "u"
auth = "kerberos"
`);
    const cfg = resolveConfig({ cliSources: [], env: { SSH_MCP_CONFIG: envPath } });
    expect(cfg.sources[0].name).toBe('env');
    expect(cfg.configPath).toBe(envPath);
  });

  it('fails closed when SSH_MCP_CONFIG points to a directory instead of falling through (Codex 3551117478)', () => {
    const envDir = path.join(tmp, 'env-config-dir');
    fs.mkdirSync(envDir, { recursive: true });
    const xdgRoot = path.join(tmp, 'xdg-readable');
    writeToml(xdgRoot, 'ssh-mcp/config.toml', `
[[sources]]
id = "xdg"
host = "xdg.example"
user = "u"
auth = "kerberos"
`);

    expect(() => resolveConfig({
      cliSources: [],
      env: { SSH_MCP_CONFIG: envDir, XDG_CONFIG_HOME: xdgRoot },
    })).toThrow(/not a regular file|cannot access/);
  });

  it('fails closed when SSH_MCP_CONFIG is inaccessible instead of falling through (Codex 3549260453)', () => {
    const blockedDir = path.join(tmp, 'blocked');
    fs.mkdirSync(blockedDir, { recursive: true });
    const blockedPath = writeToml(blockedDir, 'config.toml', `
[[sources]]
id = "blocked"
host = "blocked.example"
user = "u"
auth = "kerberos"
`);
    const xdgRoot = path.join(tmp, 'xdg-readable');
    writeToml(xdgRoot, 'ssh-mcp/config.toml', `
[[sources]]
id = "xdg"
host = "xdg.example"
user = "u"
auth = "kerberos"
`);

    fs.chmodSync(blockedDir, 0o000);
    try {
      expect(() => resolveConfig({
        cliSources: [],
        env: { SSH_MCP_CONFIG: blockedPath, XDG_CONFIG_HOME: xdgRoot },
      })).toThrow(/cannot access|cannot read|EACCES|permission/i);
    } finally {
      fs.chmodSync(blockedDir, 0o700);
    }
  });

  it('a set-but-missing SSH_MCP_CONFIG falls through to XDG discovery instead of hard-failing', () => {
    // R2 Copilot finding: resolveConfig must honor the discovery contract from
    // toml-loader (SSH_MCP_CONFIG is the highest-precedence *candidate*, and a
    // missing candidate falls through). Reading env.SSH_MCP_CONFIG directly
    // made a missing path throw in loadTomlFile; the fix routes env handling
    // through discoverConfigPath so a missing SSH_MCP_CONFIG cleanly falls back.
    const xdgRoot = path.join(tmp, 'xdg');
    const xdgPath = writeToml(xdgRoot, 'ssh-mcp/config.toml', `
[[sources]]
id = "xdg"
host = "xdg.example"
user = "u"
auth = "kerberos"
`);
    const cfg = resolveConfig({
      cliSources: [],
      env: {
        SSH_MCP_CONFIG: path.join(tmp, 'does-not-exist.toml'),
        XDG_CONFIG_HOME: xdgRoot,
      },
    });
    expect(cfg.sources[0].name).toBe('xdg');
    expect(cfg.configPath).toBe(xdgPath);
  });

  it('SSH_MCP_CONFIG still wins over XDG when the env path exists', () => {
    // Precedence within discovery is preserved: an existing SSH_MCP_CONFIG is
    // probed before the XDG/home candidates.
    const envPath = writeToml(tmp, 'env-win.toml', `
[[sources]]
id = "env"
host = "env.example"
user = "u"
auth = "kerberos"
`);
    const xdgRoot = path.join(tmp, 'xdg-lose');
    writeToml(xdgRoot, 'ssh-mcp/config.toml', `
[[sources]]
id = "xdg"
host = "xdg.example"
user = "u"
auth = "kerberos"
`);
    const cfg = resolveConfig({
      cliSources: [],
      env: { SSH_MCP_CONFIG: envPath, XDG_CONFIG_HOME: xdgRoot },
    });
    expect(cfg.sources[0].name).toBe('env');
    expect(cfg.configPath).toBe(envPath);
  });

  it('discovers $XDG_CONFIG_HOME/ssh-mcp/config.toml before ~/.ssh-mcp/config.toml', () => {
    const xdgRoot = path.join(tmp, 'xdg');
    const xdgPath = writeToml(xdgRoot, 'ssh-mcp/config.toml', `
[[sources]]
id = "xdg"
host = "xdg.example"
user = "u"
auth = "kerberos"
`);

    // We cannot safely fake os.homedir() here, but setting XDG_CONFIG_HOME
    // exercises the documented discovery path and avoids touching real home.
    const cfg = resolveConfig({ cliSources: [], env: { XDG_CONFIG_HOME: xdgRoot } });
    expect(cfg.sources[0].name).toBe('xdg');
    expect(cfg.configPath).toBe(xdgPath);
  });

  it('returns an empty source list when neither CLI nor TOML exists', () => {
    const cfg = resolveConfig({ cliSources: [], env: { XDG_CONFIG_HOME: path.join(tmp, 'none') } });
    expect(cfg.sources).toEqual([]);
    expect(cfg.defaultName).toBeUndefined();
    expect(cfg.defaultExplicit).toBe(false);
    expect(cfg.configPath).toBeUndefined();
  });

  it('propagates TOML validation errors', () => {
    const bad = writeToml(tmp, 'bad.toml', `not valid =`);
    expect(() => resolveConfig({ cliSources: [], cliConfigPath: bad, env: {} })).toThrow(/parse failed/);
  });

  it('CLI sources suppress a TOML [[sources]] whose secret env ref is unset, without aborting startup (R2)', () => {
    // R2 Codex finding: when CLI sources win, the resolver discards
    // fromToml.sources downstream, so it must NOT fully validate/resolve the
    // suppressed [[sources]]. A suppressed source with an unset
    // `password = "env:PROD_PASS"` must not fail startup — only the top-level
    // sections survive.
    const p = writeToml(tmp, 'suppressed-secret.toml', `
[[sources]]
id = "prod"
host = "prod.example"
user = "u"
auth = "password"
password = "env:PROD_PASS_UNSET"

[server]
audit_dir = "~/audit-suppressed"
`);
    const cfg = resolveConfig({ cliSources: [cliSource('cli')], cliConfigPath: p, env: {} });
    expect(cfg.sources.map(s => s.name)).toEqual(['cli']);
    expect(cfg.server?.audit_dir).toContain('audit-suppressed');
    expect(cfg.configPath).toBe(p);
  });

  it('still validates TOML [[sources]] secrets when there are NO CLI sources (R2 negative)', () => {
    const p = writeToml(tmp, 'active-secret.toml', `
[[sources]]
id = "prod"
host = "prod.example"
user = "u"
auth = "password"
password = "env:PROD_PASS_UNSET"
`);
    expect(() => resolveConfig({ cliSources: [], cliConfigPath: p, env: {} }))
      .toThrow(/PROD_PASS_UNSET|not set or empty/);
  });
});

describe('resolveConfig: defaultExplicit (explicit-default vs first-registered fallback)', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-resolver-de-'));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const multiNoDefault = `
[[sources]]
id = "a"
host = "a.example"
user = "u"
auth = "kerberos"

[[sources]]
id = "b"
host = "b.example"
user = "u"
auth = "kerberos"
`;

  const multiWithDefault = `
[[sources]]
id = "a"
host = "a.example"
user = "u"
auth = "kerberos"

[[sources]]
id = "b"
host = "b.example"
user = "u"
auth = "kerberos"
default = true
`;

  it('multi-source TOML with NO `default = true`: defaultName falls back to the first source but defaultExplicit is FALSE', () => {
    // This is the security-critical case. Pre-fix the resolver collapsed an
    // explicit default with this positional fallback, so the registry was
    // always told it had an explicit default and the omit-name guard never
    // fired. The fix keeps routing-fallback defaultName but reports
    // defaultExplicit=false so bootstrapRegistry does NOT call setDefault().
    const p = writeToml(tmp, 'multi-nodefault.toml', multiNoDefault);
    const cfg = resolveConfig({ cliSources: [], cliConfigPath: p, env: {} });
    expect(cfg.sources.map(s => s.name)).toEqual(['a', 'b']);
    expect(cfg.defaultName).toBe('a');
    expect(cfg.defaultExplicit).toBe(false);
  });

  it('multi-source TOML WITH `default = true`: defaultName is the chosen source and defaultExplicit is TRUE', () => {
    const p = writeToml(tmp, 'multi-default.toml', multiWithDefault);
    const cfg = resolveConfig({ cliSources: [], cliConfigPath: p, env: {} });
    expect(cfg.sources.map(s => s.name)).toEqual(['a', 'b']);
    expect(cfg.defaultName).toBe('b');
    expect(cfg.defaultExplicit).toBe(true);
  });

  it('single-source TOML with no `default = true`: defaultName falls back but defaultExplicit is FALSE', () => {
    const p = writeToml(tmp, 'single.toml', `
[[sources]]
id = "solo"
host = "solo.example"
user = "u"
auth = "kerberos"
`);
    const cfg = resolveConfig({ cliSources: [], cliConfigPath: p, env: {} });
    expect(cfg.defaultName).toBe('solo');
    expect(cfg.defaultExplicit).toBe(false);
  });
});

describe('reloadResolveConfig pins reloads to the boot-time watched path (finding 4)', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-reload-path-'));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  // src/index.ts reloadResolveConfig feeds resolvedConfig.configPath (the
  // absolute path resolved AT BOOT, which the watcher is attached to) back as
  // the highest-precedence input. This test reproduces that call shape and
  // proves a higher-precedence config appearing AFTER boot does not hijack the
  // reload: the loader keeps reading the originally-watched file.
  it('keeps reading the boot-discovered file even when SSH_MCP_CONFIG appears post-boot', () => {
    // Boot from a default-discovered (lowest precedence) config — no CLI, no
    // SSH_MCP_CONFIG, just XDG discovery.
    const xdgRoot = path.join(tmp, 'xdg');
    const discovered = writeToml(xdgRoot, 'ssh-mcp/config.toml', `
[[sources]]
id = "discovered"
host = "discovered.example"
user = "u"
auth = "kerberos"
`);
    const bootEnv = { XDG_CONFIG_HOME: xdgRoot };
    const boot = resolveConfig({ cliSources: [], env: bootEnv });
    expect(boot.sources[0].name).toBe('discovered');
    expect(boot.configPath).toBe(discovered);

    // A higher-precedence config now appears in the environment (e.g. an
    // operator exports SSH_MCP_CONFIG after the process is already running).
    const higher = writeToml(tmp, 'higher.toml', `
[[sources]]
id = "higher"
host = "higher.example"
user = "u"
auth = "kerberos"
`);

    // FIXED behaviour: reloadResolveConfig pins cliConfigPath to the boot path,
    // so the reload re-reads the watched file, not the newly-higher one.
    const reloaded = resolveConfig({
      cliSources: [],
      cliConfigPath: boot.configPath,
      env: { ...bootEnv, SSH_MCP_CONFIG: higher },
    });
    expect(reloaded.configPath).toBe(discovered);
    expect(reloaded.sources[0].name).toBe('discovered');

    // Sanity: WITHOUT pinning (the old bug), discovery would re-run and the
    // higher-precedence SSH_MCP_CONFIG would win — applying a different file
    // than the one being watched.
    const unpinned = resolveConfig({
      cliSources: [],
      cliConfigPath: undefined,
      env: { ...bootEnv, SSH_MCP_CONFIG: higher },
    });
    expect(unpinned.configPath).toBe(higher);
    expect(unpinned.sources[0].name).toBe('higher');
  });
});
