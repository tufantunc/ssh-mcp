import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { resolveConfig } from '../resolver.js';
import type { ServerConfig } from '../../transports/types.js';

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
    expect(cfg.webui?.enabled).toBe(true);
    expect(cfg.webui?.port).toBe(9099);
    expect(cfg.server?.audit_dir).toContain('audit-only');
    expect(cfg.configPath).toBe(p);
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
    expect(cfg.configPath).toBeUndefined();
  });

  it('propagates TOML validation errors', () => {
    const bad = writeToml(tmp, 'bad.toml', `not valid =`);
    expect(() => resolveConfig({ cliSources: [], cliConfigPath: bad, env: {} })).toThrow(/parse failed/);
  });
});

describe('resolveConfig: requireConnection (D-A2 multi-source guard)', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-resolver-rc-'));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const multiToml = `
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

  it('defaults to true with no CLI and no TOML (safe default)', () => {
    const cfg = resolveConfig({ cliSources: [], env: { XDG_CONFIG_HOME: path.join(tmp, 'none') } });
    expect(cfg.requireConnection).toBe(true);
  });

  it('defaults to true with CLI sources and no TOML', () => {
    const cfg = resolveConfig({ cliSources: [cliSource('a'), cliSource('b')], env: {} });
    expect(cfg.requireConnection).toBe(true);
  });

  it('defaults to true from a TOML that omits the flag', () => {
    const p = writeToml(tmp, 'multi.toml', multiToml);
    const cfg = resolveConfig({ cliSources: [], cliConfigPath: p, env: {} });
    expect(cfg.requireConnection).toBe(true);
  });

  it('carries the opt-out (false) from [server].require_connection', () => {
    const p = writeToml(tmp, 'optout.toml', `
[server]
require_connection = false
${multiToml}`);
    const cfg = resolveConfig({ cliSources: [], cliConfigPath: p, env: {} });
    expect(cfg.requireConnection).toBe(false);
  });

  it('honors the TOML flag even when CLI sources suppress the TOML source list', () => {
    // require_connection is a top-level safety knob, like [webui]/[approval].
    const p = writeToml(tmp, 'mixed.toml', `
[server]
require_connection = false
${multiToml}`);
    const cfg = resolveConfig({ cliSources: [cliSource('cli1'), cliSource('cli2')], cliConfigPath: p, env: {} });
    expect(cfg.sources.map(s => s.name)).toEqual(['cli1', 'cli2']);
    expect(cfg.requireConnection).toBe(false);
  });
});
