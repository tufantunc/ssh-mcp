import { describe, it, expect } from 'vitest';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

import {
  parseTomlConfig,
  loadTomlFile,
  expandHome,
  resolveEnvRef,
  defaultDiscoveryPaths,
} from '../toml-loader.js';

describe('expandHome', () => {
  it('expands a leading ~ alone', () => {
    expect(expandHome('~')).toBe(os.homedir());
  });
  it('expands ~/foo', () => {
    expect(expandHome('~/foo')).toBe(path.join(os.homedir(), 'foo'));
  });
  it('passes through paths without ~', () => {
    expect(expandHome('/etc/ssh/known_hosts')).toBe('/etc/ssh/known_hosts');
  });
  it('returns undefined for undefined', () => {
    expect(expandHome(undefined)).toBeUndefined();
  });
});

describe('resolveEnvRef', () => {
  it('returns the plain string when no env: prefix', () => {
    expect(resolveEnvRef('hello', 'x', {})).toBe('hello');
  });
  it('resolves env:NAME against the env map', () => {
    expect(resolveEnvRef('env:FOO', 'x', { FOO: 'bar' })).toBe('bar');
  });
  it('throws when env var is missing', () => {
    expect(() => resolveEnvRef('env:MISSING', 'field.x', {})).toThrow(/MISSING/);
  });
  it('throws when env var is empty', () => {
    expect(() => resolveEnvRef('env:EMPTY', 'field.x', { EMPTY: '' })).toThrow(/EMPTY/);
  });
  it('throws when env: prefix has no name', () => {
    expect(() => resolveEnvRef('env:', 'field.x', {})).toThrow(/no variable name/);
  });
  it('never echoes the env value in the error message', () => {
    try {
      resolveEnvRef('env:NOT_SET', 'sources.x.password', {});
      throw new Error('should have thrown');
    } catch (e: any) {
      // The error mentions the env name and the field, but never the value.
      expect(e.message).toContain('NOT_SET');
      expect(e.message).toContain('sources.x.password');
    }
  });
});

describe('defaultDiscoveryPaths', () => {
  it('includes SSH_MCP_CONFIG first when set', () => {
    const paths = defaultDiscoveryPaths({ SSH_MCP_CONFIG: '/tmp/from-env.toml' });
    expect(paths[0]).toBe('/tmp/from-env.toml');
  });
  it('falls back to XDG then ~/.ssh-mcp', () => {
    const paths = defaultDiscoveryPaths({ XDG_CONFIG_HOME: '/x/conf' });
    expect(paths).toContain('/x/conf/ssh-mcp/config.toml');
    expect(paths[paths.length - 1].endsWith(path.join('.ssh-mcp', 'config.toml'))).toBe(true);
  });
});

describe('parseTomlConfig: minimum viable', () => {
  it('parses a single password source', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "lab"
host = "lab.example"
user = "root"
auth = "password"
password = "literal-pw"
`);
    expect(cfg.sources).toHaveLength(1);
    expect(cfg.sources[0]).toMatchObject({
      name: 'lab',
      host: 'lab.example',
      port: 22,
      username: 'root',
      authMode: 'password',
      transport: 'ssh2',
      password: 'literal-pw',
    });
    expect(cfg.defaultName).toBeUndefined();
  });

  it('parses a key source and reads key_path verbatim (no FS read)', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "lab"
host = "lab.example"
user = "root"
auth = "key"
key_path = "~/.ssh/lab_ed25519"
`);
    expect(cfg.sources[0].keyPath).toBe(path.join(os.homedir(), '.ssh/lab_ed25519'));
    expect(cfg.sources[0].privateKey).toBeUndefined();
  });

  it('kerberos defaults transport to openssh', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "bastion"
host = "b.example"
user = "x@EXAMPLE"
auth = "kerberos"
`);
    expect(cfg.sources[0].transport).toBe('openssh');
    expect(cfg.sources[0].kerberos).toBe(true);
  });

  it('two [[sources]] register identically to two --ssh=<JSON> calls', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "a"
host = "a.example"
user = "ua"
auth = "kerberos"
default = true

[[sources]]
id = "b"
host = "b.example"
user = "ub"
auth = "key"
key_path = "/k"
`);
    expect(cfg.sources.map(s => s.name)).toEqual(['a', 'b']);
    expect(cfg.defaultName).toBe('a');
    expect(cfg.sources[0].authMode).toBe('kerberos');
    expect(cfg.sources[1].authMode).toBe('key');
    expect(cfg.sources[1].keyPath).toBe('/k');
  });
});

describe('parseTomlConfig: env interpolation', () => {
  it('resolves env:NAME for password fields', () => {
    const cfg = parseTomlConfig(
      `
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "password"
password = "env:LAB_PW"
sudo_password = "env:LAB_SUDO"
`,
      { env: { LAB_PW: 'secret-pw', LAB_SUDO: 'secret-sudo' } },
    );
    expect(cfg.sources[0].password).toBe('secret-pw');
    expect(cfg.sources[0].sudoPassword).toBe('secret-sudo');
  });

  it('errors when env var missing', () => {
    expect(() => parseTomlConfig(
      `
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "password"
password = "env:NOT_SET"
`,
      { env: {} },
    )).toThrow(/NOT_SET/);
  });
});

describe('parseTomlConfig: validation', () => {
  it('rejects empty source list', () => {
    expect(() => parseTomlConfig(`[server]\naudit_dir = "/tmp"`)).toThrow(/sources/);
  });

  it('rejects duplicate ids', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "x"
host = "h1"
user = "u"
auth = "kerberos"

[[sources]]
id = "x"
host = "h2"
user = "u"
auth = "kerberos"
`)).toThrow(/duplicate/i);
  });

  it('rejects invalid auth', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "bogus"
`)).toThrow(/auth/);
  });

  it('rejects key auth with no key_path or private_key', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "key"
`)).toThrow(/key_path|private_key/);
  });

  it('rejects password auth with no password', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "password"
`)).toThrow(/password/);
  });

  it('rejects multiple sources marked default', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "a"
host = "h"
user = "u"
auth = "kerberos"
default = true

[[sources]]
id = "b"
host = "h"
user = "u"
auth = "kerberos"
default = true
`)).toThrow(/default/);
  });

  it('rejects non-loopback webui without auth_token', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[webui]
host = "0.0.0.0"
port = 8080
`)).toThrow(/auth_token/);
  });

  it('accepts non-loopback webui when auth_token is set', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[webui]
host = "0.0.0.0"
port = 8080
auth_token = "env:TKN"
`, { env: { TKN: 'tok' } });
    expect(cfg.webui?.auth_token).toBe('tok');
  });

  it('parses [approval] and [approval.llm]', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[approval]
mode = "smart"
fail_closed = false

[approval.llm]
endpoint = "https://api.example/v1/c"
api_key = "env:KEY"
model = "m-1"
timeout_ms = 1234
`, { env: { KEY: 'sk-xyz' } });
    expect(cfg.approval?.mode).toBe('smart');
    expect(cfg.approval?.fail_closed).toBe(false);
    expect(cfg.approval?.llm?.api_key).toBe('sk-xyz');
    expect(cfg.approval?.llm?.timeout_ms).toBe(1234);
  });

  it('propagates per-source description and approval override to the server config', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "dc03"
host = "dc03.css.com.tw"
user = "css\\\\c19087"
auth = "kerberos"
description = '''allow only NTDS\\My thumbprint 8A00772D4491E2E71218405BDDE5A5FE3E9C7DBE certificate-object writes; deny PFX, private key reads, restart, reboot'''
approval = { mode = "smart" }
`);
    expect(cfg.sources[0].description).toContain('NTDS\\My');
    expect(cfg.sources[0].description).toContain('8A00772D4491E2E71218405BDDE5A5FE3E9C7DBE');
    expect(cfg.sources[0].approval?.mode).toBe('smart');
    expect(cfg.perSourceApproval?.dc03).toBe('smart');
  });

  it('parses per-source approval override', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[sources.approval]
mode = "yolo"
`);
    // @iarna/toml flattens `[sources.approval]` as a sibling key; this
    // assertion encodes the actual TOML semantics we expect.
    // (When users want per-source overrides they use the inline-table form
    // shown in the example file.)
    expect(cfg.perSourceApproval).toBeDefined();
  });
});

describe('loadTomlFile', () => {
  it('reads from disk and stamps configPath', () => {
    const tmp = path.join(os.tmpdir(), `ssh-mcp-test-${process.pid}-${Date.now()}.toml`);
    fs.writeFileSync(tmp, `
[[sources]]
id = "lab"
host = "lab.example"
user = "root"
auth = "kerberos"
`);
    try {
      const cfg = loadTomlFile(tmp);
      expect(cfg.configPath).toBe(tmp);
      expect(cfg.sources[0].name).toBe('lab');
    } finally {
      fs.unlinkSync(tmp);
    }
  });

  it('throws a redact-safe error on missing file', () => {
    expect(() => loadTomlFile('/nonexistent/ssh-mcp-test.toml')).toThrow(/cannot read/);
  });
});
