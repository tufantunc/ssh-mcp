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
} from '../../src/config/toml-loader.js';

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
  it('redacts secret assignment lines from TOML parser errors (Codex 3549260449)', () => {
    try {
      parseTomlConfig(`
[[sources]]
id = "p"
host = "h"
user = "u"
auth = "password"
password = "super-secret-value
`);
      throw new Error('should have thrown');
    } catch (e: any) {
      expect(e.message).toMatch(/TOML parse failed/);
      expect(e.message).toContain('password');
      expect(e.message).toContain('[REDACTED]');
      expect(e.message).not.toContain('super-secret-value');
    }
  });

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

  it('resolves env:NAME for an inline private_key (Codex 3541772408)', () => {
    // Without env resolution the literal "env:SSH_KEY" would be copied into
    // ServerConfig.privateKey and the ssh2 transport would fail to parse it as
    // key material even though the env var is set.
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "key"
private_key = "env:SSH_KEY"
`, { env: { SSH_KEY: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----' } });
    expect(cfg.sources[0].privateKey).toBe('-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----');
    expect(cfg.sources[0].privateKey).not.toMatch(/^env:/);
  });

  it('throws (redact-safe) when an inline private_key env ref is unset', () => {
    try {
      parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "key"
private_key = "env:SSH_KEY_MISSING"
`, { env: {} });
      throw new Error('should have thrown');
    } catch (e: any) {
      expect(e.message).toMatch(/SSH_KEY_MISSING/);
      expect(e.message).toMatch(/private_key/);
    }
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

  it('rejects a non-boolean default marker such as default = "true" (Codex 3541772419)', () => {
    // A quoted/non-boolean `default` value must be rejected rather than silently
    // ignored, otherwise the intended default is never applied and omitted
    // connectionName calls start failing under the multi-source guard.
    expect(() => parseTomlConfig(`
[[sources]]
id = "a"
host = "h"
user = "u"
auth = "kerberos"
default = "true"
`)).toThrow(/default must be a boolean/);
  });

  it('rejects a numeric default marker (default = 1)', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "a"
host = "h"
user = "u"
auth = "kerberos"
default = 1
`)).toThrow(/default must be a boolean/);
  });

  it('accepts default = false (explicit non-default) without error', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "a"
host = "h"
user = "u"
auth = "kerberos"
default = false
`);
    expect(cfg.defaultName).toBeUndefined();
    expect(cfg.defaultExplicit).toBe(false);
  });

  it('rejects non-loopback webui without auth_token when enabled', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[webui]
enabled = true
host = "0.0.0.0"
port = 8080
`)).toThrow(/auth_token/);
  });

  it('does NOT require auth_token for a disabled non-loopback webui (Codex 3541772404)', () => {
    // With enabled = false the section is inert (parsed/reserved, never served),
    // so a non-loopback host must not force SSH startup to fail on a missing
    // token.
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[webui]
enabled = false
host = "0.0.0.0"
port = 8080
`);
    expect(cfg.webui?.enabled).toBe(false);
    expect(cfg.webui?.host).toBe('0.0.0.0');
    expect(cfg.webui?.auth_token).toBeUndefined();
  });

  it('does NOT require auth_token for a non-loopback webui with enabled omitted (defaults off)', () => {
    // [webui] with a host but no `enabled` key is off by default, so the token
    // gate must not fire.
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[webui]
host = "0.0.0.0"
port = 8080
`);
    expect(cfg.webui?.auth_token).toBeUndefined();
  });

  it('accepts non-loopback webui when auth_token is set', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[webui]
enabled = true
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
    // @iarna/toml attaches `[sources.approval]` to the immediately preceding
    // `[[sources]]` entry (verified: identical to the inline `approval = { ...
    // }` form documented in ssh-mcp.toml.example). Assert on the resolved
    // record so this guards the intended semantics — the override actually
    // lands on source "x" with the captured mode — not merely that the map
    // object exists (it is always initialized to `{}`).
    expect(cfg.perSourceApproval).toEqual({ x: 'yolo' });
  });

  it('rejects an empty per-source approval override mode (Codex 3549260472)', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[sources.approval]
mode = ""
`)).toThrow(/sources\.x\.approval\.mode must be one of/);
  });
});

describe('parseTomlConfig: [server].require_connection wiring', () => {
  const oneSource = `
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"
`;

  it('projects require_connection = false onto ResolvedConfig.requireConnection', () => {
    const cfg = parseTomlConfig(`
[server]
require_connection = false
${oneSource}`);
    expect(cfg.requireConnection).toBe(false);
    expect(cfg.server?.require_connection).toBe(false);
  });

  it('projects require_connection = true onto ResolvedConfig.requireConnection', () => {
    const cfg = parseTomlConfig(`
[server]
require_connection = true
${oneSource}`);
    expect(cfg.requireConnection).toBe(true);
  });

  it('leaves requireConnection undefined when the field is absent (safe default applied downstream)', () => {
    const cfg = parseTomlConfig(oneSource);
    expect(cfg.requireConnection).toBeUndefined();
  });

  it('rejects a non-boolean require_connection', () => {
    expect(() => parseTomlConfig(`
[server]
require_connection = "no"
${oneSource}`)).toThrow(/require_connection.*boolean/);
  });
});

describe('parseTomlConfig: transport/host-key/secret guards (R1 findings 3-6)', () => {
  // Finding 3: kerberos requires openssh; explicit ssh2 must be rejected at parse.
  it('rejects auth="kerberos" with explicit transport="ssh2"', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "kerberos"
transport = "ssh2"
`)).toThrow(/kerberos.*openssh|openssh.*kerberos/i);
  });

  it('still defaults a kerberos source (no transport) to openssh', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "kerberos"
`);
    expect(cfg.sources[0].transport).toBe('openssh');
  });

  // Finding 4: host-key fields require openssh (ssh2 silently ignores them).
  it('rejects known_hosts_file on an ssh2 (default) key source', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "key"
key_path = "/k"
known_hosts_file = "/tmp/known"
`)).toThrow(/known_hosts_file.*openssh|strict_host_key_checking.*openssh/i);
  });

  it('rejects strict_host_key_checking on an ssh2 (default) password source', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "p"
host = "h"
user = "u"
auth = "password"
password = "pw"
strict_host_key_checking = "yes"
`)).toThrow(/openssh/i);
  });

  it('accepts known_hosts_file / strict_host_key_checking on transport="openssh"', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "key"
key_path = "/k"
transport = "openssh"
known_hosts_file = "/tmp/known"
strict_host_key_checking = "accept-new"
`);
    expect(cfg.sources[0].knownHostsFile).toBe('/tmp/known');
    expect(cfg.sources[0].strictHostKeyChecking).toBe('accept-new');
  });

  it('accepts host-key fields on a kerberos source (implies openssh)', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u@EX"
auth = "kerberos"
known_hosts_file = "/tmp/known"
`);
    expect(cfg.sources[0].transport).toBe('openssh');
    expect(cfg.sources[0].knownHostsFile).toBe('/tmp/known');
  });

  // Finding 5: openssh key sources need an on-disk key_path (inline key unused).
  it('rejects auth="key" transport="openssh" with only private_key', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "key"
transport = "openssh"
private_key = "-----BEGIN KEY-----"
`)).toThrow(/key_path/);
  });

  it('accepts auth="key" transport="openssh" with key_path', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "key"
transport = "openssh"
key_path = "/k"
`);
    expect(cfg.sources[0].keyPath).toBe('/k');
    expect(cfg.sources[0].transport).toBe('openssh');
  });

  it('rejects an unquoted numeric key_path before home expansion (Codex 3549260462)', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "key"
key_path = 123
`)).toThrow(/key_path must be a quoted string/);
  });

  it('still accepts inline private_key on the ssh2 transport', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "key"
private_key = "-----BEGIN KEY-----"
`);
    expect(cfg.sources[0].transport).toBe('ssh2');
    expect(cfg.sources[0].privateKey).toBe('-----BEGIN KEY-----');
  });

  // Finding 6: secret fields must be quoted strings (a TOML number is rejected).
  it('rejects an unquoted numeric password', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "p"
host = "h"
user = "u"
auth = "password"
password = 123456
`)).toThrow(/password must be a quoted string/);
  });

  it('rejects an unquoted numeric sudo_password', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "p"
host = "h"
user = "u"
auth = "password"
password = "pw"
sudo_password = 123456
`)).toThrow(/sudo_password must be a quoted string/);
  });

  it('rejects an unquoted numeric su_password', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "p"
host = "h"
user = "u"
auth = "password"
password = "pw"
su_password = 42
`)).toThrow(/su_password must be a quoted string/);
  });

  it('does not echo the secret value in the type-guard error', () => {
    try {
      parseTomlConfig(`
[[sources]]
id = "p"
host = "h"
user = "u"
auth = "password"
password = 987654
`);
      throw new Error('should have thrown');
    } catch (e: any) {
      expect(e.message).toContain('sources.p.password');
      expect(e.message).not.toContain('987654');
    }
  });

  it('allowEmptySources tolerates a TOML with only top-level sections', () => {
    const cfg = parseTomlConfig(`
[webui]
enabled = true
host = "127.0.0.1"
port = 8088
`, { allowEmptySources: true });
    expect(cfg.sources).toEqual([]);
    expect(cfg.webui?.enabled).toBe(true);
    expect(cfg.webui?.port).toBe(8088);
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

describe('parseTomlConfig: R2 Codex findings (port range, gssapi-delegate scope, deferred LLM key, ignored sources)', () => {
  const kerbSource = (extra = '') => `
[[sources]]
id = "k"
host = "h"
user = "u"
auth = "kerberos"
${extra}`;

  // Finding: TOML ports must be usable TCP ports (integer 1..65535).
  it('rejects a non-integer port (22.5)', () => {
    expect(() => parseTomlConfig(kerbSource('port = 22.5')))
      .toThrow(/port must be an integer between 1 and 65535/);
  });

  it('rejects a negative port (-1)', () => {
    expect(() => parseTomlConfig(kerbSource('port = -1')))
      .toThrow(/port must be an integer between 1 and 65535/);
  });

  it('rejects an out-of-range port (70000)', () => {
    expect(() => parseTomlConfig(kerbSource('port = 70000')))
      .toThrow(/port must be an integer between 1 and 65535/);
  });

  it('rejects port 0 (not a usable TCP port)', () => {
    expect(() => parseTomlConfig(kerbSource('port = 0')))
      .toThrow(/port must be an integer between 1 and 65535/);
  });

  it('accepts a valid integer port and the boundary values 1 and 65535', () => {
    expect(parseTomlConfig(kerbSource('port = 2222')).sources[0].port).toBe(2222);
    expect(parseTomlConfig(kerbSource('port = 1')).sources[0].port).toBe(1);
    expect(parseTomlConfig(kerbSource('port = 65535')).sources[0].port).toBe(65535);
  });

  // Finding: gssapi_delegate_credentials is only wired for kerberos auth.
  it('rejects gssapi_delegate_credentials on a password source', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "p"
host = "h"
user = "u"
auth = "password"
password = "pw"
gssapi_delegate_credentials = "yes"
`)).toThrow(/gssapi_delegate_credentials requires auth="kerberos"/);
  });

  it('rejects gssapi_delegate_credentials on a key source', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "kk"
host = "h"
user = "u"
auth = "key"
key_path = "/tmp/id"
gssapi_delegate_credentials = "yes"
`)).toThrow(/gssapi_delegate_credentials requires auth="kerberos"/);
  });

  it('still accepts gssapi_delegate_credentials on a kerberos source', () => {
    const cfg = parseTomlConfig(kerbSource('gssapi_delegate_credentials = "yes"'));
    expect(cfg.sources[0].gssapiDelegateCredentials).toBe('yes');
  });

  // Finding: [approval.llm].api_key resolution is deferred unless smart mode.
  it('does NOT resolve api_key when approval mode is manual/default (avoids startup failure on missing env)', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[approval]
mode = "manual"

[approval.llm]
api_key = "env:MISSING_KEY"
`, { env: {} });
    // No throw despite MISSING_KEY being unset, and api_key stays unresolved.
    expect(cfg.approval?.llm?.api_key).toBeUndefined();
  });

  it('does NOT resolve api_key when [approval] omits mode entirely', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[approval.llm]
api_key = "env:MISSING_KEY"
`, { env: {} });
    expect(cfg.approval?.llm?.api_key).toBeUndefined();
  });

  it('still resolves api_key when smart mode is enabled', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[approval]
mode = "smart"

[approval.llm]
api_key = "env:KEY"
`, { env: { KEY: 'sk-xyz' } });
    expect(cfg.approval?.llm?.api_key).toBe('sk-xyz');
  });

  // Finding: ignoreSources skips validating suppressed [[sources]] entirely.
  it('ignoreSources skips validation + secret resolution of [[sources]] and keeps top-level sections', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "prod"
host = "prod.example"
user = "u"
auth = "password"
password = "env:PROD_PASS_UNSET"

[webui]
enabled = true
host = "127.0.0.1"
port = 8099
`, { ignoreSources: true, env: {} });
    // The suppressed source's unset env: secret must NOT abort parsing.
    expect(cfg.sources).toEqual([]);
    expect(cfg.webui?.enabled).toBe(true);
    expect(cfg.webui?.port).toBe(8099);
  });

  it('without ignoreSources, the same unset-secret source still throws', () => {
    expect(() => parseTomlConfig(`
[[sources]]
id = "prod"
host = "prod.example"
user = "u"
auth = "password"
password = "env:PROD_PASS_UNSET"
`, { env: {} })).toThrow(/PROD_PASS_UNSET|not set or empty/);
  });
});
