import { describe, it, expect } from 'vitest';
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  resultToMcpContent,
  isFailedExecResult,
  resolveAuthMode,
  buildTransportConfig,
  hasLegacyCliFlags,
  buildApprovalProfile,
  approvalTargetForConnection,
  buildProductionApprovalEngine,
  makeApprovalModeLookup,
  appendDescriptionComment,
  resolveApprovalEngineInput,
  resolveConfiguredApprovalMode,
  preResolutionProfileName,
  approvalResolverWarningFromInput,
  isCliSwitchEnabled,
  prepareKeyContents,
  validateConfig,
  resolveCliConfigPath,
  buildWebUIApprovalQueueAdapter,
  validateSshCliFlag,
} from '../src/index';
import { ApprovalDispatcher } from '../src/approval/engine';
import { TransportRegistry } from '../src/transports/registry';
import type { ExecResult, ServerConfig } from '../src/transports/types';
import type { ResolvedConfig } from '../src/config/types';

// Pure-function unit tests for the CLI config/result mapping layer. These
// import from src/index, which is safe because the test runner sets
// SSH_MCP_DISABLE_MAIN=1 (isCliEnabled=false) so no server/CLI side effects run
// on import.

function runCliStartup(args: string[], envOverrides: NodeJS.ProcessEnv): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.SSH_MCP_DISABLE_MAIN;
  delete env.SSH_MCP_TEST;
  for (const [key, value] of Object.entries(envOverrides)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts', ...args], {
      cwd: process.cwd(),
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error(`CLI startup did not exit within timeout. stdout=${stdout} stderr=${stderr}`));
    }, 10000);

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timeout);
      resolve({ code, stdout, stderr });
    });
  });
}

describe('CLI bootstrap validation order', () => {
  it('reports incomplete legacy CLI args before loading auto-discovered TOML (Codex 3551304743)', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-cli-order-'));
    const badToml = path.join(dir, 'bad.toml');
    await fs.writeFile(badToml, '[[sources]]\nid = "broken"\npassword = "unterminated\n');
    try {
      const result = await runCliStartup(['--host=h'], {
        SSH_MCP_CONFIG: badToml,
        XDG_CONFIG_HOME: path.join(dir, 'xdg'),
        HOME: dir,
      });
      expect(result.code).not.toBe(0);
      expect(result.stderr).toContain('Missing required --user');
      expect(result.stderr).not.toContain('TOML parse failed');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects bare --ssh before falling back to an auto-discovered TOML source', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-cli-bare-ssh-'));
    const validToml = path.join(dir, 'config.toml');
    await fs.writeFile(validToml, `
[[sources]]
id = "toml-fallback"
host = "toml.example"
user = "u"
auth = "kerberos"
`);
    try {
      const result = await runCliStartup(['--ssh'], {
        SSH_MCP_CONFIG: validToml,
        XDG_CONFIG_HOME: path.join(dir, 'xdg'),
        HOME: dir,
      });
      expect(result.code).not.toBe(0);
      expect(result.stderr).toContain('--ssh requires a value (--ssh=<JSON>)');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
  it('treats --webui=false as disabled while validating TOML WebUI settings', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-cli-webui-false-'));
    const config = path.join(dir, 'config.toml');
    await fs.writeFile(config, `
[webui]
enabled = false
host = "0.0.0.0"
auth_token = "env:WEBUI_TOKEN_MISSING"

[approval]
mode = "manual"

[[sources]]
id = "test"
host = "test.example"
user = "u"
auth = "kerberos"
`);
    try {
      const result = await runCliStartup([`--config=${config}`, '--webui=false'], {
        WEBUI_TOKEN_MISSING: undefined,
        XDG_CONFIG_HOME: path.join(dir, 'xdg'),
        HOME: dir,
      });
      expect(result.code).not.toBe(0);
      expect(result.stderr).toContain('manual approval mode requires WebUI to be enabled');
      expect(result.stderr).not.toContain('WEBUI_TOKEN_MISSING');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('lets explicit --webui=false override TOML enabled=true before boot validation', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-cli-webui-override-'));
    const config = path.join(dir, 'config.toml');
    await fs.writeFile(config, `
[webui]
enabled = true
host = "0.0.0.0"
auth_token = "env:WEBUI_TOKEN_MISSING"

[approval]
mode = "manual"

[[sources]]
id = "test"
host = "test.example"
user = "u"
auth = "kerberos"
`);
    try {
      const result = await runCliStartup([`--config=${config}`, '--webui=false'], {
        WEBUI_TOKEN_MISSING: undefined,
        XDG_CONFIG_HOME: path.join(dir, 'xdg'),
        HOME: dir,
      });
      expect(result.code).not.toBe(0);
      expect(result.stderr).toContain('manual approval mode requires WebUI to be enabled');
      expect(result.stderr).not.toContain('WEBUI_TOKEN_MISSING');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});

describe('validateSshCliFlag', () => {
  it('rejects the null marker produced by a bare --ssh', () => {
    expect(() => validateSshCliFlag({ ssh: null }))
      .toThrow(/--ssh requires a value/);
  });

  it('leaves absent --ssh handling to the selected legacy or TOML mode', () => {
    expect(() => validateSshCliFlag({})).not.toThrow();
  });
});

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

  it('classifies mapper-throwing ExecResult values as audit failures, not successes', () => {
    expect(isFailedExecResult({ stdout: '', stderr: '', exitCode: 0 })).toBe(false);
    expect(isFailedExecResult({ stdout: '', stderr: '', exitCode: 1 })).toBe(true);
    expect(isFailedExecResult({ stdout: '', stderr: '', exitCode: null, category: 'timeout' })).toBe(true);
    expect(isFailedExecResult({ stdout: '', stderr: 'auth failed', exitCode: 0, category: 'auth' })).toBe(true);
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

describe('approval command/context helpers', () => {
  const resolvedConfig = (partial: Partial<ResolvedConfig> = {}): ResolvedConfig => ({
    sources: [],
    perSourceApproval: {},
    defaultExplicit: false,
    ...partial,
  });

  it('threads per-source approval mode and source description into the approval profile', () => {
    const profile = buildApprovalProfile(
      'prod',
      { prod: 'manual' },
      { description: 'production host; maintenance window required' },
    );

    expect(profile).toEqual({
      id: 'prod',
      description: 'production host; maintenance window required',
      approval: { mode: 'manual' },
    });
  });

  it('uses the live registry description when building the command approval target', () => {
    const registry = new TransportRegistry();
    registry.register({
      name: 'prod',
      host: 'prod.example.com',
      port: 22,
      username: 'operator',
      transport: 'openssh',
      authMode: 'kerberos',
      description: 'boot policy',
      approval: { mode: 'manual' },
    });
    registry.setDescription('prod', 'live edited policy');

    expect(approvalTargetForConnection(registry, 'prod')).toEqual({
      profile: 'prod',
      approvalProfile: {
        id: 'prod',
        description: 'live edited policy',
        approval: { mode: 'manual' },
      },
    });
  });

  it('does not leak another source approval mode into the default profile', () => {
    const profile = buildApprovalProfile('default', { prod: 'smart' });
    expect(profile).toEqual({ id: 'default' });
  });

  it('does not treat inherited Object.prototype members as approval overrides', () => {
    expect(buildApprovalProfile('constructor', {})).toEqual({ id: 'constructor' });
    expect(buildApprovalProfile('toString', {})).toEqual({ id: 'toString' });
  });

  it('WebUI approval-mode lookup ignores inherited Object.prototype keys (Codex 3568536828)', () => {
    const engine = { defaultMode: 'smart' as const };
    const lookup = makeApprovalModeLookup({
      perSourceApproval: { prod: 'manual' },
      getEngine: () => engine,
    });
    // Own override wins; anything else falls back to the engine default —
    // including profiles named after Object.prototype members, which the old
    // `perSource[name] ?? default` read as inherited functions.
    expect(lookup('prod')).toBe('manual');
    expect(lookup('staging')).toBe('smart');
    expect(lookup('toString')).toBe('smart');
    expect(lookup('constructor')).toBe('smart');
    expect(lookup('hasOwnProperty')).toBe('smart');
    // No engine wired -> legacy no-engine allow path is advertised as yolo.
    const noEngine = makeApprovalModeLookup({
      perSourceApproval: {},
      getEngine: () => null,
    });
    expect(noEngine('toString')).toBe('yolo');
  });

  it('reads a profile mode mutation from the live WebUI controller on the next lookup', () => {
    const engine = buildProductionApprovalEngine(true, resolvedConfig({
      approval: { mode: 'yolo' },
      perSourceApproval: { prod: 'yolo' },
    }))!;
    const modeController = {
      getEffectiveMode: (profileId: string) => engine.getEffectiveMode(profileId),
    };
    const lookup = makeApprovalModeLookup({
      perSourceApproval: { prod: 'yolo' },
      getEngine: () => engine,
      modeController,
    });

    expect(lookup('prod')).toBe('yolo');
    engine.setProfileMode('prod', 'manual');
    expect(lookup('prod')).toBe('manual');
  });

  it('neutralizes description newlines before appending the shell comment', () => {
    const assembled = appendDescriptionComment('true', 'safe note\nrm -rf /tmp/should-not-run # nested');
    expect(assembled).toMatch(/^true # /);
    expect(assembled).toContain('rm -rf /tmp/should-not-run');
    expect(assembled).not.toMatch(/[\r\n]/);
  });

  it('treats no [approval] and no per-source overrides as approval inactive', () => {
    const input = resolveApprovalEngineInput(resolvedConfig());
    expect(input).toBeNull();
    expect(approvalResolverWarningFromInput(input, {
      webuiEnabled: true,
      resolverWired: false,
    })).toBeNull();
  });

  it('uses yolo as the default only for per-source-only approval configs', () => {
    expect(resolveApprovalEngineInput(resolvedConfig({
      perSourceApproval: { lab: 'manual' },
    }))?.defaultMode).toBe('yolo');
  });

  it('keeps yolo default for [approval.llm]-only configs that support per-source smart', () => {
    expect(resolveApprovalEngineInput(resolvedConfig({
      approval: { llm: { endpoint: 'https://api.example/v1/c', model: 'm-1', api_key: 'sk-test' } },
      perSourceApproval: { lab: 'smart' },
    }))?.defaultMode).toBe('yolo');
  });

  it('keeps [approval.llm]-only config inactive without a smart mode selection', () => {
    expect(resolveApprovalEngineInput(resolvedConfig({
      approval: { llm: { endpoint: 'https://api.example/v1/c', model: 'm-1' } },
    }))).toBeNull();
  });

  it('builds an LLM-only WebUI engine with a yolo baseline and live smart switching', () => {
    const engine = buildProductionApprovalEngine(true, resolvedConfig({
      approval: {
        llm: {
          endpoint: 'https://api.example/v1/c',
          model: 'm-1',
        },
      },
    }));

    expect(engine).not.toBeNull();
    expect(engine!.getGlobalMode()).toBe('yolo');
    expect(engine!.availableModes()).toContain('smart');
    engine!.setGlobalMode('smart');
    expect(engine!.getGlobalMode()).toBe('smart');
  });

  it('parses --webui=false as disabled while preserving the bare flag', () => {
    expect(isCliSwitchEnabled({ webui: 'false' }, 'webui')).toBe(false);
    expect(isCliSwitchEnabled({ webui: 'FALSE' }, 'webui')).toBe(false);
    expect(isCliSwitchEnabled({ webui: null }, 'webui')).toBe(true);
    expect(isCliSwitchEnabled({}, 'webui')).toBe(false);
  });

  it('preserves the documented manual default when a top-level approval option is configured', () => {
    const input = resolveApprovalEngineInput(resolvedConfig({
      approval: { fail_closed: true },
      perSourceApproval: { lab: 'yolo' },
    }));
    expect(input?.defaultMode).toBeUndefined();
    expect(input?.fail_closed).toBe(true);
  });

  it('redacts pending command and description text before WebUI list and enqueue exposure', async () => {
    const engine = new ApprovalDispatcher({
      defaultMode: 'manual',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });
    const queue = buildWebUIApprovalQueueAdapter(engine)!;
    let enqueued: ReturnType<typeof queue.list>[number] | undefined;
    queue.on('enqueue', pending => { enqueued = pending; });

    const decision = engine.decide({
      profile: { id: 'prod' },
      tool: 'exec',
      command: 'deploy --token=live-credential',
      description: 'password another-credential',
    });
    await Promise.resolve();

    const listed = queue.list()[0];
    expect(listed.command).toBe('deploy --token=<redacted>');
    expect(listed.description).toBe('password <redacted>');
    expect(enqueued?.command).toBe(listed.command);
    expect(enqueued?.description).toBe(listed.description);

    engine.resolvePending(listed.id, 'deny', 'test cleanup', 'test');
    await decision;
  });

  it('bounds pending command and description text before WebUI list and enqueue exposure', async () => {
    const engine = new ApprovalDispatcher({
      defaultMode: 'manual',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });
    const queue = buildWebUIApprovalQueueAdapter(engine)!;
    const secret = 'ghp_' + 'S'.repeat(36);
    const hugeCommand = `deploy --token=${secret} ${'c'.repeat(2 * 1024 * 1024)}`;
    const hugeDescription = `password ${secret} ${'d'.repeat(2 * 1024 * 1024)}`;
    let enqueued: ReturnType<typeof queue.list>[number] | undefined;
    queue.on('enqueue', pending => { enqueued = pending; });

    const decision = engine.decide({
      profile: { id: 'prod' },
      tool: 'exec',
      command: hugeCommand,
      description: hugeDescription,
    });
    await Promise.resolve();

    const listed = queue.list()[0];
    expect(Buffer.byteLength(listed.command, 'utf8')).toBeLessThanOrEqual(16 * 1024);
    expect(Buffer.byteLength(listed.description ?? '', 'utf8')).toBeLessThanOrEqual(16 * 1024);
    expect(listed.command).not.toContain(secret);
    expect(listed.description).not.toContain(secret);
    expect(enqueued).toEqual(listed);

    engine.resolvePending(listed.id, 'deny', 'test cleanup', 'test');
    await decision;
  });

  it('resolves the effective configured mode for audit failures before the gate decides', () => {
    const config = resolvedConfig({
      approval: { mode: 'smart' },
      perSourceApproval: { lab: 'yolo' },
    });

    expect(resolveConfiguredApprovalMode('lab', config)).toBe('yolo');
    expect(resolveConfiguredApprovalMode('unknown', config)).toBe('smart');
    expect(resolveConfiguredApprovalMode('constructor', config)).toBe('smart');
    expect(resolveConfiguredApprovalMode('legacy', resolvedConfig())).toBe('yolo');
  });

  it('keeps a whitespace connection name unresolved instead of attributing it to the default profile', () => {
    expect(preResolutionProfileName('   ', 'prod', false)).toBe('   ');
    expect(preResolutionProfileName('', 'prod', false)).toBe('prod');
    expect(preResolutionProfileName(undefined, 'prod', true)).toBe('(unresolved)');
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

describe('prepareKeyContents (Codex 3549295046: skip deferred key reads when password auth wins)', () => {
  it('does NOT read a stale keyPath when the resolved authMode is password', async () => {
    // The registry hook must mirror buildTransportConfig()'s eager-read guard:
    // a `--password=... --key=/stale` config records keyPath but authMode is
    // 'password', so the first tool call must use the password, not ENOENT on
    // the stale/nonexistent key file.
    const cfg: ServerConfig = {
      name: 'n',
      host: 'h',
      port: 22,
      username: 'u',
      authMode: 'password',
      transport: 'ssh2',
      password: 'pw',
      keyPath: '/nonexistent/path/to/stale-key',
    };
    await prepareKeyContents(cfg);
    expect(cfg.privateKey).toBeUndefined();
    expect(cfg.password).toBe('pw');
  });

  it('reads the ssh2 keyPath when the resolved authMode is key', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ssh-mcp-test-'));
    const keyPath = path.join(dir, 'id_test');
    await fs.writeFile(keyPath, 'KEYDATA');
    try {
      const cfg: ServerConfig = {
        name: 'n', host: 'h', port: 22, username: 'u',
        authMode: 'key', transport: 'ssh2', keyPath,
      };
      await prepareKeyContents(cfg);
      expect(cfg.privateKey).toBe('KEYDATA');
      await fs.writeFile(keyPath, 'ROTATED');
      await prepareKeyContents(cfg);
      expect(cfg.privateKey).toBe('ROTATED');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('does not read the key for an openssh key config (uses -i path instead)', async () => {
    const cfg: ServerConfig = {
      name: 'n', host: 'h', port: 22, username: 'u',
      authMode: 'key', transport: 'openssh', keyPath: '/nonexistent/path/to/key',
    };
    await prepareKeyContents(cfg);
    expect(cfg.privateKey).toBeUndefined();
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

  it('expands a leading home marker for --config=~/... (Codex 3549260475)', () => {
    expect(resolveCliConfigPath({ config: '~/ssh-mcp/config.toml' }))
      .toBe(path.join(os.homedir(), 'ssh-mcp/config.toml'));
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
