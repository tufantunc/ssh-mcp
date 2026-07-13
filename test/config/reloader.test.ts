/**
 * reloader.ts — ConfigReloader transaction (PR-9, the WHAT-of-reload).
 *
 * Drives a REAL TransportRegistry + REAL ApprovalDispatcher through the
 * parse→validate→swap→rollback contract using in-memory TOML strings (no SSH
 * host, no disk config — `loadConfig` is a closure the test controls). Asserts
 * the acceptance criteria directly:
 *   - a good reload swaps the connection set + reseeds approval policy + emits
 *     `config-reloaded`
 *   - a config whose loader THROWS preserves the old connections (no event)
 *   - a config that fails the registry swap rolls BOTH registry + approval
 *     policy back together (no half-apply, no event)
 *   - live description overrides (D3) are dropped on a successful reload
 *   - in-memory only: no fs write-back surface is touched
 */
import { describe, it, expect, vi } from 'vitest';

import { ConfigReloader } from '../../src/config/reloader.js';
import type { ConfigReloadedEvent } from '../../src/config/reloader.js';
import { parseTomlConfig } from '../../src/config/toml-loader.js';
import type { ResolvedConfig } from '../../src/config/types.js';
import { TransportRegistry } from '../../src/transports/registry.js';
import type { ServerConfig } from '../../src/transports/types.js';
import { ApprovalDispatcher } from '../../src/approval/engine.js';

const TOML_A = `
[approval]
mode = "yolo"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
description = "alpha box"

[[sources]]
id = "beta"
host = "beta.example"
user = "root"
auth = "kerberos"
`;

// Adds a third source, drops beta, flips global policy to manual.
const TOML_B = `
[approval]
mode = "manual"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"

[[sources]]
id = "gamma"
host = "gamma.example"
user = "root"
auth = "kerberos"
approval = { mode = "manual" }
`;

function freshRegistry(toml: string): TransportRegistry {
  const cfg = parseTomlConfig(toml);
  const reg = new TransportRegistry();
  for (const src of cfg.sources) reg.register(src);
  if (cfg.defaultName) reg.setDefault(cfg.defaultName);
  return reg;
}

/** Manual-armed dispatcher so a reload to manual policy is switchable. */
function freshEngine(): ApprovalDispatcher {
  return new ApprovalDispatcher({
    defaultMode: 'yolo',
    manual: { webuiEnabled: true, timeout_ms: 1000 },
  });
}

describe('ConfigReloader — successful reload', () => {
  it('swaps connections, reseeds approval policy, and emits config-reloaded', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = freshEngine();
    let loaded = parseTomlConfig(TOML_A) as ResolvedConfig;

    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => loaded,
      log: () => {},
    });

    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    // Sanity: boot state.
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(engine.getGlobalMode()).toBe('yolo');

    // Point the loader at config B and reload.
    loaded = parseTomlConfig(TOML_B) as ResolvedConfig;
    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    expect(registry.names()).toEqual(['alpha', 'gamma']);
    expect(registry.getDefaultName()).toBe('alpha');
    // Approval policy reseeded: global -> manual, gamma static override -> manual.
    expect(engine.getGlobalMode()).toBe('manual');
    expect(engine.getEffectiveMode('gamma')).toBe('manual');
    // SSE event fired exactly once with the new source list.
    expect(events).toHaveLength(1);
    expect(events[0].sources).toEqual(['alpha', 'gamma']);
  });

  it('drops live description overrides (D3) on a successful reload', async () => {
    const registry = freshRegistry(TOML_A);
    let loaded = parseTomlConfig(TOML_A) as ResolvedConfig;
    const reloader = new ConfigReloader({ registry, loadConfig: () => loaded, log: () => {} });

    // A live edit sets an override that out-prioritises the TOML description.
    registry.setDescription('alpha', 'LIVE override');
    expect(registry.getEffectiveDescription('alpha')).toBe('LIVE override');

    loaded = parseTomlConfig(TOML_A) as ResolvedConfig;
    const res = await reloader.reload();
    expect(res.ok).toBe(true);
    // Override gone; TOML description is the source of truth again.
    expect(registry.getDescriptionOverride('alpha')).toBeUndefined();
    expect(registry.getEffectiveDescription('alpha')).toBe('alpha box');
  });
});

describe('ConfigReloader — bad config preserves the old connections', () => {
  it('keeps existing connections when the loader throws (parse failure)', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = freshEngine();
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => { throw new Error('Config: TOML parse failed: boom'); },
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/parse\/validation failed/);
    // Old connections untouched; no event.
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(engine.getGlobalMode()).toBe('yolo');
    expect(events).toHaveLength(0);
  });

  it('keeps existing connections when the new config has zero sources', async () => {
    const registry = freshRegistry(TOML_A);
    const reloader = new ConfigReloader({
      registry,
      loadConfig: () => ({ sources: [], perSourceApproval: {} } as ResolvedConfig),
      log: () => {},
    });
    const res = await reloader.reload();
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/no sources/);
    expect(registry.names()).toEqual(['alpha', 'beta']);
  });
});

describe('ConfigReloader — rollback on swap failure', () => {
  it('rolls back registry AND approval policy together when prepareSources throws', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = freshEngine();
    let loaded = parseTomlConfig(TOML_B) as ResolvedConfig;

    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => loaded,
      // Fail mid-swap, AFTER load+validate but BEFORE registry.replaceAll commits.
      prepareSources: async () => { throw new Error('key file unreadable'); },
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    // Everything is exactly as it was at boot — no half-apply.
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(registry.getDefaultName()).toBe('alpha');
    expect(engine.getGlobalMode()).toBe('yolo');
    expect(events).toHaveLength(0);
  });

  it('rolls back when the new policy names an unarmed engine (smart with no LLM)', async () => {
    const registry = freshRegistry(TOML_A);
    // yolo-only engine: NOT armed for smart.
    const engine = new ApprovalDispatcher({ defaultMode: 'yolo' });
    const smartToml = `
[approval]
mode = "smart"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(smartToml) as ResolvedConfig,
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    // Registry rolled back too even though IT would have accepted the swap —
    // the two layers move together.
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(engine.getGlobalMode()).toBe('yolo');
    expect(events).toHaveLength(0);
  });

  it('rejects a smart reload that would keep using a stale boot-time LLM config', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = new ApprovalDispatcher({
      defaultMode: 'smart',
      smart: { llm: { endpoint: 'https://old.example/v1/chat/completions', model: 'old-model' } },
    });
    const smartWithoutCurrentLlmToml = `
[approval]
mode = "smart"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(smartWithoutCurrentLlmToml) as ResolvedConfig,
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    expect(res.reason).toMatch(/smart.*\[approval\.llm\]\.endpoint and \.model/);
    expect(engine.getGlobalMode()).toBe('smart');
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(events).toHaveLength(0);
  });

  it('rejects a per-source smart reload unless the new file still carries current LLM settings', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = new ApprovalDispatcher({
      defaultMode: 'yolo',
      smart: { llm: { endpoint: 'https://old.example/v1/chat/completions', model: 'old-model' } },
    });
    const perSourceSmartWithoutLlmToml = `
[approval]
mode = "yolo"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
approval = { mode = "smart" }
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(perSourceSmartWithoutLlmToml) as ResolvedConfig,
      log: () => {},
    });

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/smart.*\[approval\.llm\]\.endpoint and \.model/);
    expect(engine.getEffectiveMode('alpha')).toBe('yolo');
    expect(registry.names()).toEqual(['alpha', 'beta']);
  });
});

describe('ConfigReloader — no approval engine wired (security: cannot silently apply unenforced policy)', () => {
  // The most likely real-world trap: server booted with NO [approval] section
  // and WebUI off -> buildProductionApprovalEngine returns null -> the reloader
  // is constructed WITHOUT an engine. gateApproval is then legacy:no-engine
  // (allow). A hot reload can reseed connections but cannot ARM an engine that
  // was never built, so a new config that selects manual/smart/per-source
  // non-yolo must be REJECTED and rolled back — never reported as applied.
  it('rejects + rolls back a reload that introduces a global manual policy', async () => {
    const registry = freshRegistry(TOML_A);
    // No engine passed — exactly the no-[approval]/WebUI-off boot shape.
    const reloader = new ConfigReloader({
      registry,
      loadConfig: () => parseTomlConfig(TOML_B) as ResolvedConfig, // [approval] mode = "manual"
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    expect(res.reason).toMatch(/no approval engine is armed/);
    // Connections untouched (no half-apply), no success event.
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(registry.getDefaultName()).toBe('alpha');
    expect(events).toHaveLength(0);
  });

  it('rejects + rolls back a reload that introduces a per-source non-yolo policy', async () => {
    const registry = freshRegistry(TOML_A);
    const perSourceManualToml = `
[approval]
mode = "yolo"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"

[[sources]]
id = "beta"
host = "beta.example"
user = "root"
auth = "kerberos"
approval = { mode = "manual" }
`;
    const reloader = new ConfigReloader({
      registry,
      loadConfig: () => parseTomlConfig(perSourceManualToml) as ResolvedConfig,
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/no approval engine is armed/);
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(events).toHaveLength(0);
  });

  it('still applies a no-engine reload when the new policy is yolo / absent (no enforcement change)', async () => {
    const registry = freshRegistry(TOML_A);
    // New file keeps everything yolo (TOML_A is mode = "yolo") but swaps the
    // source set, proving the guard only blocks ENFORCEMENT-changing policies.
    const yoloSwapToml = `
[approval]
mode = "yolo"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"

[[sources]]
id = "gamma"
host = "gamma.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      loadConfig: () => parseTomlConfig(yoloSwapToml) as ResolvedConfig,
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    expect(registry.names()).toEqual(['alpha', 'gamma']);
    expect(events).toHaveLength(1);
  });
});

describe('ConfigReloader — boot/reload parity (Codex round: findings 1-3)', () => {
  // These mimic resolveConfig()'s PRODUCTION output shape, which parseTomlConfig
  // does NOT reproduce: for a multi-source TOML with no explicit default,
  // resolveConfig() sets `defaultName` to the first source POSITIONALLY while
  // keeping `defaultExplicit=false`. parseTomlConfig leaves defaultName
  // undefined instead, so a test that reloads a parseTomlConfig() result would
  // never exercise the "positional fallback leaks as explicit default" bug.
  function resolvedShape(over: Partial<ResolvedConfig> & { sources: ResolvedConfig['sources'] }): ResolvedConfig {
    return {
      defaultExplicit: false,
      perSourceApproval: {},
      ...over,
    } as ResolvedConfig;
  }

  const twoSourcesNoDefault = () => {
    const cfg = parseTomlConfig(TOML_A); // alpha + beta, [approval] mode = yolo
    return resolvedShape({
      sources: cfg.sources,
      // resolveConfig's positional fallback: names the first source but marks
      // it NON-explicit so the omit-name guard must stay armed.
      defaultName: cfg.sources[0].name,
      defaultExplicit: false,
      perSourceApproval: {},
      approval: { mode: 'yolo' },
    });
  };

  it('finding 1: a positional (non-explicit) default does NOT arm the omit-name shortcut after reload', async () => {
    const registry = freshRegistry(TOML_A); // alpha+beta, no explicit default → guard armed
    // Guard is armed at boot: omit-name rejects.
    expect(() => registry.getEffectiveDescription()).toThrow(/connectionName is required/);

    let loaded = twoSourcesNoDefault();
    const reloader = new ConfigReloader({ registry, loadConfig: () => loaded, log: () => {} });
    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    // The bug: forwarding next.defaultName unconditionally would flip
    // defaultExplicit=true and let omit-name silently route to the first host.
    // Fixed: the guard stays armed because the default was only positional.
    expect(() => registry.getEffectiveDescription()).toThrow(/connectionName is required/);
    expect(registry.getDefaultName()).toBe('alpha');
  });

  it('finding 1: an EXPLICIT default still re-arms omit-name across a reload', async () => {
    const registry = freshRegistry(TOML_A);
    const loaded = resolvedShape({
      sources: parseTomlConfig(TOML_A).sources,
      defaultName: 'beta',
      defaultExplicit: true, // user chose default = true on beta
      approval: { mode: 'yolo' },
    });
    const reloader = new ConfigReloader({ registry, loadConfig: () => loaded, log: () => {} });
    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    // Explicit default → omit-name resolves to beta instead of throwing.
    expect(() => registry.getEffectiveDescription()).not.toThrow();
    expect(registry.getDefaultName()).toBe('beta');
  });

  it('finding 2: a bare [approval] block (no mode) reloads to manual, not yolo', async () => {
    const registry = freshRegistry(TOML_A);
    // Manual-armed engine (so a manual reload IS switchable). Boot default yolo.
    const engine = freshEngine();
    expect(engine.getGlobalMode()).toBe('yolo');

    // The reloaded file has an [approval] block with ONLY fail_closed (no mode).
    // Boot resolves that to the documented 'manual'; the reloader must too —
    // reading raw next.approval?.mode (undefined) would let reloadPolicy default
    // it to yolo, silently disabling approval until restart.
    const loaded = resolvedShape({
      sources: parseTomlConfig(TOML_A).sources,
      defaultName: parseTomlConfig(TOML_A).sources[0].name,
      defaultExplicit: false,
      approval: { fail_closed: true }, // bare knob, no mode
    });
    const reloader = new ConfigReloader({ registry, engine, loadConfig: () => loaded, log: () => {} });
    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    expect(engine.getGlobalMode()).toBe('manual');
  });

  it('finding 2: the no-engine guard REJECTS a bare [approval] block (would silently enforce)', async () => {
    const registry = freshRegistry(TOML_A);
    // No engine — the no-[approval]/WebUI-off boot shape.
    const loaded = resolvedShape({
      sources: parseTomlConfig(TOML_A).sources,
      defaultName: parseTomlConfig(TOML_A).sources[0].name,
      defaultExplicit: false,
      approval: { fail_closed: true }, // resolves to manual → enforcing
    });
    const reloader = new ConfigReloader({ registry, loadConfig: () => loaded, log: () => {} });
    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/no approval engine is armed/);
    // The bug: keying on raw next.approval?.mode (undefined) would MISS that the
    // file enforces manual and let the reload "succeed" with approval unarmed.
    expect(registry.names()).toEqual(['alpha', 'beta']);
  });

  it('finding 3: require_connection = false in the reloaded file opts OUT the guard live', async () => {
    const registry = freshRegistry(TOML_A); // guard armed at boot
    expect(() => registry.getEffectiveDescription()).toThrow(/connectionName is required/);

    const loaded = resolvedShape({
      sources: parseTomlConfig(TOML_A).sources,
      defaultName: parseTomlConfig(TOML_A).sources[0].name,
      defaultExplicit: false,
      requireConnection: false, // operator edited [server] to disable the guard
      approval: { mode: 'yolo' },
    });
    const reloader = new ConfigReloader({ registry, loadConfig: () => loaded, log: () => {} });
    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    // Guard now opted out: omit-name falls back to the first host instead of throwing.
    expect(() => registry.getEffectiveDescription()).not.toThrow();
  });

  it('finding 3: require_connection re-tightens to true on a later reload (not sticky from boot)', async () => {
    // Start from a registry booted with the guard OFF.
    const registry = freshRegistry(TOML_A);
    registry.setRequireConnectionWhenMulti(false);
    expect(() => registry.getEffectiveDescription()).not.toThrow();

    const loaded = resolvedShape({
      sources: parseTomlConfig(TOML_A).sources,
      defaultName: parseTomlConfig(TOML_A).sources[0].name,
      defaultExplicit: false,
      requireConnection: true, // file edited to re-enable the guard
      approval: { mode: 'yolo' },
    });
    const reloader = new ConfigReloader({ registry, loadConfig: () => loaded, log: () => {} });
    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    // The bug: sticky-from-boot would keep accepting omitted connectionName.
    // Fixed: the guard re-arms because the reload applied require_connection=true.
    expect(() => registry.getEffectiveDescription()).toThrow(/connectionName is required/);
  });

  it('finding 3: a rolled-back reload restores the pre-swap require_connection state', async () => {
    const registry = freshRegistry(TOML_A);
    registry.setRequireConnectionWhenMulti(false); // guard OFF before the swap
    expect(() => registry.getEffectiveDescription()).not.toThrow();

    // A reload that would set the guard ON but then FAILS mid-swap (prepareSources
    // throws AFTER replaceAll + setRequireConnectionWhenMulti already ran) must
    // roll the guard back to its pre-swap OFF state, not leave it stuck ON.
    const loaded = resolvedShape({
      sources: parseTomlConfig(TOML_B).sources, // alpha + gamma
      defaultName: parseTomlConfig(TOML_B).sources[0].name,
      defaultExplicit: false,
      requireConnection: true,
      approval: { mode: 'yolo' },
      perSourceApproval: {},
    });
    const reloader = new ConfigReloader({
      registry,
      loadConfig: () => loaded,
      prepareSources: async () => { throw new Error('key file unreadable'); },
      log: () => {},
    });
    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    // Guard restored to OFF (pre-swap), and the source set is unchanged.
    expect(() => registry.getEffectiveDescription()).not.toThrow();
    expect(registry.names()).toEqual(['alpha', 'beta']);
  });
});

describe('ConfigReloader — lazy key prep on reload (Codex R4 finding 2: boot/reload parity)', () => {
  // Boot reads ssh2 key files LAZILY inside registry.get(name) (the registry's
  // prepareConfig hook), so a source with an unreadable/unmounted key only
  // fails when that host is used — a bad UNUSED key never breaks startup. The
  // fixed buildConfigReloader mirrors this by passing NO eager `prepareSources`
  // hook, so a reload does not pre-read every source's key. These two tests
  // reproduce both wirings to pin the regression: the OLD eager hook rolls the
  // whole reload back on one unreadable key; the FIXED no-hook wiring applies.

  // Mirrors index.ts prepareKeyContents: reads the ssh2 key file eagerly.
  const eagerPrepareKeyContents = async (sources: ServerConfig[]) => {
    const fs = await import('node:fs/promises');
    for (const cfg of sources) {
      if (cfg.transport === 'ssh2' && cfg.keyPath && !cfg.privateKey) {
        cfg.privateKey = await fs.readFile(cfg.keyPath, 'utf8'); // throws ENOENT
      }
    }
  };

  // A reloaded config whose second (kept) source is an ssh2 host with a key
  // path that does not exist on disk. Only the parse/registry layers should run.
  const withUnreadableSsh2Key = (): ResolvedConfig => ({
    sources: [
      { name: 'alpha', host: 'alpha.example', port: 22, username: 'root', authMode: 'kerberos', transport: 'openssh', kerberos: true },
      { name: 'keyhost', host: 'keyhost.example', port: 22, username: 'root', authMode: 'key', transport: 'ssh2', keyPath: '/nonexistent/ssh-mcp/id_ed25519' },
    ],
    perSourceApproval: {},
    defaultExplicit: false,
    approval: { mode: 'yolo' },
  } as ResolvedConfig);

  it('FIXED wiring (no prepareSources): applies the reload even when a source key is unreadable', async () => {
    const registry = freshRegistry(TOML_A);
    const reloader = new ConfigReloader({
      registry,
      loadConfig: () => withUnreadableSsh2Key(),
      // No prepareSources — key reads stay lazy, deferred to registry.get().
      log: () => {},
    });
    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    // The swap applied: an unused source's bad key never rolled it back.
    expect(registry.names()).toEqual(['alpha', 'keyhost']);
  });

  it('OLD wiring (eager prepareSources): the same unreadable key rolls the whole reload back', async () => {
    const registry = freshRegistry(TOML_A);
    const reloader = new ConfigReloader({
      registry,
      loadConfig: () => withUnreadableSsh2Key(),
      // The pre-fix buildConfigReloader passed exactly this eager hook, which
      // pre-reads EVERY source's key before the swap — one ENOENT aborts and
      // rolls back edits to unrelated healthy sources. This is the regression.
      prepareSources: eagerPrepareKeyContents,
      log: () => {},
    });
    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    // The old connection set is preserved (the reload never applied).
    expect(registry.names()).toEqual(['alpha', 'beta']);
  });
});

describe('ConfigReloader — in-memory only (no disk write-back)', () => {
  it('never mutates the config file on disk during a reload', async () => {
    const { mkdtempSync, rmSync, writeFileSync, readFileSync, statSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');

    const dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-reload-nowrite-'));
    const cfgFile = join(dir, 'config.toml');
    writeFileSync(cfgFile, TOML_A);
    const before = readFileSync(cfgFile, 'utf8');
    const beforeMtime = statSync(cfgFile).mtimeMs;

    try {
      const registry = freshRegistry(TOML_A);
      // A reload that genuinely swaps the source set (TOML_B) — the most likely
      // moment a buggy implementation might "persist" back to disk. TOML_B flips
      // policy to manual, so wire a manual-armed engine; otherwise the no-engine
      // enforcement guard would (correctly) reject the manual policy and this
      // test would never exercise the actual swap path it cares about.
      const reloader = new ConfigReloader({
        registry,
        engine: freshEngine(),
        loadConfig: () => parseTomlConfig(TOML_B) as ResolvedConfig,
        log: () => {},
      });
      const res = await reloader.reload();
      expect(res.ok).toBe(true);
      expect(registry.names()).toEqual(['alpha', 'gamma']);

      // The on-disk file is byte-identical and untouched (mtime unchanged).
      expect(readFileSync(cfgFile, 'utf8')).toBe(before);
      expect(statSync(cfgFile).mtimeMs).toBe(beforeMtime);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('exposes no fs/write/persist member on the reloader instance', () => {
    const registry = freshRegistry(TOML_A);
    const reloader = new ConfigReloader({
      registry,
      loadConfig: () => parseTomlConfig(TOML_A) as ResolvedConfig,
      log: () => {},
    }) as any;
    for (const k of Object.keys(reloader)) {
      expect(k.toLowerCase()).not.toMatch(/writeback|persist|savefile/);
    }
  });
});

describe('ConfigReloader — smart [approval.llm] change is rejected (Codex V5 finding 1)', () => {
  // The SmartApproval sub-engine is built ONCE at boot and never rebuilt on
  // reload (reloadPolicy only reseeds the mode store). So a reload that edits
  // [approval.llm] while smart stays the effective mode would be reported as
  // applied while approvals keep hitting the STALE boot-time endpoint/model/key.
  // The reloader must reject + roll back such a change; an unchanged LLM block
  // (only source/description edits) must still reload fine.
  const smartToml = (endpoint: string, model: string, apiKey: string, extra = '') => `
[approval]
mode = "smart"
${extra}
[approval.llm]
endpoint = "${endpoint}"
model = "${model}"
api_key = "${apiKey}"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
`;

  function smartArmedEngine(): ApprovalDispatcher {
    return new ApprovalDispatcher({
      defaultMode: 'smart',
      smart: { llm: { endpoint: 'https://llm.old/v1/chat/completions', model: 'gpt-old', api_key: 'boot-key' } },
    });
  }

  it('rejects an inactive LLM addition when smart was not armed at boot', async () => {
    const registry = freshRegistry(TOML_A);
    // Mirrors a WebUI-enabled yolo/manual process: an approval dispatcher exists,
    // but no SmartApproval sub-engine was constructed at boot.
    const engine = freshEngine();
    expect(engine.availableModes()).not.toContain('smart');
    const inactiveLlmAddition = `
[approval]
mode = "yolo"

[approval.llm]
endpoint = "https://llm.new/v1/chat/completions"
model = "gpt-new"
api_key = "new-key"

[[sources]]
id = "gamma"
host = "gamma.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(inactiveLlmAddition) as ResolvedConfig,
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/\[approval\.llm\].*cannot be hot-reloaded/);
    expect(res.reason).toMatch(/smart engine is not armed/);
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(engine.availableModes()).not.toContain('smart');
    expect(events).toHaveLength(0);
  });

  it('rejects + rolls back a reload that changes the LLM endpoint', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = smartArmedEngine();
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () =>
        parseTomlConfig(smartToml('https://llm.NEW/v1/chat/completions', 'gpt-old', 'boot-key')) as ResolvedConfig,
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    expect(res.reason).toMatch(/\[approval\.llm\] change/);
    expect(res.reason).toMatch(/endpoint/);
    // Connections untouched, no success event.
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(events).toHaveLength(0);
  });

  it('rejects an LLM endpoint edit even when the reloaded policy currently selects yolo', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = smartArmedEngine();
    const inactiveSmartLlmEdit = `
[approval]
mode = "yolo"

[approval.llm]
endpoint = "https://llm.NEW/v1/chat/completions"
model = "gpt-old"
api_key = "boot-key"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(inactiveSmartLlmEdit) as ResolvedConfig,
      log: () => {},
    });

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/\[approval\.llm\] change/);
    expect(res.reason).toMatch(/endpoint/);
    expect(registry.names()).toEqual(['alpha', 'beta']);
  });

  it('rejects an unresolved api_key while smart is armed but currently inactive', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = new ApprovalDispatcher({
      defaultMode: 'yolo',
      smart: { llm: { endpoint: 'http://127.0.0.1:11434/v1/chat/completions', model: 'local-model' } },
    });
    const unresolvedKeyWhileYolo = `
[approval]
mode = "yolo"

[approval.llm]
endpoint = "http://127.0.0.1:11434/v1/chat/completions"
model = "local-model"
api_key = "env:MISSING_KEY"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(unresolvedKeyWhileYolo, { env: {} }) as ResolvedConfig,
      log: () => {},
    });

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    expect(res.reason).toMatch(/api_key/);
    expect(registry.names()).toEqual(['alpha', 'beta']);
  });

  it('rejects a reload that only rotates the api_key', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = smartArmedEngine();
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () =>
        parseTomlConfig(smartToml('https://llm.old/v1/chat/completions', 'gpt-old', 'ROTATED-key')) as ResolvedConfig,
      log: () => {},
    });
    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/\[approval\.llm\] change/);
    expect(res.reason).toMatch(/api_key/);
  });

  it('rejects a reload that changes the model', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = smartArmedEngine();
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () =>
        parseTomlConfig(smartToml('https://llm.old/v1/chat/completions', 'gpt-NEW', 'boot-key')) as ResolvedConfig,
      log: () => {},
    });
    const res = await reloader.reload();
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/model/);
  });

  it('rejects a reload that flips fail_closed', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = smartArmedEngine(); // fail_closed defaults to true
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () =>
        parseTomlConfig(
          smartToml('https://llm.old/v1/chat/completions', 'gpt-old', 'boot-key', 'fail_closed = false'),
        ) as ResolvedConfig,
      log: () => {},
    });
    const res = await reloader.reload();
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/fail_closed/);
  });

  it('rejects a reload that REMOVES the [approval.llm] block while smart is armed but inactive', async () => {
    // Codex V7: smart was armed at boot, but the reloaded file deletes the whole
    // [approval.llm] block while currently selecting yolo. The armed SmartApproval
    // sub-engine survives (never rebuilt) and stays WebUI-selectable, so a later
    // switch back to smart would hit the STALE boot-time endpoint/model/key that
    // the on-disk config claims no longer exists. Must be rejected + rolled back.
    const registry = freshRegistry(TOML_A);
    const engine = smartArmedEngine();
    const removedLlmWhileYolo = `
[approval]
mode = "yolo"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(removedLlmWhileYolo) as ResolvedConfig,
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/rolled back/);
    expect(res.reason).toMatch(/\[approval\.llm\] removed/);
    // Connections + policy untouched, no success event.
    expect(registry.names()).toEqual(['alpha', 'beta']);
    expect(events).toHaveLength(0);
  });

  it('rejects removing the entire [approval] section while smart is armed but inactive', async () => {
    // Even harsher removal: the whole [approval] section is gone, so
    // resolveApprovalEngineInput has no llm to compare, yet the boot smart engine
    // is still armed. A per-source-only config keeps global default yolo; the
    // armed engine must still block the reload rather than silently drop the LLM.
    const registry = freshRegistry(TOML_A);
    const engine = smartArmedEngine();
    const noApprovalSection = `
[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(noApprovalSection) as ResolvedConfig,
      log: () => {},
    });

    const res = await reloader.reload();

    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/\[approval\.llm\] removed/);
    expect(registry.names()).toEqual(['alpha', 'beta']);
  });

  it('ALLOWS a reload that keeps the LLM block byte-identical (only source edits)', async () => {
    const registry = freshRegistry(TOML_A);
    const engine = smartArmedEngine();
    // Same endpoint/model/api_key/fail_closed as boot — a legitimate reload that
    // swaps sources but does not touch [approval.llm]. Must NOT be rejected.
    const sameLlmWithExtraSource = `
[approval]
mode = "smart"

[approval.llm]
endpoint = "https://llm.old/v1/chat/completions"
model = "gpt-old"
api_key = "boot-key"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"

[[sources]]
id = "gamma"
host = "gamma.example"
user = "root"
auth = "kerberos"
`;
    const reloader = new ConfigReloader({
      registry,
      engine,
      loadConfig: () => parseTomlConfig(sameLlmWithExtraSource) as ResolvedConfig,
      log: () => {},
    });
    const events: ConfigReloadedEvent[] = [];
    reloader.on('config-reloaded', e => events.push(e));

    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    expect(registry.names()).toEqual(['alpha', 'gamma']);
    expect(events).toHaveLength(1);
  });
});

describe('ConfigReloader — a successful reload closes only changed transports (Codex V5 finding 3)', () => {
  // A successful reload must call registry.closeChanged(previousConfigs) — NOT
  // the blunt closeAll() — so unchanged sources keep their live persistent ssh2
  // transport and an in-flight command is not interrupted by a description /
  // approval-policy-only edit.
  it('calls closeChanged with the pre-swap config map, never closeAll', async () => {
    const registry = freshRegistry(TOML_A);
    const preSwapConfigs = registry.snapshotState().configs;

    const closeChangedSpy = vi.spyOn(registry, 'closeChanged');
    const closeAllSpy = vi.spyOn(registry, 'closeAll');

    let loaded = parseTomlConfig(TOML_A) as ResolvedConfig;
    const reloader = new ConfigReloader({ registry, loadConfig: () => loaded, log: () => {} });

    // A yolo→yolo reload that only swaps the source set (no engine needed).
    loaded = parseTomlConfig(`
[approval]
mode = "yolo"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"

[[sources]]
id = "gamma"
host = "gamma.example"
user = "root"
auth = "kerberos"
`) as ResolvedConfig;

    const res = await reloader.reload();

    expect(res.ok).toBe(true);
    expect(closeAllSpy).not.toHaveBeenCalled();
    expect(closeChangedSpy).toHaveBeenCalledTimes(1);
    // Passed the pre-swap config map so it can diff old-vs-new params. The map
    // instance differs (snapshot copy), but it must carry the OLD source names.
    const passed = closeChangedSpy.mock.calls[0][0] as Map<string, ServerConfig>;
    expect([...passed.keys()]).toEqual([...preSwapConfigs.keys()]);
    expect([...passed.keys()]).toEqual(['alpha', 'beta']);
  });

  it('a close failure during closeChanged does not fail the reload (best-effort)', async () => {
    const registry = freshRegistry(TOML_A);
    vi.spyOn(registry, 'closeChanged').mockRejectedValueOnce(new Error('transport close boom'));

    let loaded = parseTomlConfig(TOML_A) as ResolvedConfig;
    const reloader = new ConfigReloader({ registry, loadConfig: () => loaded, log: () => {} });
    loaded = parseTomlConfig(`
[approval]
mode = "yolo"

[[sources]]
id = "alpha"
host = "alpha.example"
user = "root"
auth = "kerberos"

[[sources]]
id = "gamma"
host = "gamma.example"
user = "root"
auth = "kerberos"
`) as ResolvedConfig;

    const res = await reloader.reload();
    // The config is already swapped and valid; a close failure only logs.
    expect(res.ok).toBe(true);
    expect(registry.names()).toEqual(['alpha', 'gamma']);
  });
});
