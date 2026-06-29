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
import { describe, it, expect } from 'vitest';

import { ConfigReloader } from '../reloader.js';
import type { ConfigReloadedEvent } from '../reloader.js';
import { parseTomlConfig } from '../toml-loader.js';
import type { ResolvedConfig } from '../types.js';
import { TransportRegistry } from '../../transports/registry.js';
import { ApprovalDispatcher } from '../../approval/engine.js';

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
