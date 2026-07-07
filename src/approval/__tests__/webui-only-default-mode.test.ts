import { afterEach, beforeEach, describe, expect, it } from 'vitest';

/**
 * Regression test for the WebUI-only bare-engine default mode (Codex P1).
 *
 * When `--webui`/`[webui].enabled` is used WITHOUT any `[approval]` section or
 * per-source approval override, buildProductionApprovalEngine builds a
 * "synthetic" live-switchable engine. Before the fix it passed
 * `defaultMode: undefined`, which buildApprovalEngineFromConfig coerces to
 * `manual`, so every exec was enqueued/blocked even though no approval was
 * configured — regressing the legacy read-only WebUI/status case. The synthetic
 * engine must default to `yolo` (matching makeApprovalModeLookup's static
 * baseline), while still keeping the WebUI's manual sub-engine pre-armed so a
 * live switch to manual works.
 *
 * Under SSH_MCP_DISABLE_MAIN=1 the module's resolvedConfig is the empty
 * `{ sources: [], perSourceApproval: {} }` literal — i.e. no [approval] section
 * and no per-source overrides — which is exactly the synthetic scenario.
 */
describe('buildProductionApprovalEngine — bare WebUI-only default mode', () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of ['SSH_MCP_DISABLE_MAIN', 'SSH_MCP_TEST']) {
      saved[k] = process.env[k];
    }
    process.env.SSH_MCP_DISABLE_MAIN = '1';
    delete process.env.SSH_MCP_TEST;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it('returns null when the WebUI is inactive (legacy no-engine allow preserved)', async () => {
    const mod = await import('../../index.js');
    expect(mod.buildProductionApprovalEngine(false)).toBeNull();
  });

  it('defaults the synthetic WebUI-only engine to yolo, not manual', async () => {
    const mod = await import('../../index.js');
    const engine = mod.buildProductionApprovalEngine(true);
    expect(engine).not.toBeNull();
    // Global default must be yolo so unconfigured execs are auto-allowed
    // (legacy read-only WebUI/status behavior), not blocked as manual.
    expect(engine!.getGlobalMode()).toBe('yolo');
    // Manual must still be pre-armed so the WebUI can live-switch into it.
    expect(engine!.availableModes()).toContain('manual');
    expect(engine!.availableModes()).toContain('yolo');
  });
});
