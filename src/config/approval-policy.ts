/**
 * Shared approval-policy resolution (PR-9).
 *
 * Boot (src/index.ts `buildProductionApprovalEngine`) and hot reload
 * (src/config/reloader.ts) must agree EXACTLY on how a `ResolvedConfig`'s
 * `[approval]` section maps to the engine's effective global default mode.
 * They diverged before: boot ran the config through
 * `resolveApprovalEngineInput` + `buildApprovalEngineFromConfig` (whose
 * documented default for a bare `[approval]` block is `manual`), while the
 * reloader passed the RAW `next.approval?.mode` straight through — so a bare
 * `[approval]` (e.g. `[approval]\nfail_closed = true`) resolved to `manual` at
 * boot but silently became `yolo` on the reload path (`reloadPolicy`'s
 * `?? 'yolo'`), disabling approval until restart. Centralising the resolution
 * here makes that class of divergence impossible.
 */

import type { ResolvedConfig, ApprovalMode } from './types.js';
import type { BuildEngineFromConfigInput } from '../approval/engine.js';

/**
 * Resolve the `[approval]` / per-source config into the concrete engine input.
 * Returns null for the legacy CLI path (no `[approval]` section and no
 * per-source overrides) so the gate keeps its backward-compatible
 * `legacy:no-engine` allow.
 *
 * Pure: depends only on the passed `config`. src/index.ts wraps this with a
 * default of the module-level `resolvedConfig` and re-exports it, so the boot
 * engine builder and this reload resolver read the exact same rules.
 */
export function resolveApprovalEngineInput(
  config: ResolvedConfig,
): BuildEngineFromConfigInput | null {
  const approvalCfg = config.approval;
  const perSourceModes: ApprovalMode[] = Object.values(config.perSourceApproval ?? {});
  if (approvalCfg === undefined && perSourceModes.length === 0) {
    return null;
  }
  const approvalLlmOnly = approvalCfg !== undefined
    && approvalCfg.mode === undefined
    && approvalCfg.fail_closed === undefined
    && approvalCfg.llm !== undefined;
  const perSourceOnlyDefault = perSourceModes.length > 0
    && (approvalCfg === undefined || approvalLlmOnly);
  return {
    // Resolve the GLOBAL default mode:
    //  - explicit [approval].mode set        -> honor it.
    //  - no global mode, per-source overrides, and either no [approval] block
    //    or an [approval.llm]-only block -> keep the global default 'yolo'
    //    (unrestricted) so only the overridden sources are gated. Defining
    //    [approval.llm] for a per-source `mode = "smart"` makes
    //    resolvedConfig.approval non-undefined even though no global mode was
    //    requested, so keying solely on `approvalCfg === undefined` would
    //    wrongly fall through to manual here and gate every ungated host (or
    //    throw at boot with WebUI off).
    //  - no global mode but a real top-level approval knob (e.g.
    //    `fail_closed = true`, or a bare [approval] block) was added
    //    deliberately to enable approval; leave defaultMode undefined so
    //    buildApprovalEngineFromConfig applies the documented 'manual' default.
    defaultMode:
      approvalCfg?.mode !== undefined
        ? approvalCfg.mode
        : perSourceOnlyDefault
          ? 'yolo'
          : undefined,
    fail_closed: approvalCfg?.fail_closed,
    llm: approvalCfg?.llm,
    perSourceModes,
  };
}

/**
 * The CONCRETE global default approval mode a `ResolvedConfig` resolves to —
 * i.e. what `buildApprovalEngineFromConfig` would run as the engine's global
 * default for this config. Used by the reloader to (a) decide whether a
 * no-engine reload would silently start enforcing (any mode other than yolo)
 * and (b) reseed `reloadPolicy` with the SAME default boot would have chosen.
 *
 * Mapping (mirrors boot precisely):
 *   - no [approval] section AND no per-source overrides -> 'yolo'
 *     (the legacy no-engine gate is an unconditional allow == yolo behaviour).
 *   - otherwise `resolveApprovalEngineInput(config).defaultMode ?? 'manual'`
 *     (a bare/knob-only [approval] block documents 'manual'; an explicit
 *     mode or per-source-only config keeps its resolved default).
 */
export function resolveEffectiveDefaultMode(config: ResolvedConfig): ApprovalMode {
  const input = resolveApprovalEngineInput(config);
  if (input === null) return 'yolo';
  return input.defaultMode ?? 'manual';
}
