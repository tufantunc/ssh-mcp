/**
 * Approval engine entry point.
 *
 * Resolves the effective mode (per-source override > global default) and
 * dispatches to yolo / smart / manual. Returned ApprovalDecision is meant to
 * be appended verbatim into the audit record's `approval` block.
 */

import { EventEmitter } from 'node:events';
import {
  ApprovalContext,
  ApprovalDecision,
  ApprovalEngine,
  ApprovalMode,
  APPROVAL_MODES,
  ManualApprovalOptions,
  ModeChangedPayload,
  PendingApproval,
  SmartApprovalOptions,
} from './types.js';
import { YoloApproval } from './yolo.js';
import { SmartApproval } from './smart.js';
import type { SmartLlmSnapshot } from './smart.js';
import { ManualApproval } from './manual.js';
import { ApprovalModeStore } from './mode-store.js';
import type { ModeStoreState } from './mode-store.js';

export interface BuildApprovalEngineOptions {
  /** Default approval mode when a source has no [sources.approval] override. */
  defaultMode: ApprovalMode;
  /** Smart-mode config; required when defaultMode or any per-source override uses smart. */
  smart?: SmartApprovalOptions;
  /** Manual-mode config; required when defaultMode or any per-source override uses manual. */
  manual?: ManualApprovalOptions;
  /**
   * Static per-source overrides (TOML `[sources.approval].mode`), keyed by
   * source id. Seeds the in-memory mode store's static layer so the WebUI
   * effective-mode lookup and the gate agree on precedence. Live runtime
   * switches sit ON TOP of these; the statics are never mutated.
   */
  staticOverrides?: Record<string, ApprovalMode>;
}

/**
 * Raised when a live mode switch targets a mode whose sub-engine was never
 * armed at boot (e.g. switch to `smart` with no `[approval.llm]`). Callers
 * (the WebUI route) map this to a 400, not a 500 — it is user error, not a
 * server fault, and the store is left untouched (atomic: validate before swap).
 */
export class ModeUnavailableError extends Error {
  constructor(public readonly mode: ApprovalMode, reason: string) {
    super(`approval mode "${mode}" is not available for live switching: ${reason}`);
    this.name = 'ModeUnavailableError';
  }
}

/**
 * Dispatch engine that owns one instance per mode. Sub-engines are built once
 * at construction and never torn down — a live mode switch only re-points which
 * engine NEW decisions resolve to (via the in-memory ApprovalModeStore). That
 * is what makes the hot-swap atomic and race-free: an in-flight manual approval
 * lives inside the persistent ManualApproval instance and is unaffected when the
 * effective mode flips underneath it; `decide()` samples the mode exactly once,
 * up front, then commits to that engine for the lifetime of the call.
 */
export class ApprovalDispatcher extends EventEmitter implements ApprovalEngine {
  private readonly yolo = new YoloApproval();
  private readonly smart?: SmartApproval;
  private readonly manual?: ManualApproval;
  private readonly modeStore: ApprovalModeStore;

  constructor(opts: BuildApprovalEngineOptions) {
    super();
    if (opts.smart) {
      this.smart = new SmartApproval(opts.smart);
    }
    if (opts.manual) {
      // Construction itself enforces the WebUI-required invariant.
      this.manual = new ManualApproval(opts.manual);
      // Forward manual queue events through the dispatcher so the WebUI
      // adapter can subscribe to one place regardless of effective mode.
      this.manual.on('enqueue', (p: PendingApproval) => this.emit('enqueue', p));
      this.manual.on('resolve', (p: PendingApproval, d: ApprovalDecision) =>
        this.emit('resolve', p, d),
      );
    }
    // Eager validate: default mode must have its engine wired.
    this.requireEngineFor(opts.defaultMode);
    // Direct callers can bypass buildApprovalEngineFromConfig and provide
    // static overrides themselves. Validate every seeded mode before exposing
    // it through getEffectiveMode/decide so an unavailable engine fails at
    // construction instead of on the first command for that profile.
    for (const mode of Object.values(opts.staticOverrides ?? {})) {
      this.requireEngineFor(mode);
    }
    // In-memory mutable mode state (Decision D3). Global seeds from the boot
    // default; statics seed from TOML [sources.approval]. Live switches mutate
    // only the store, never disk.
    this.modeStore = new ApprovalModeStore(opts.defaultMode, opts.staticOverrides);
  }

  private requireEngineFor(mode: ApprovalMode): ApprovalEngine {
    switch (mode) {
      case 'yolo':
        return this.yolo;
      case 'smart':
        if (!this.smart) {
          throw new Error(`approval mode "smart" requested but [approval.llm] is not configured`);
        }
        return this.smart;
      case 'manual':
        if (!this.manual) {
          throw new Error(`approval mode "manual" requested but WebUI/manual options are not configured`);
        }
        return this.manual;
      default: {
        const exhaustive: never = mode;
        throw new Error(`unknown approval mode: ${exhaustive}`);
      }
    }
  }

  /**
   * Resolve the effective mode for a decision context. Precedence:
   *   1. live runtime override for this profile (mode store)
   *   2. per-call static override carried on ctx (legacy / TOML-resolved source)
   *   3. mode store static override > live global default
   * Sampled once per decide() call so an in-flight switch can't change the
   * engine a request is mid-way through.
   */
  private effectiveMode(ctx: ApprovalContext): ApprovalMode {
    const id = ctx.profile.id;
    const live = this.modeStore.getLiveOverride(id);
    if (live) return live;
    if (ctx.profile.approval?.mode) return ctx.profile.approval.mode;
    return this.modeStore.effective(id);
  }

  async decide(ctx: ApprovalContext): Promise<ApprovalDecision> {
    const effective = this.effectiveMode(ctx);
    const engine = this.requireEngineFor(effective);
    return engine.decide(ctx);
  }

  /** Modes that can be switched to RIGHT NOW (their sub-engine is armed). */
  availableModes(): ApprovalMode[] {
    return APPROVAL_MODES.filter(m =>
      m === 'yolo' || (m === 'smart' && !!this.smart) || (m === 'manual' && !!this.manual),
    );
  }

  /** Live global default. */
  getGlobalMode(): ApprovalMode {
    return this.modeStore.getGlobal();
  }

  /** Effective mode for a named profile (override > static > global). */
  getEffectiveMode(profileId: string): ApprovalMode {
    const live = this.modeStore.getLiveOverride(profileId);
    if (live) return live;
    return this.modeStore.effective(profileId);
  }

  /**
   * Live-switch the GLOBAL default mode. Validates the target engine is armed
   * (throws ModeUnavailableError, leaving the store untouched) BEFORE mutating —
   * atomic: a rejected switch never half-applies. Emits `mode-changed`.
   */
  setGlobalMode(mode: ApprovalMode): ModeChangedPayload {
    this.assertSwitchable(mode);
    this.modeStore.setGlobal(mode);
    const payload: ModeChangedPayload = {
      scope: 'global',
      mode,
      effective: mode,
      at: new Date().toISOString(),
    };
    this.emit('mode-changed', payload);
    return payload;
  }

  /**
   * Live-switch (or clear, when `mode === null`) a per-profile override.
   * Clearing reveals the static override / global beneath it. Validates the
   * target engine is armed before mutating. Emits `mode-changed` with the
   * profile's resulting effective mode.
   */
  setProfileMode(profileId: string, mode: ApprovalMode | null): ModeChangedPayload {
    if (mode !== null) this.assertSwitchable(mode);
    this.modeStore.setOverride(profileId, mode);
    const effective = this.getEffectiveMode(profileId);
    const payload: ModeChangedPayload = {
      scope: 'profile',
      profileId,
      mode: mode ?? effective,
      effective,
      // Echo the REQUESTED override verbatim (mode string, or null on a clear)
      // so clients can distinguish "override cleared, now showing fallback" from
      // "override set to that same mode". Without this, a clear looks identical
      // to a set and leaves a phantom override in the client's mirror.
      override: mode,
      at: new Date().toISOString(),
    };
    this.emit('mode-changed', payload);
    return payload;
  }

  private assertSwitchable(mode: ApprovalMode): void {
    try {
      this.requireEngineFor(mode);
    } catch (err: any) {
      throw new ModeUnavailableError(mode, err?.message ?? 'engine not configured');
    }
  }

  /**
   * Hot-reload the approval POLICY from a freshly-loaded config (PR-9). Re-seeds
   * the global default + static per-source overrides and clears live runtime
   * overrides, so the edited file becomes the source of truth again.
   *
   * Sub-engines (yolo/smart/manual) are NEVER rebuilt — only the mode store is
   * re-seeded — so this is allocation-free and cannot change which transports
   * or LLM endpoint are wired. That means a reload can only select among modes
   * already armed at boot: a new default/override naming an UNARMED engine
   * (e.g. switch to `smart` when no `[approval.llm]` was configured at startup)
   * is rejected with {@link ModeUnavailableError} and the store is left
   * untouched (validate-before-swap — atomic). The reloader maps that to a
   * kept-old-policy outcome; switching INTO a newly-configured smart/manual
   * engine still requires a restart, exactly like dbhub's tool-list caveat.
   */
  reloadPolicy(input: { defaultMode?: ApprovalMode; staticOverrides?: Record<string, ApprovalMode> }): void {
    const nextDefault: ApprovalMode = input.defaultMode ?? 'yolo';
    const nextStatic = input.staticOverrides ?? {};
    // Validate-before-swap: every mode the new policy can resolve to must have
    // an armed sub-engine. Throws (leaving the store untouched) on the first
    // unarmed mode.
    this.assertSwitchable(nextDefault);
    for (const mode of Object.values(nextStatic)) {
      this.assertSwitchable(mode);
    }
    this.modeStore.reseed(nextDefault, nextStatic);
  }

  /** Capture the mode-store state for external rollback (PR-9). */
  captureModeState(): ModeStoreState {
    return this.modeStore.capture();
  }

  /**
   * Normalized snapshot of the live smart sub-engine's LLM settings, or `null`
   * when no smart engine is armed. The config hot-reload path uses this to
   * reject a reload that edits `[approval.llm]` (endpoint/model/api_key/
   * timeout_ms/provider/fail_closed): sub-engines are built once at boot and
   * never rebuilt on reload, so a changed LLM block would otherwise be reported
   * as applied while approvals keep hitting the stale boot-time endpoint.
   */
  describeSmartLlm(): SmartLlmSnapshot | null {
    return this.smart?.describeConfig() ?? null;
  }

  /** Restore a previously captured mode-store state (PR-9 rollback). */
  restoreModeState(state: ModeStoreState): void {
    this.modeStore.restore(state);
  }

  /**
   * The mode `decide()` falls back to when a source carries no per-source
   * override (`ctx.profile.approval?.mode`). Exposed read-only so status
   * surfaces (e.g. the WebUI `/api/profiles` view) can report the
   * genuinely-enforced default instead of guessing a different fallback.
   */
  get defaultMode(): ApprovalMode {
    return this.modeStore.getGlobal();
  }

  listPending(): PendingApproval[] {
    return this.manual?.listPending() ?? [];
  }

  resolvePending(id: string, decision: 'allow' | 'deny', note?: string, decided_by?: string): boolean {
    if (!this.manual) return false;
    return this.manual.resolvePending(id, decision, note, decided_by);
  }
}

/** Convenience builder mirroring dbhub's factory style. */
export function buildApprovalEngine(opts: BuildApprovalEngineOptions): ApprovalDispatcher {
  return new ApprovalDispatcher(opts);
}

/**
 * Resolve TOML [approval] config into a concrete dispatcher.
 *
 * `manualOpts.webuiEnabled` carries the boot-time decision about whether the
 * WebUI is going to be started — when manual mode is selected (default or per-
 * source) and WebUI is off, ManualApproval's constructor will throw
 * `ManualApprovalDisabledError`. That is the structural gate-12 invariant: do
 * not loosen.
 */
export interface BuildEngineFromConfigInput {
  defaultMode?: ApprovalMode;
  fail_closed?: boolean;
  llm?: {
    endpoint?: string;
    api_key?: string;
    /** Configured key could not be resolved while smart was inactive. */
    api_key_unresolved?: true;
    model?: string;
    timeout_ms?: number;
    provider?: 'openai' | string;
  };
  /** Used to decide whether to also construct a manual sub-engine for per-source overrides. */
  perSourceModes?: ApprovalMode[];
  /**
   * Per-source static approval overrides keyed by source id (TOML
   * [sources.approval].mode). Seeds the dispatcher's in-memory mode store so a
   * live switch starts from the operator's configured baseline.
   */
  staticOverrides?: Record<string, ApprovalMode>;
}

export interface BuildEngineFromConfigOptions {
  manualOpts: { webuiEnabled: boolean; timeout_ms?: number };
  /** Test seam for SmartApproval. */
  smartFetchImpl?: SmartApprovalOptions['fetchImpl'];
}

export function buildApprovalEngineFromConfig(
  approval: BuildEngineFromConfigInput | undefined,
  options: BuildEngineFromConfigOptions,
): ApprovalDispatcher {
  // Default mode mirrors TOML default ('manual' per ApprovalSection comment).
  const defaultMode: ApprovalMode = approval?.defaultMode ?? 'manual';
  const perSource = approval?.perSourceModes ?? [];
  // staticOverrides is a distinct source of per-profile modes (seeded straight
  // into the mode store, see below). A mode declared ONLY there — never in
  // defaultMode or perSourceModes — would otherwise skip sub-engine arming and
  // surface as an effective mode whose engine requireEngineFor() cannot resolve,
  // failing the first decision for that profile. Fold static modes into the
  // arming/validation set so a static-only manual/smart cannot become an
  // unavailable effective mode.
  const staticModes = Object.values(approval?.staticOverrides ?? {});
  const usedModes = new Set<ApprovalMode>([defaultMode, ...perSource, ...staticModes]);

  const built: BuildApprovalEngineOptions = {
    defaultMode,
    staticOverrides: approval?.staticOverrides,
  };

  // Smart: required-by-config when any used mode is 'smart'. Additionally,
  // PRE-ARM smart whenever the LLM is fully configured so the WebUI can
  // live-switch into it without a restart — arming an unused-but-configured
  // engine is harmless (it only resolves decisions when selected).
  const llm = approval?.llm;
  // An explicitly configured key that could not be resolved is different from
  // an omitted optional key (some local endpoints need no auth). Do not pre-arm
  // smart in the unresolved case: advertising it would switch into an engine
  // guaranteed to omit the operator's configured authorization.
  const llmConfigured = !!(llm?.endpoint && llm?.model && !llm?.api_key_unresolved);
  if (usedModes.has('smart') && !llmConfigured) {
    if (llm?.api_key_unresolved) {
      throw new Error('approval mode "smart" requires the configured [approval.llm].api_key to resolve');
    }
    throw new Error('approval mode "smart" requires [approval.llm].endpoint and .model');
  }
  if (llmConfigured) {
    built.smart = {
      llm: {
        endpoint: llm!.endpoint!,
        // validateApproval() preserves a configured key when it resolves. If a
        // configured env key was unavailable, llmConfigured above stays false,
        // so smart is never advertised with silently missing authorization.
        api_key: llm!.api_key,
        model: llm!.model!,
        timeout_ms: llm!.timeout_ms,
        provider: (llm!.provider as 'openai' | 'anthropic' | 'azure' | undefined) ?? 'openai',
      },
      fail_closed: approval?.fail_closed !== false,
      fetchImpl: options.smartFetchImpl,
    };
  }

  // Manual: required-by-config when any used mode is 'manual'. Additionally,
  // PRE-ARM manual whenever the WebUI is active so it can live-switch into
  // manual without a restart. When manual is required but WebUI is off,
  // ManualApproval's constructor throws ManualApprovalDisabledError — the
  // gate-12 invariant — and we must NOT loosen that. (When manual is only
  // pre-armed, webuiEnabled is true, so construction succeeds.)
  if (usedModes.has('manual') || options.manualOpts.webuiEnabled) {
    built.manual = {
      webuiEnabled: options.manualOpts.webuiEnabled,
      timeout_ms: options.manualOpts.timeout_ms,
    };
  }

  return new ApprovalDispatcher(built);
}

/**
 * Boot-time advisory for the manual-mode-without-a-resolver case.
 *
 * `manual` mode enqueues each command and waits for something to settle the
 * queue (`resolvePending`) — in practice the WebUI manual-approval server. That
 * server lands in the child lane `pr/webui-manual-approval`; the approval-engine
 * lane ships the engine + queue primitive but wires no resolver. When this build
 * boots `manual` mode with the WebUI enabled but no resolver present (i.e. the
 * approval-engine lane merged standalone, ahead of its child lane), every
 * pending approval sits in the queue until it times out and is denied.
 *
 * That is a legitimate stacked-PR state, NOT a fatal error (keep boot
 * succeeding — do not throw). But it is otherwise silent, so surface a
 * non-fatal warning. Returns the warning text when it should fire, or `null`
 * when it should not:
 *   - WebUI disabled: `manual` mode is already fatal-at-boot (gate-12
 *     invariant, ManualApprovalDisabledError) — no warning needed here.
 *   - resolver wired (child lane present): the queue is driven — no warning.
 *   - `manual` mode not in use (yolo/smart only): nothing enqueues — no warning.
 *
 * `defaultMode` mirrors buildApprovalEngineFromConfig: an omitted default
 * resolves to `manual`, so the bare-[approval] case is covered.
 */
export function manualWithoutResolverWarning(params: {
  webuiEnabled: boolean;
  defaultMode?: ApprovalMode;
  perSourceModes?: ApprovalMode[];
  resolverWired: boolean;
}): string | null {
  if (!params.webuiEnabled || params.resolverWired) return null;
  const defaultMode: ApprovalMode = params.defaultMode ?? 'manual';
  const usedModes = new Set<ApprovalMode>([defaultMode, ...(params.perSourceModes ?? [])]);
  if (!usedModes.has('manual')) return null;
  return (
    'approval mode "manual" is active but no approval resolver is wired in this ' +
    'build; pending approvals will time out until the WebUI manual-approval ' +
    'server (pr/webui-manual-approval) is present. This is expected when the ' +
    'approval-engine lane is used standalone ahead of its child lane.'
  );
}
