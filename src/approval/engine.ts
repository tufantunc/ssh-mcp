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
import { ManualApproval } from './manual.js';
import { ApprovalModeStore } from './mode-store.js';

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

  constructor(private readonly opts: BuildApprovalEngineOptions) {
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
   * The mode `decide()` falls back to when a source carries no per-source
   * override (`ctx.profile.approval?.mode`). Exposed read-only so status
   * surfaces (e.g. the WebUI `/api/profiles` view) can report the
   * genuinely-enforced default instead of guessing a different fallback.
   */
  get defaultMode(): ApprovalMode {
    return this.opts.defaultMode;
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
  const usedModes = new Set<ApprovalMode>([defaultMode, ...perSource]);

  const built: BuildApprovalEngineOptions = {
    defaultMode,
    staticOverrides: approval?.staticOverrides,
  };

  // Smart: required-by-config when any used mode is 'smart'. Additionally,
  // PRE-ARM smart whenever the LLM is fully configured so the WebUI can
  // live-switch into it without a restart — arming an unused-but-configured
  // engine is harmless (it only resolves decisions when selected).
  const llm = approval?.llm;
  const llmConfigured = !!(llm?.endpoint && llm?.model);
  if (usedModes.has('smart') && !llmConfigured) {
    throw new Error('approval mode "smart" requires [approval.llm].endpoint and .model');
  }
  if (llmConfigured) {
    built.smart = {
      llm: {
        endpoint: llm!.endpoint!,
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
