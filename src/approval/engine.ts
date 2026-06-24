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
  ManualApprovalOptions,
  PendingApproval,
  SmartApprovalOptions,
} from './types.js';
import { YoloApproval } from './yolo.js';
import { SmartApproval } from './smart.js';
import { ManualApproval } from './manual.js';

export interface BuildApprovalEngineOptions {
  /** Default approval mode when a source has no [sources.approval] override. */
  defaultMode: ApprovalMode;
  /** Smart-mode config; required when defaultMode or any per-source override uses smart. */
  smart?: SmartApprovalOptions;
  /** Manual-mode config; required when defaultMode or any per-source override uses manual. */
  manual?: ManualApprovalOptions;
}

/**
 * Dispatch engine that owns one instance per mode. Lazy-builds per-mode
 * engines so a yolo-only deployment never has to configure smart or manual.
 */
export class ApprovalDispatcher extends EventEmitter implements ApprovalEngine {
  private readonly yolo = new YoloApproval();
  private readonly smart?: SmartApproval;
  private readonly manual?: ManualApproval;

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

  async decide(ctx: ApprovalContext): Promise<ApprovalDecision> {
    const effective = ctx.profile.approval?.mode ?? this.opts.defaultMode;
    const engine = this.requireEngineFor(effective);
    return engine.decide(ctx);
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
  const defaultMode: ApprovalMode = approval?.defaultMode ?? 'yolo';
  const perSource = approval?.perSourceModes ?? [];
  const usedModes = new Set<ApprovalMode>([defaultMode, ...perSource]);

  const built: BuildApprovalEngineOptions = { defaultMode };

  if (usedModes.has('smart')) {
    const llm = approval?.llm;
    if (!llm?.endpoint || !llm?.model) {
      throw new Error('approval mode "smart" requires [approval.llm].endpoint and .model');
    }
    built.smart = {
      llm: {
        endpoint: llm.endpoint,
        api_key: llm.api_key,
        model: llm.model,
        timeout_ms: llm.timeout_ms,
        provider: (llm.provider as 'openai' | 'anthropic' | 'azure' | undefined) ?? 'openai',
      },
      fail_closed: approval?.fail_closed !== false,
      fetchImpl: options.smartFetchImpl,
    };
  }

  if (usedModes.has('manual')) {
    built.manual = {
      webuiEnabled: options.manualOpts.webuiEnabled,
      timeout_ms: options.manualOpts.timeout_ms,
    };
  }

  return new ApprovalDispatcher(built);
}
