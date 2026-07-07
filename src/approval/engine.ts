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
