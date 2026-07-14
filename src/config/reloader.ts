/**
 * ConfigReloader — the "what" of TOML hot reload (PR-9, Decision D4).
 *
 * `config-watcher.ts` decides WHEN to reload (debounced fs.watch); this module
 * decides WHAT a reload does, with dbhub's exact safety contract:
 *
 *   parse → validate-before-swap → swap → rollback-on-failure → emit event.
 *
 * Reload SCOPE (Decision D4): connections (the registry's named sources +
 * params), per-source descriptions, and approval policy (global default +
 * static per-source modes). It does NOT touch the MCP tool list — that set
 * (`exec`/`sudo-exec`/`list-servers`) is static and registered once at startup,
 * so a STDIO client never has to reconnect (see README "TOML watch / hot
 * reload" and the dbhub STDIO caveat).
 *
 * Safety guarantees:
 *  - A config that fails to parse/validate leaves every existing connection and
 *    the current approval policy exactly as they were (the operator keeps
 *    serving). The failure is logged, never thrown to the watcher.
 *  - The swap is transactional: registry + approval policy are captured up
 *    front and restored together if ANY step throws, so a partial apply can't
 *    leave the server in a Frankenstein half-old/half-new state.
 *  - All mutation is in-memory (D3): a reload reseeds from the file but writes
 *    nothing back, so it can never feedback-loop with the watcher.
 */

import { EventEmitter } from 'node:events';
import type { ResolvedConfig, ApprovalMode } from './types.js';
import { resolveApprovalEngineInput, resolveEffectiveDefaultMode } from './approval-policy.js';
import type { ServerConfig } from '../transports/types.js';
import type { RegistryStateSnapshot } from '../transports/registry.js';
import type { ModeStoreState } from '../approval/mode-store.js';
import { DEFAULT_SMART_LLM_TIMEOUT_MS, type SmartLlmSnapshot } from '../approval/smart.js';
import { isSmartLlmPreArmable } from '../approval/engine.js';

/** The registry surface the reloader drives (subset of TransportRegistry). */
export interface RegistryReloadTarget {
  getAllConfigs(): ServerConfig[];
  snapshotState(): RegistryStateSnapshot;
  restoreState(snap: RegistryStateSnapshot): void;
  replaceAll(sources: ServerConfig[], defaultName?: string): void;
  /**
   * Apply the reloaded `[server].require_connection` value to the multi-source
   * omit-name guard. A reload must re-project this exactly like boot
   * (applyRegistryConnectionPolicy) so a file that flips the setting takes
   * effect without a restart; captured in snapshotState() so a rolled-back swap
   * restores the pre-swap guard state.
   */
  setRequireConnectionWhenMulti(required: boolean): void;
  closeAll(): Promise<void>;
  /**
   * Close ONLY the transports whose source was removed or whose connection
   * parameters changed relative to `previousConfigs`, preserving the live
   * persistent transports of sources whose connection params are unchanged.
   * A reload that only edits descriptions or approval policy must not tear
   * down healthy in-flight ssh2 connections (Codex V5 finding). `previousConfigs`
   * is the pre-swap config map (from `snapshotState().configs`).
   */
  closeChanged(previousConfigs: Map<string, ServerConfig>): Promise<void>;
  names(): string[];
  getDefaultName(): string | null;
}

/** The approval surface the reloader drives (subset of ApprovalDispatcher). */
export interface ApprovalReloadTarget {
  reloadPolicy(input: { defaultMode?: ApprovalMode; staticOverrides?: Record<string, ApprovalMode> }): void;
  captureModeState(): ModeStoreState;
  restoreModeState(state: ModeStoreState): void;
  /**
   * Snapshot of the live smart sub-engine's LLM settings, or `null` when no
   * smart engine is armed. Sub-engines are built once at boot and never rebuilt
   * on reload, so the reloader compares this against the incoming file to reject
   * an `[approval.llm]` change that would otherwise silently keep using stale
   * boot-time settings (Codex V5 finding).
   */
  describeSmartLlm(): SmartLlmSnapshot | null;
}

/** Outcome of one reload attempt — surfaced to logs and (on success) SSE. */
export interface ConfigReloadResult {
  ok: boolean;
  /** Why a reload was skipped / rolled back. Present iff `ok === false`. */
  reason?: string;
  /** Registered connection names AFTER the attempt (old set on failure). */
  sources: string[];
  /** Effective default connection name AFTER the attempt. */
  defaultName: string | null;
  at: string;
}

/** Payload broadcast as the `config-reloaded` SSE event (success only). */
export interface ConfigReloadedEvent {
  sources: string[];
  defaultName: string | null;
  at: string;
}

export interface ConfigReloaderOptions {
  registry: RegistryReloadTarget;
  /**
   * Loads + validates the config from disk. MUST throw on any parse/validation
   * error (the reloader treats a throw as "keep the old config"). In production
   * this wraps `resolveConfig()` against the same precedence chain used at boot.
   */
  loadConfig: () => ResolvedConfig;
  /** Optional approval engine to reseed in lockstep with the registry. */
  engine?: ApprovalReloadTarget;
  /**
   * Optional async hook applied to the new sources before they are registered
   * (e.g. read ssh2 key files into memory). Mirrors index.ts `prepareKeyContents`.
   * A throw here aborts the swap and rolls back.
   */
  prepareSources?: (sources: ServerConfig[]) => Promise<void>;
  /** Optional log sink (defaults to console.error). */
  log?: (msg: string) => void;
}

function assertSmartPolicyHasCurrentLlm(config: ResolvedConfig): void {
  const input = resolveApprovalEngineInput(config);
  if (input === null) return;

  const effectiveModes: ApprovalMode[] = [
    resolveEffectiveDefaultMode(config),
    ...Object.values(config.perSourceApproval ?? {}),
  ];
  if (!effectiveModes.includes('smart')) return;

  if (!input.llm?.endpoint || !input.llm?.model) {
    throw new Error('approval mode "smart" on reload requires current [approval.llm].endpoint and .model');
  }
}

/** True when the reloaded config resolves smart as an effective (default or per-source) mode. */
function reloadSelectsSmart(config: ResolvedConfig): boolean {
  const effectiveModes: ApprovalMode[] = [
    resolveEffectiveDefaultMode(config),
    ...Object.values(config.perSourceApproval ?? {}),
  ];
  return effectiveModes.includes('smart');
}

/**
 * Reject a reload that CHANGES OR REMOVES the live smart engine's LLM settings.
 * The SmartApproval sub-engine is constructed once at boot and never rebuilt on
 * reload (reloadPolicy only reseeds the mode store), so an edited
 * `[approval.llm]` block — endpoint/model/api_key/timeout_ms/provider or the
 * associated fail_closed flag — would be reported as applied while approvals
 * keep hitting the stale boot-time engine. Removing the block entirely is the
 * same trap: the armed sub-engine survives and stays WebUI-selectable, so a
 * later switch back to smart hits settings the on-disk file claims are gone.
 *
 * This must run whenever a smart engine is armed, even if the reloaded policy
 * currently resolves to yolo/manual. Otherwise an operator can edit or delete
 * inactive `[approval.llm]`, then later flip back to smart and expect the new
 * (or absent) endpoint / model / key to be honored while the process still
 * holds the boot-time engine. Missing endpoint/model for an actually-selected
 * smart policy is still handled by assertSmartPolicyHasCurrentLlm +
 * reloadPolicy's assertSwitchable.
 */
function assertSmartLlmUnchanged(config: ResolvedConfig, engine?: ApprovalReloadTarget): void {
  const live = engine?.describeSmartLlm() ?? null;
  const llm = config.approval?.llm;
  if (live === null) {
    // Preserve blocks that would also leave smart unavailable on a fresh boot.
    // Unsupported/incomplete/unresolved blocks are always inert. A PRE-ARMABLE
    // block is also inert when there is no live dispatcher AND the incoming
    // config is LLM-only: buildProductionApprovalEngine returns null for that
    // shape when WebUI is disabled, so a source/description-only reload has the
    // same yolo/no-engine semantics as a fresh boot. (When WebUI is active a
    // synthetic dispatcher always exists, so `engine` cannot be absent here.)
    if (!isSmartLlmPreArmable(llm)) return;
    if (!engine && resolveApprovalEngineInput(config) === null && !reloadSelectsSmart(config)) {
      return;
    }
    // Otherwise a fresh boot would construct/expose smart (explicit policy,
    // per-source policy, or a WebUI synthetic dispatcher), but this process
    // cannot add a SmartApproval sub-engine during reload.
    throw new Error(
      'new approval [approval.llm] config cannot be hot-reloaded while the smart engine is not armed ' +
      '(the smart engine is built once at boot) — restart to apply',
    );
  }

  if (!llm) {
    // The reloaded file has REMOVED the `[approval.llm]` block (or the whole
    // `[approval]` section) while a smart sub-engine is still armed from boot.
    // The sub-engine is never rebuilt, and buildApprovalEngineFromConfig
    // PRE-ARMS smart whenever the LLM is fully configured, so the WebUI keeps
    // listing `smart` in availableModes() even while the current policy resolves
    // to yolo/manual. An operator who later switches back to smart would hit the
    // STALE boot-time endpoint/model/key that the on-disk config claims no longer
    // exists — the same stale-config trap as an edited block, and a divergence
    // between fresh boot (which would fail to arm smart) and hot reload. Reject
    // and roll back; restart to actually drop the LLM settings / disarm smart.
    throw new Error(
      'smart approval [approval.llm] removed while the smart engine is armed ' +
      'cannot be hot-reloaded (the smart engine is built once at boot) — restart to apply',
    );
  }

  const nextProvider = (llm.provider as string | undefined) ?? 'openai';
  const nextFailClosed = config.approval?.fail_closed !== false; // default true
  const changed: string[] = [];
  if ((llm.endpoint ?? undefined) !== live.endpoint) changed.push('endpoint');
  if ((llm.model ?? undefined) !== live.model) changed.push('model');
  if (llm.api_key_unresolved || (llm.api_key ?? undefined) !== (live.api_key ?? undefined)) {
    changed.push('api_key');
  }
  const nextTimeoutMs = llm.timeout_ms ?? DEFAULT_SMART_LLM_TIMEOUT_MS;
  const liveTimeoutMs = live.timeout_ms ?? DEFAULT_SMART_LLM_TIMEOUT_MS;
  if (nextTimeoutMs !== liveTimeoutMs) changed.push('timeout_ms');
  if (nextProvider !== live.provider) changed.push('provider');
  if (nextFailClosed !== live.fail_closed) changed.push('fail_closed');

  if (changed.length > 0) {
    throw new Error(
      `smart approval [approval.llm] change (${changed.join(', ')}) cannot be hot-reloaded ` +
      `(the smart engine is built once at boot) — restart to apply`,
    );
  }
}

/**
 * Owns the reload transaction and emits `config-reloaded` on success. Construct
 * once at boot; call `reload()` from the watcher's debounced `onChange`.
 */
export class ConfigReloader extends EventEmitter {
  private readonly registry: RegistryReloadTarget;
  private readonly loadConfig: () => ResolvedConfig;
  private readonly engine?: ApprovalReloadTarget;
  private readonly prepareSources?: (sources: ServerConfig[]) => Promise<void>;
  private readonly log: (msg: string) => void;

  constructor(opts: ConfigReloaderOptions) {
    super();
    this.registry = opts.registry;
    this.loadConfig = opts.loadConfig;
    this.engine = opts.engine;
    this.prepareSources = opts.prepareSources;
    this.log = opts.log ?? ((m: string) => console.error(m));
  }

  /** Snapshot of the registry's current source names (for failure reporting). */
  private currentSources(): string[] {
    return this.registry.names();
  }

  /**
   * Run one reload transaction. Never throws — every failure mode returns a
   * `ConfigReloadResult` with `ok:false` and a reason, leaving the live config
   * untouched. On success, registers the new sources, reseeds approval policy,
   * closes stale transports, and emits `config-reloaded`.
   */
  async reload(): Promise<ConfigReloadResult> {
    const at = new Date().toISOString();

    // --- 1. Parse + validate. A throw here means keep the old config. -------
    let next: ResolvedConfig;
    try {
      next = this.loadConfig();
    } catch (err: any) {
      const reason = `parse/validation failed: ${err?.message || err}`;
      this.log(`Config reload: ${reason} — keeping existing connections.`);
      return { ok: false, reason, sources: this.currentSources(), defaultName: this.registry.getDefaultName(), at };
    }

    if (!next.sources || next.sources.length === 0) {
      const reason = 'new config has no sources';
      this.log(`Config reload: ${reason} — keeping existing connections.`);
      return { ok: false, reason, sources: this.currentSources(), defaultName: this.registry.getDefaultName(), at };
    }

    // --- 2. Capture state for rollback. ------------------------------------
    const registrySnap = this.registry.snapshotState();
    const engineSnap = this.engine?.captureModeState();

    // --- 3. Swap, validate-before-commit per layer, rollback on any error. --
    try {
      // Whether an approval dispatcher exists or not, a newly pre-armable LLM
      // block cannot be applied without constructing a smart sub-engine. Keep
      // selected-smart validation first so an incomplete current block reports
      // the direct boot-parity error before the broader stale-engine guard.
      if (this.engine) assertSmartPolicyHasCurrentLlm(next);
      assertSmartLlmUnchanged(next, this.engine);

      // Security guard (no-engine path): when the server booted WITHOUT an
      // approval engine (no [approval] policy + WebUI disabled), gateApproval
      // falls back to `legacy:no-engine` allow — effectively yolo. A reload
      // can reseed the registry, but it CANNOT arm an engine that wasn't built
      // at boot (sub-engines are constructed once; see ApprovalDispatcher). So
      // if the new file introduces a policy that would CHANGE enforcement
      // (any default or per-source mode other than yolo), applying the rest of
      // the reload would silently report success while commands stay
      // unenforced — a config that requires approval on a fresh boot would run
      // wide open after a hot reload. Reject and roll back instead. Switching
      // INTO manual/smart needs a restart (documented in the README).
      if (!this.engine) {
        // Compute the modes the NEW file would ENFORCE the same way boot does.
        // The global default must go through resolveEffectiveDefaultMode(), not
        // a raw `next.approval?.mode` read: a bare/knob-only [approval] block
        // (e.g. `[approval]\nfail_closed = true`, no `mode`) resolves to the
        // documented `manual` at boot, so reading only `next.approval?.mode`
        // (undefined) would miss that the new file is enforcing and let the
        // reload silently "succeed" with approval still unarmed.
        const introduced: ApprovalMode[] = [resolveEffectiveDefaultMode(next)];
        for (const m of Object.values(next.perSourceApproval ?? {})) introduced.push(m);
        const enforcing = introduced.find(m => m !== 'yolo');
        if (enforcing) {
          throw new Error(
            `new config selects approval mode "${enforcing}" but no approval engine is armed ` +
            `(server booted with no [approval] policy and WebUI disabled) — restart to arm it`,
          );
        }
      }

      if (this.prepareSources) {
        await this.prepareSources(next.sources);
      }
      // registry.replaceAll validates (dup names, unknown default) before it
      // mutates, so a bad source list throws here with the registry untouched.
      //
      // Pass the explicit default ONLY when the operator actually chose one
      // (`default = true` on a source → defaultExplicit). Boot keys the
      // multi-source omit-name guard on defaultExplicit: for a config with
      // several `[[sources]]` and no explicit default, resolveConfig() sets
      // `defaultName` to the FIRST source merely as a routing fallback while
      // `defaultExplicit` stays false, and boot deliberately does NOT call
      // setDefault(). Forwarding `next.defaultName` unconditionally here would
      // make replaceAll() treat that positional fallback as an explicit default
      // (defaultExplicit=true), so after the first hot reload the same config
      // would start routing omitted `connectionName` calls to the first host
      // instead of rejecting them — a silent multi-host safety regression that
      // boot never has. Mirror boot: only forward an EXPLICIT default.
      this.registry.replaceAll(
        next.sources,
        next.defaultExplicit ? next.defaultName : undefined,
      );

      // Apply the reloaded [server].require_connection to the omit-name guard,
      // exactly like boot's applyRegistryConnectionPolicy (absent field → safe
      // default ON). Without this the guard is sticky from boot: a server
      // started with require_connection=false would keep accepting omitted
      // connectionName even after the file is edited to true (or the field
      // removed), leaving the unsafe opt-out active until restart. Captured in
      // snapshotState() above, so a later rollback restores the pre-swap value.
      this.registry.setRequireConnectionWhenMulti(next.requireConnection ?? true);

      // Approval policy reseed validates the new modes name armed engines
      // before mutating; an unarmed mode throws ModeUnavailableError. Smart is
      // stricter than mere engine availability: a server booted with an old LLM
      // endpoint may have the smart sub-engine armed, but a reload whose CURRENT
      // file still selects smart must also carry a complete current LLM block so
      // fresh boot and hot reload enforce the same config validity.
      if (this.engine) {
        this.engine.reloadPolicy({
          // Resolve the effective global default the SAME way boot does
          // (resolveEffectiveDefaultMode): a bare/knob-only [approval] block
          // documents `manual`, and a per-source-only config keeps `yolo`.
          // Passing the raw `next.approval?.mode` (undefined for those shapes)
          // would let reloadPolicy's `?? 'yolo'` silently downgrade a manual
          // boot policy to yolo — disabling approval until restart.
          defaultMode: resolveEffectiveDefaultMode(next),
          staticOverrides: next.perSourceApproval ?? {},
        });
      }

      // Drop ONLY the transports whose source was removed or whose connection
      // parameters changed, so a host whose params changed re-dials lazily with
      // the new config. Sources whose connection params are UNCHANGED keep their
      // live persistent ssh2 transport — a reload that only edits descriptions
      // or approval policy must not interrupt an in-flight command on a healthy
      // connection. Best-effort: a close failure must not fail the reload (the
      // config is already swapped and valid). `registrySnap.configs` is the
      // pre-swap config map captured above.
      try {
        await this.registry.closeChanged(registrySnap.configs);
      } catch (closeErr: any) {
        this.log(`Config reload: closing stale transports failed (continuing): ${closeErr?.message || closeErr}`);
      }
    } catch (err: any) {
      // Roll back BOTH layers together so they never diverge.
      this.registry.restoreState(registrySnap);
      if (this.engine && engineSnap) this.engine.restoreModeState(engineSnap);
      const reason = `swap failed, rolled back: ${err?.message || err}`;
      this.log(`Config reload: ${reason}`);
      return { ok: false, reason, sources: this.currentSources(), defaultName: this.registry.getDefaultName(), at };
    }

    // --- 4. Success: broadcast. --------------------------------------------
    const sources = this.registry.names();
    const defaultName = this.registry.getDefaultName();
    this.log(`Config reload: applied — ${sources.length} source(s): ${sources.join(', ')}`);
    const event: ConfigReloadedEvent = { sources, defaultName, at };
    this.emit('config-reloaded', event);
    return { ok: true, sources, defaultName, at };
  }
}
