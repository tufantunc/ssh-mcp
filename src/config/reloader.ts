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
import { resolveEffectiveDefaultMode } from './approval-policy.js';
import type { ServerConfig } from '../transports/types.js';
import type { RegistryStateSnapshot } from '../transports/registry.js';
import type { ModeStoreState } from '../approval/mode-store.js';

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
  names(): string[];
  getDefaultName(): string | null;
}

/** The approval surface the reloader drives (subset of ApprovalDispatcher). */
export interface ApprovalReloadTarget {
  reloadPolicy(input: { defaultMode?: ApprovalMode; staticOverrides?: Record<string, ApprovalMode> }): void;
  captureModeState(): ModeStoreState;
  restoreModeState(state: ModeStoreState): void;
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
      // before mutating; an unarmed mode throws ModeUnavailableError.
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

      // Drop stale transports so a host whose params changed re-dials lazily
      // with the new config. Best-effort: a close failure must not fail the
      // reload (the config is already swapped and valid).
      try {
        await this.registry.closeAll();
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
