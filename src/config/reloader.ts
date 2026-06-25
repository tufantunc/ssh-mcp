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
import type { ServerConfig } from '../transports/types.js';
import type { RegistryStateSnapshot } from '../transports/registry.js';
import type { ModeStoreState } from '../approval/mode-store.js';

/** The registry surface the reloader drives (subset of TransportRegistry). */
export interface RegistryReloadTarget {
  getAllConfigs(): ServerConfig[];
  snapshotState(): RegistryStateSnapshot;
  restoreState(snap: RegistryStateSnapshot): void;
  replaceAll(sources: ServerConfig[], defaultName?: string): void;
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
      if (this.prepareSources) {
        await this.prepareSources(next.sources);
      }
      // registry.replaceAll validates (dup names, unknown default) before it
      // mutates, so a bad source list throws here with the registry untouched.
      this.registry.replaceAll(next.sources, next.defaultName);

      // Approval policy reseed validates the new modes name armed engines
      // before mutating; an unarmed mode throws ModeUnavailableError.
      if (this.engine) {
        this.engine.reloadPolicy({
          defaultMode: next.approval?.mode,
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
