/**
 * In-memory mutable approval-mode store (Decision D3: in-memory override only).
 *
 * This is the net-new state that backs the live approval-mode switch (PR-7).
 * It deliberately holds NOTHING on disk: there is no TOML write-back, no file
 * handle, no fs import. A process restart discards every live override and the
 * boot-time TOML config takes over again. That is the whole point of D3 — a
 * runtime switch must never silently mutate the operator's config file or race
 * the config watcher (PR-9).
 *
 * Three layers, highest precedence first:
 *   1. live overrides   — set at runtime via the WebUI (`PUT .../approval-mode`)
 *   2. static overrides — immutable, seeded from `[sources.approval]` TOML
 *   3. global default   — mutable live value; initialised to the boot default
 *
 * `effective(profileId)` walks those layers. Clearing a live override (passing
 * `null`) reveals the static override beneath it, or the global default if the
 * profile had none. The global default is itself live-mutable, so a global
 * switch is felt by every profile that has no override of its own.
 */

import type { ApprovalMode } from './types.js';

export interface ModeStoreSnapshot {
  global: ApprovalMode;
  /** Live runtime overrides only (what the WebUI has changed this session). */
  overrides: Record<string, ApprovalMode>;
}

/**
 * Full capture of every mutable layer (global + static + live), used by the
 * config hot-reload path (PR-9) to roll back a re-seed that fails downstream
 * validation. In-memory only.
 */
export interface ModeStoreState {
  global: ApprovalMode;
  staticOverrides: Record<string, ApprovalMode>;
  liveOverrides: Record<string, ApprovalMode>;
}

export class ApprovalModeStore {
  private global: ApprovalMode;
  private staticOverrides: Map<string, ApprovalMode>;
  private readonly liveOverrides = new Map<string, ApprovalMode>();

  constructor(globalDefault: ApprovalMode, staticOverrides?: Record<string, ApprovalMode>) {
    this.global = globalDefault;
    this.staticOverrides = new Map(Object.entries(staticOverrides ?? {}));
  }

  /** The current live global default. */
  getGlobal(): ApprovalMode {
    return this.global;
  }

  /** Replace the global default. In-memory only. */
  setGlobal(mode: ApprovalMode): void {
    this.global = mode;
  }

  /** Live runtime override for `profileId`, if one has been set this session. */
  getLiveOverride(profileId: string): ApprovalMode | undefined {
    return this.liveOverrides.get(profileId);
  }

  /** Immutable static (TOML-seeded) override for `profileId`, if any. */
  getStaticOverride(profileId: string): ApprovalMode | undefined {
    return this.staticOverrides.get(profileId);
  }

  /**
   * Set (or clear, when `mode === null`) the live runtime override for a
   * profile. Clearing reveals the static override / global beneath it.
   */
  setOverride(profileId: string, mode: ApprovalMode | null): void {
    if (mode === null) {
      this.liveOverrides.delete(profileId);
    } else {
      this.liveOverrides.set(profileId, mode);
    }
  }

  /**
   * Effective mode for a profile: live override > static override > global.
   * `profileId` is optional so callers gating the default connection can ask
   * for the bare global resolution.
   */
  effective(profileId?: string): ApprovalMode {
    if (profileId) {
      const live = this.liveOverrides.get(profileId);
      if (live) return live;
      const stat = this.staticOverrides.get(profileId);
      if (stat) return stat;
    }
    return this.global;
  }

  /** Snapshot of the live mutable state (global + live overrides). */
  snapshot(): ModeStoreSnapshot {
    return {
      global: this.global,
      overrides: Object.fromEntries(this.liveOverrides),
    };
  }

  /**
   * Re-seed the global default and the static (TOML-derived) override layer
   * from a freshly-loaded config (PR-9 hot reload), and CLEAR every live
   * runtime override. Rationale: a config-file edit re-establishes the file as
   * the source of truth, exactly as the registry drops its description
   * overrides on reload — the operator's on-disk policy wins again. In-memory
   * only; no disk surface.
   */
  reseed(globalDefault: ApprovalMode, staticOverrides?: Record<string, ApprovalMode>): void {
    this.global = globalDefault;
    this.staticOverrides = new Map(Object.entries(staticOverrides ?? {}));
    this.liveOverrides.clear();
  }

  /** Full capture of all three layers, for rollback of a failed reload. */
  capture(): ModeStoreState {
    return {
      global: this.global,
      staticOverrides: Object.fromEntries(this.staticOverrides),
      liveOverrides: Object.fromEntries(this.liveOverrides),
    };
  }

  /** Restore a previously {@link capture}d state (rollback). */
  restore(state: ModeStoreState): void {
    this.global = state.global;
    this.staticOverrides = new Map(Object.entries(state.staticOverrides));
    this.liveOverrides.clear();
    for (const [k, v] of Object.entries(state.liveOverrides)) {
      this.liveOverrides.set(k, v);
    }
  }
}
