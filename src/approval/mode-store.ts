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

export class ApprovalModeStore {
  private global: ApprovalMode;
  private readonly staticOverrides: Map<string, ApprovalMode>;
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
}
