import { ISshTransport, ServerConfig } from './types.js';
import type { ResolvedSource } from '../approval/types.js';
import { createTransport } from './factory.js';

/**
 * Opaque capture of the registry's mutable config state, used by the config
 * hot-reload path (PR-9) to roll back a swap that fails validation. Holds only
 * the config maps + default pointer — NOT the live transports (those are lazy
 * and re-init from config on next use). In-memory only.
 */
export interface RegistryStateSnapshot {
  configs: Map<string, ServerConfig>;
  defaultName: string | null;
  descriptionOverrides: Map<string, string>;
}

/**
 * Registry of named SSH transports for multi-host MCP mode.
 *
 * Transports are lazily created on first use (so startup cost is O(1)
 * regardless of how many hosts are configured). Each transport is reused
 * across subsequent tool calls to the same connection name.
 *
 * When only a single config is registered, its name becomes the default
 * — callers may omit connectionName from tool arguments.
 */
export class TransportRegistry {
  private configs = new Map<string, ServerConfig>();
  private transports = new Map<string, ISshTransport>();
  private initPromises = new Map<string, Promise<ISshTransport>>();
  private defaultName: string | null = null;
  /**
   * Live per-source description overrides (PR-8, Decision D3: in-memory only).
   *
   * Presence of a key means the source description has been overridden at
   * runtime via the WebUI; the value is the override text (may be the empty
   * string when an operator deliberately blanks the description). Deleting a
   * key reverts to the TOML-seeded `ServerConfig.description`. This Map holds
   * NOTHING on disk — a process restart discards every override and the boot
   * config takes over again, exactly like the approval mode store. The
   * approval engine re-reads the effective description on its NEXT decision
   * because `profile()` applies the override on every call.
   */
  private descriptionOverrides = new Map<string, string>();
  /** True only when setDefault() was called; first-registered fallback leaves this false. */
  private defaultExplicit = false;

  register(config: ServerConfig): void {
    if (!config.name) {
      throw new Error('ServerConfig.name is required');
    }
    if (this.configs.has(config.name)) {
      throw new Error(`Duplicate server name: ${config.name}`);
    }
    this.configs.set(config.name, config);
    // First registered becomes the default unless explicitly overridden.
    if (this.defaultName === null) {
      this.defaultName = config.name;
    }
  }

  /** Override which name is used when tool calls omit connectionName. */
  setDefault(name: string): void {
    if (!this.configs.has(name)) {
      throw new Error(`Cannot set default to unknown server: ${name}`);
    }
    this.defaultName = name;
    this.defaultExplicit = true;
  }

  /** Returns names of all registered servers in registration order. */
  names(): string[] {
    return Array.from(this.configs.keys());
  }

  hasAny(): boolean {
    return this.configs.size > 0;
  }

  getDefaultName(): string | null {
    return this.defaultName;
  }

  /** Resolved approval profile for a given connection name. */
  profile(name?: string): ResolvedSource {
    const resolved = this.resolveName(name);
    const cfg = this.configs.get(resolved)!;
    return {
      id: resolved,
      description: this.effectiveDescription(resolved),
      approval: cfg.approval,
    };
  }

  /**
   * Effective description for a source: live runtime override > TOML-seeded
   * `ServerConfig.description`. Returns `undefined` when neither is set.
   * Both `profile()` (the approval-engine read path) and `list()` (the WebUI
   * status surface) resolve through here, so a live override is felt by the
   * gate's next decision and every open dashboard at once.
   */
  private effectiveDescription(resolved: string): string | undefined {
    const override = this.descriptionOverrides.get(resolved);
    if (override !== undefined) return override;
    return this.configs.get(resolved)?.description;
  }

  /**
   * Set (text) or clear (`null` → revert to the TOML description) the live
   * runtime description override for a source. In-memory only (Decision D3):
   * never writes back to the config file. Returns the resulting effective
   * description (the empty string when blanked or unset). Throws on an unknown
   * connection name — the same contract as `get()` / `profile()`.
   */
  setDescription(name: string, description: string | null): string {
    const resolved = this.resolveName(name);
    if (description === null) {
      this.descriptionOverrides.delete(resolved);
    } else {
      this.descriptionOverrides.set(resolved, description);
    }
    return this.effectiveDescription(resolved) ?? '';
  }

  /** Effective description for a source as a string (override > TOML > ''). */
  getEffectiveDescription(name?: string): string {
    const resolved = this.resolveName(name);
    return this.effectiveDescription(resolved) ?? '';
  }

  /** The live runtime description override for `name`, if one is set. */
  getDescriptionOverride(name?: string): string | undefined {
    const resolved = this.resolveName(name);
    return this.descriptionOverrides.get(resolved);
  }

  /** Resolve name argument → canonical name. Falls back to default. */
  private resolveName(name?: string): string {
    if (name && this.configs.has(name)) return name;
    if (name && !this.configs.has(name)) {
      throw new Error(
        `Unknown connection name: ${name}. Registered: ${this.names().join(', ') || '(none)'}`
      );
    }
    if (this.defaultName === null) {
      throw new Error('No servers registered');
    }
    // When connectionName is omitted and more than one server is configured,
    // refuse to silently pick the first-registered host — the command could
    // land on the wrong machine. The connectionName tool arg is advertised as
    // optional only for the single-server case (see connectionNameSchema in
    // index.ts). A deliberate setDefault() re-enables the omit-name shortcut.
    if (!name && this.configs.size > 1 && !this.defaultExplicit) {
      throw new Error(
        `connectionName is required when multiple servers are configured: ${this.names().join(', ')}`
      );
    }
    return this.defaultName;
  }

  /** Get (or lazily create+init) the transport for a given name. */
  async get(name?: string): Promise<ISshTransport> {
    const resolved = this.resolveName(name);
    const existing = this.transports.get(resolved);
    if (existing) return existing;

    // Serialize concurrent init requests for the same name
    const pending = this.initPromises.get(resolved);
    if (pending) return pending;

    const cfg = this.configs.get(resolved)!;
    const initPromise = (async () => {
      const t = createTransport(cfg);
      try {
        await t.init();
        // Cache the live transport only on successful init.
        this.transports.set(resolved, t);
        return t;
      } finally {
        // Always clear the in-flight entry so a rejected init (e.g. a transient
        // connect timeout to a temporarily-unreachable host) is NOT cached.
        // Otherwise every later get() would replay the same rejection via the
        // pending-promise return above, and the connection could never retry
        // without a process restart.
        this.initPromises.delete(resolved);
      }
    })();
    this.initPromises.set(resolved, initPromise);
    return initPromise;
  }

  /** Snapshot status for list-servers tool. */
  list(): Array<{
    name: string;
    description?: string;
    host: string;
    port: number;
    username: string;
    transport: 'ssh2' | 'openssh';
    authMode: string;
    connected: boolean;
    isDefault: boolean;
  }> {
    const out = [];
    for (const [name, cfg] of this.configs) {
      out.push({
        name,
        description: this.effectiveDescription(name),
        host: cfg.host,
        port: cfg.port,
        username: cfg.username,
        transport: (cfg.transport ?? (cfg.kerberos ? 'openssh' : 'ssh2')) as 'ssh2' | 'openssh',
        authMode: cfg.authMode ?? (cfg.kerberos ? 'kerberos' : cfg.keyPath || cfg.privateKey ? 'key' : cfg.password ? 'password' : 'unspecified'),
        connected: this.transports.has(name),
        isDefault: this.defaultName === name,
      });
    }
    return out;
  }

  async closeAll(): Promise<void> {
    const tasks: Promise<void>[] = [];
    for (const t of this.transports.values()) {
      tasks.push(t.close().catch(() => { /* best effort */ }));
    }
    this.transports.clear();
    this.initPromises.clear();
    await Promise.allSettled(tasks);
  }

  // ===========================================================================
  // Config hot-reload (PR-9). These let the ConfigReloader swap the registered
  // sources atomically on a TOML file change, with validate-before-swap +
  // rollback. The MCP tool list is NOT touched (Decision D4) — only the set of
  // named connections, their parameters, and per-source descriptions.
  // ===========================================================================

  /** Snapshot of every currently registered ServerConfig, in registration order. */
  getAllConfigs(): ServerConfig[] {
    return Array.from(this.configs.values());
  }

  /**
   * Capture the mutable config state for rollback. Cheap (shallow Map copies);
   * the ServerConfig objects themselves are never mutated in place, so sharing
   * their references is safe. Live transports are intentionally NOT captured —
   * they re-init lazily from whatever config is active on the next call.
   */
  snapshotState(): RegistryStateSnapshot {
    return {
      configs: new Map(this.configs),
      defaultName: this.defaultName,
      descriptionOverrides: new Map(this.descriptionOverrides),
    };
  }

  /** Restore a previously captured state (rollback after a failed swap). */
  restoreState(snap: RegistryStateSnapshot): void {
    this.configs = new Map(snap.configs);
    this.defaultName = snap.defaultName;
    this.descriptionOverrides = new Map(snap.descriptionOverrides);
  }

  /**
   * Atomically replace the entire set of registered sources (config hot-reload).
   *
   * Validation runs to completion against a throwaway map BEFORE any field on
   * `this` is touched, so a malformed source list leaves the registry exactly
   * as it was — the caller keeps serving the old connections (validate-before-
   * swap). On success the live in-memory description overrides (D3) are dropped:
   * a file edit re-establishes the TOML baseline as the source of truth.
   *
   * Cached transports are NOT closed here — the caller decides when to call
   * `closeAll()` so a host whose connection params changed re-dials with the
   * new config on its next use. Keeping it separate also keeps `replaceAll`
   * synchronous and trivially rollback-safe.
   */
  replaceAll(sources: ServerConfig[], defaultName?: string): void {
    if (!Array.isArray(sources) || sources.length === 0) {
      throw new Error('replaceAll requires at least one source');
    }
    const next = new Map<string, ServerConfig>();
    for (const cfg of sources) {
      if (!cfg.name) {
        throw new Error('ServerConfig.name is required');
      }
      if (next.has(cfg.name)) {
        throw new Error(`Duplicate server name: ${cfg.name}`);
      }
      next.set(cfg.name, cfg);
    }
    let nextDefault: string;
    if (defaultName) {
      if (!next.has(defaultName)) {
        throw new Error(`Cannot set default to unknown server: ${defaultName}`);
      }
      nextDefault = defaultName;
    } else {
      nextDefault = sources[0].name;
    }
    // Commit — every check above passed, so this can't half-apply.
    this.configs = next;
    this.defaultName = nextDefault;
    this.descriptionOverrides = new Map();
  }
}
