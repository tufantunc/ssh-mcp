import { ISshTransport, ServerConfig } from './types.js';
import type { ResolvedSource } from '../approval/types.js';
import { createTransport } from './factory.js';

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
      await t.init();
      this.transports.set(resolved, t);
      this.initPromises.delete(resolved);
      return t;
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
}
