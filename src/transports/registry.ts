import { ISshTransport, ServerConfig } from './types.js';
import { createTransport } from './factory.js';

/** Construction-time options for {@link TransportRegistry}. */
export interface TransportRegistryOptions {
  /**
   * When multiple sources are registered, require callers to name one
   * explicitly: an omitted/blank connectionName fails fast instead of silently
   * resolving to the first-registered (default) source.
   *
   * Default `true` (safe). D-A2 wires the config-driven opt-out (an operator
   * setting `false` here, or via {@link TransportRegistry.setRequireConnectionWhenMulti},
   * restores the legacy silent-default convenience). Single-source deployments
   * are unaffected either way — omission always resolves the lone source.
   */
  requireConnectionWhenMulti?: boolean;
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
 *
 * When MULTIPLE configs are registered, an omitted/blank connectionName is a
 * fail-fast error by default (see {@link TransportRegistryOptions}). This
 * removes the R1 landmine where omission silently routed to whichever source
 * happened to be registered first. A deliberate {@link setDefault} re-enables
 * the omit-name shortcut for callers that pick a canonical default.
 */
export class TransportRegistry {
  private configs = new Map<string, ServerConfig>();
  private transports = new Map<string, ISshTransport>();
  private initPromises = new Map<string, Promise<ISshTransport>>();
  private defaultName: string | null = null;
  private requireConnectionWhenMulti: boolean;
  /** True only when setDefault() was called; first-registered fallback leaves this false. */
  private defaultExplicit = false;
  /** Lazy per-host prep callback (see constructor doc). Set only for the function-first-arg form. */
  private prepareConfig?: (cfg: ServerConfig) => Promise<void>;

  /**
   * Multi-host form: lazy per-host prep callback first, options second.
   *
   * @param prepareConfig Optional per-host preparation run lazily on first
   *   get(name), inside the init path — NOT at register() time. Used to defer
   *   expensive/failure-prone work (e.g. reading an ssh2 key file from disk)
   *   until the host is actually selected, so one secondary host with a
   *   missing/unmounted key path does not break startup or block list-servers
   *   and commands against otherwise-healthy hosts.
   * @param options Construction-time behavior flags — currently the
   *   require-connection-when-multi guard (see {@link TransportRegistryOptions}).
   */
  constructor(prepareConfig?: (cfg: ServerConfig) => Promise<void>, options?: TransportRegistryOptions);
  /**
   * Options-first form: no prep callback, just the behavior flags. Keeps the
   * guard-branch convention `new TransportRegistry({ requireConnectionWhenMulti: false })`
   * valid alongside the multi-host convention `new TransportRegistry(prepareKeyContents)`.
   */
  constructor(options?: TransportRegistryOptions);
  constructor(
    prepareConfigOrOptions?: ((cfg: ServerConfig) => Promise<void>) | TransportRegistryOptions,
    options: TransportRegistryOptions = {}
  ) {
    // Shape-detect the first arg: a function is the lazy prepareConfig
    // callback (multi-host convention); an object is the options bag (guard
    // convention). No caller mixes both today, but (fn, options) stays valid.
    if (typeof prepareConfigOrOptions === 'function') {
      this.prepareConfig = prepareConfigOrOptions;
    } else if (prepareConfigOrOptions) {
      options = prepareConfigOrOptions;
    }
    // Safe default: require an explicit name when multiple sources exist unless
    // an operator explicitly opts out (D-A2 escape hatch).
    this.requireConnectionWhenMulti = options.requireConnectionWhenMulti ?? true;
  }

  /**
   * Toggle the require-connection-when-multi guard after construction.
   * D-A2 uses this to inject the resolved config setting into the registry
   * built in `bootstrapRegistry()` without rewriting the guard logic.
   */
  setRequireConnectionWhenMulti(require: boolean): void {
    this.requireConnectionWhenMulti = require;
  }

  register(config: ServerConfig): void {
    // Normalize the source name at registration so storage and lookup agree.
    // resolveName() trims the requested connectionName, so register() MUST trim
    // too; otherwise a whitespace-padded registered name ('prod ') is
    // unreachable (every lookup trims to 'prod') yet still occupies a slot, and
    // a 'prod' + 'prod ' pair silently mis-routes to the wrong host. Trimming,
    // rejecting a blank/whitespace-only name, and duplicate-checking the
    // NORMALIZED value together close that gap (R1-PR5 finding #2).
    const name = config.name?.trim();
    if (!name) {
      throw new Error('ServerConfig.name is required');
    }
    if (this.configs.has(name)) {
      throw new Error(`Duplicate server name: ${name}`);
    }
    // Store under the canonical (trimmed) name so the map key, the stored
    // config.name, and every later resolveName() lookup are byte-identical.
    this.configs.set(name, { ...config, name });
    // First registered becomes the default unless explicitly overridden.
    if (this.defaultName === null) {
      this.defaultName = name;
    }
  }

  /** Override which name is used when tool calls omit connectionName. */
  setDefault(name: string): void {
    // Trim to stay consistent with register()/resolveName() normalization.
    const normalized = name?.trim();
    if (!normalized || !this.configs.has(normalized)) {
      throw new Error(`Cannot set default to unknown server: ${name}`);
    }
    this.defaultName = normalized;
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

  /**
   * Resolve name argument → canonical name.
   *
   * - A non-blank name must match a registered source, else fail-fast
   *   ("Unknown connection name" — R2 regression guard).
   * - An omitted OR blank/whitespace-only name with multiple sources fails fast
   *   ("connectionName is required ...") by default — the R1 landmine fix —
   *   unless either escape hatch is engaged (global opt-out, or a deliberate
   *   setDefault()).
   * - An omitted/blank name with a single source (or an engaged escape hatch)
   *   resolves to the default, preserving the single-server omission convenience.
   */
  private resolveName(name?: string): string {
    // Normalize first: a blank/whitespace-only name ('' / '   ' / '\t') must be
    // treated as OMITTED, never as a valid name and never as an "unknown name".
    // This stops empty strings from slipping past as either a default or a
    // confusing unknown-name error.
    const trimmed = name?.trim();

    if (trimmed) {
      if (this.configs.has(trimmed)) return trimmed;
      throw new Error(
        `Unknown connection name: ${trimmed}. Registered: ${this.names().join(', ') || '(none)'}`
      );
    }

    // From here on the name is omitted or blank.
    if (this.defaultName === null) {
      throw new Error('No servers registered');
    }

    // R1 landmine fix: with multiple sources, refuse to silently pick the
    // default. Branch on the ACTUAL registered source count (configs.size), not
    // the CLI isMultiHost flag, which reflects how sources were supplied rather
    // than how many are registered and can diverge from the real count.
    // Two independent escape hatches re-enable omission:
    //   - requireConnectionWhenMulti === false (global opt-out, D-A2 config seam)
    //   - a deliberate setDefault() call (defaultExplicit): the operator picked
    //     a canonical default, so omission is an explicit choice, not a landmine.
    if (this.requireConnectionWhenMulti && this.configs.size > 1 && !this.defaultExplicit) {
      throw new Error(
        `connectionName is required when multiple SSH connections are configured. ` +
          `Specify one of: ${this.names().join(', ')}.`
      );
    }

    // size === 1 (or an engaged escape hatch): preserve omission convenience.
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
      try {
        // Lazy per-host prep (e.g. reading the ssh2 key file). Deferred to here
        // so a missing key on this host fails only when the host is used, not at
        // startup. Kept inside the try so the finally below clears the in-flight
        // entry on a prep failure too — a later get() retries instead of
        // replaying the cached rejection (same contract as a rejected init).
        if (this.prepareConfig) await this.prepareConfig(cfg);
        const t = createTransport(cfg);
        await t.init();
        // Cache the live transport only on successful init.
        this.transports.set(resolved, t);
        return t;
      } finally {
        // Always clear the in-flight entry so a rejected prep/init (e.g. a
        // missing key file, or a transient connect timeout to a temporarily-
        // unreachable host) is NOT cached. Otherwise every later get() would
        // replay the same rejection via the pending-promise return above, and
        // the connection could never retry without a process restart.
        this.initPromises.delete(resolved);
      }
    })();
    this.initPromises.set(resolved, initPromise);
    return initPromise;
  }

  /** Snapshot status for list-servers tool. */
  list(): Array<{
    name: string;
    host: string;
    port: number;
    username: string;
    transport: 'ssh2' | 'openssh';
    authMode: string;
    connected: boolean;
    isDefault: boolean;
  }> {
    // A name is only a *usable* default when it can actually be selected with an
    // omitted connectionName: either it's the lone server, the multi-source
    // guard is disabled, or setDefault() was called. In the normal multi-host
    // case (>1 server, guard enabled, no explicit default), resolveName()
    // rejects an omitted name, so advertising the first-registered host as
    // "(default)" would be misleading — report isDefault=false there.
    const defaultUsable = !this.requireConnectionWhenMulti || this.defaultExplicit || this.configs.size === 1;
    const out = [];
    for (const [name, cfg] of this.configs) {
      out.push({
        name,
        host: cfg.host,
        port: cfg.port,
        username: cfg.username,
        transport: (cfg.transport ?? (cfg.kerberos ? 'openssh' : 'ssh2')) as 'ssh2' | 'openssh',
        authMode: cfg.authMode ?? (cfg.kerberos ? 'kerberos' : cfg.keyPath || cfg.privateKey ? 'key' : cfg.password ? 'password' : 'unspecified'),
        connected: this.transports.has(name),
        isDefault: defaultUsable && this.defaultName === name,
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
