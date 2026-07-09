import { ISshTransport, ServerConfig } from './types.js';
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
  /** True only when setDefault() was called; first-registered fallback leaves this false. */
  private defaultExplicit = false;
  /**
   * Multi-source connection guard toggle. When true (default, safe), a tool
   * call that omits/blanks connectionName against a multi-source registry with
   * no explicit default is rejected. Set false to opt out and restore the
   * legacy silent-default fallback (the `[server].require_connection = false`
   * escape hatch — wired from the resolver via setRequireConnectionWhenMulti).
   */
  private requireConnectionWhenMulti = true;

  /**
   * @param prepareConfig Optional per-host preparation run lazily on first
   *   get(name), inside the init path — NOT at register() time. Used to defer
   *   expensive/failure-prone work (e.g. reading an ssh2 key file from disk)
   *   until the host is actually selected, so one secondary host with a
   *   missing/unmounted key path does not break startup or block list-servers
   *   and commands against otherwise-healthy hosts.
   */
  constructor(private prepareConfig?: (cfg: ServerConfig) => Promise<void>) {}

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

  /**
   * Toggle the multi-source omit-name guard. Pass `false` to opt out (restore
   * the legacy silent-default fallback) or `true` to keep it enforced. The boot
   * path injects this from the resolved `[server].require_connection` value;
   * absent any config the registry stays safe (guard ON).
   */
  setRequireConnectionWhenMulti(required: boolean): void {
    this.requireConnectionWhenMulti = required;
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
   * True when resolveName() would REJECT an omitted/blank connectionName:
   * multiple sources are registered, no explicit default was set, and the
   * multi-source guard is on. Callers that compute gating/audit attribution
   * BEFORE calling get() use this to avoid misattributing a guard-rejected
   * call to the first-registered host — the call never actually lands on a
   * host, so attributing it to one corrupts audit profile for exactly the
   * guard case.
   */
  wouldRejectOmittedName(): boolean {
    return (
      this.requireConnectionWhenMulti &&
      this.configs.size > 1 &&
      !this.defaultExplicit
    );
  }

  /**
   * Resolve the profile/attribution name for an audit record WITHOUT throwing.
   *
   * Mirrors resolveName()'s ambiguity rules but is side-effect free and never
   * rejects, so it is safe to call on the failure/catch path. Critically, for
   * the ambiguous multi-host case (connectionName omitted, more than one server
   * registered, no explicit default) it returns the '(unresolved)' sentinel
   * rather than getDefaultName()'s first-registered server — that call is
   * rejected by resolveName() before any command runs, so attributing its
   * failure audit record to the first host would corrupt attribution.
   */
  resolveProfileName(name?: string): string {
    // An explicitly-requested name is the accurate attribution even if it is
    // unknown (registry.get throws later; the record should still name what the
    // caller asked for, not a sentinel).
    if (name) return name;
    if (this.defaultName === null) return 'default';
    if (this.configs.size > 1 && !this.defaultExplicit) return '(unresolved)';
    return this.defaultName;
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
    // index.ts). A deliberate setDefault() re-enables the omit-name shortcut,
    // and setRequireConnectionWhenMulti(false) opts out of the guard entirely.
    if (!name && this.wouldRejectOmittedName()) {
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
    description?: string;
    host: string;
    port: number;
    username: string;
    transport: 'ssh2' | 'openssh';
    authMode: string;
    connected: boolean;
    isDefault: boolean;
  }> {
    // A name is only a *usable* default when it can actually be selected with an
    // omitted connectionName: it's the lone server, setDefault() was called, OR
    // the multi-source guard was opted out via require_connection=false. In the
    // last case resolveName() routes an omitted connectionName to the
    // first-registered host (this.defaultName), so that host IS the effective
    // default and list-servers must mark it — otherwise it reports "no default"
    // while omitted commands silently land on the first host, misleading the
    // user about where they run (Codex 3541772413). In the normal multi-host
    // case (>1 server, guard ON, no explicit default) resolveName() rejects an
    // omitted name, so no host is advertised as default.
    const defaultUsable =
      this.defaultExplicit || this.configs.size === 1 || !this.requireConnectionWhenMulti;
    const out = [];
    for (const [name, cfg] of this.configs) {
      // A cached transport is "initialized" — but for OpenSSH that only means
      // the local ssh binary/askpass setup passed; no live connection is proven
      // until a command actually runs (openssh spawns per-exec, has no
      // persistent socket). Prefer the transport's own isConnected() liveness
      // probe when present so list-servers does not report an initialized-only
      // OpenSSH host as connected when it has never answered. Fall back to
      // "cached after successful init" only for transports without a probe.
      const cached = this.transports.get(name);
      const connected = cached
        ? (typeof cached.isConnected === 'function' ? cached.isConnected() : true)
        : false;
      out.push({
        name,
        description: cfg.description,
        host: cfg.host,
        port: cfg.port,
        username: cfg.username,
        transport: (cfg.transport ?? (cfg.kerberos ? 'openssh' : 'ssh2')) as 'ssh2' | 'openssh',
        authMode: cfg.authMode ?? (cfg.kerberos ? 'kerberos' : cfg.keyPath || cfg.privateKey ? 'key' : cfg.password ? 'password' : 'unspecified'),
        connected,
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
