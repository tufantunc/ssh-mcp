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
  /**
   * Whether the captured default was set by a deliberate setDefault()/explicit
   * reload default (true) vs. the first-registered fallback (false). Carried
   * through rollback so a failed reload cannot flip the omit-name guard
   * (resolveName) into a different multi-server behavior than before the swap.
   */
  defaultExplicit: boolean;
  /**
   * Captured value of the multi-source omit-name guard toggle
   * (`[server].require_connection`). A reload applies the NEW file's
   * require_connection; carrying the old value here lets a failed/rolled-back
   * swap restore the exact guard state that was live before the swap, so a
   * bad reload can never leave the guard looser (or stricter) than boot.
   */
  requireConnectionWhenMulti: boolean;
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
  /**
   * Per-name identity token for the CURRENTLY-owning in-flight initializer.
   * A hot-reload (closeAll clears initPromises) followed by a fresh get() can
   * install a NEWER init promise under the same name while an older init() is
   * still awaiting. Each initializer captures its own token here on start and,
   * in its finally, only clears initPromises when the slot still holds ITS
   * token — so a stale initializer completing late cannot evict the newer
   * in-flight entry (which would let a later concurrent get() start a duplicate
   * init and leak transports). In-memory only.
   */
  private initTokens = new Map<string, object>();
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
  /**
   * Monotonic reload generation (PR-9). Bumped by {@link closeAll} — the step a
   * config hot-reload calls to drop stale transports. A `get()` whose `init()`
   * is still in flight captures the generation up front and re-checks it after
   * `init()` resolves: if it changed, a reload completed underneath the init, so
   * the freshly-dialed transport was built from the now-stale config and MUST
   * NOT be cached (otherwise it resurrects an old host/auth connection after
   * closeAll already cleared the map). In-memory only.
   */
  private reloadGeneration = 0;
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
    if (config.name === '.' || config.name === '..') {
      throw new Error('ServerConfig.name must not be a dot-segment ("." or "..")');
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
    if (this.wouldRejectOmittedName()) return '(unresolved)';
    return this.defaultName;
  }

  /**
   * Resolve name argument → canonical name without initializing a transport.
   * Useful when a caller must validate target selection before doing other
   * work (for example, before prompting for approval).
   */
  resolveRegisteredName(name?: string): string {
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

  /** Resolve name argument → canonical name. Falls back to default. */
  private resolveName(name?: string): string {
    return this.resolveRegisteredName(name);
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
    const gen = this.reloadGeneration;
    // Identity token for THIS initializer. Recorded in initTokens[resolved]
    // below; the finally only clears the shared init entry if the slot still
    // belongs to this token, so a stale init resolving after a reload cannot
    // wipe a newer in-flight initializer.
    const token = {};
    const initPromise = (async () => {
      let t: ISshTransport | undefined;
      let initError: unknown;
      try {
        // Lazy per-host prep (e.g. reading the ssh2 key file). Deferred to here
        // so a missing key on this host fails only when the host is used, not at
        // startup. Kept inside the try so the finally below clears the in-flight
        // entry on a prep failure too — a later get() retries instead of
        // replaying the cached rejection (same contract as a rejected init).
        if (this.prepareConfig) await this.prepareConfig(cfg);
        t = createTransport(cfg);
        await t.init();
      } catch (err) {
        initError = err;
      } finally {
        // Clear the in-flight entry so a rejected prep/init (e.g. a missing key
        // file, or a transient connect timeout to a temporarily-unreachable
        // host) is NOT cached. Otherwise every later get() would replay the same
        // rejection via the pending-promise return above, and the connection
        // could never retry without a process restart. Cleared BEFORE the
        // generation re-check below so the recursive re-get on a mid-init
        // reload can't deadlock on this very promise.
        //
        // Guard on the identity token: a reload (closeAll clears initPromises +
        // initTokens) followed by a fresh get() installs a NEWER init under this
        // same name. If this (now stale) initializer blindly deleted the slot,
        // it would evict that newer initializer, letting a subsequent get()
        // start a THIRD init and leak transports. Only delete when the slot
        // still holds our token.
        if (this.initTokens.get(resolved) === token) {
          this.initPromises.delete(resolved);
          this.initTokens.delete(resolved);
        }
      }
      if (initError) {
        // If the config changed while prepareConfig()/init() was in flight, the
        // error belongs to an obsolete source/params set. Retry against the
        // CURRENT registry instead of surfacing a stale key-read/connect error.
        if (this.reloadGeneration !== gen) {
          await t?.close().catch(() => { /* best effort */ });
          return this.get(resolved);
        }
        throw initError;
      }
      if (!t) {
        throw new Error(`Transport initialization aborted before transport creation: ${resolved}`);
      }
      // A config hot-reload (replaceAll + closeAll) may have completed while we
      // were awaiting init(). If so, `t` was dialed against the pre-reload
      // config; caching it would resurrect a stale connection for `resolved`
      // after closeAll already cleared the map. Discard it and re-resolve
      // against the CURRENT config so the caller gets a transport built from
      // the new parameters (or a clear error if `resolved` was removed).
      if (this.reloadGeneration !== gen) {
        await t.close().catch(() => { /* best effort */ });
        return this.get(resolved);
      }
      // Cache the live transport only on successful, still-current init.
      this.transports.set(resolved, t);
      return t;
    })();
    this.initPromises.set(resolved, initPromise);
    this.initTokens.set(resolved, token);
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
        description: this.effectiveDescription(name),
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
    // Bump the reload generation FIRST so any get() whose init() is still in
    // flight (captured the old generation) discards its soon-to-be-stale
    // transport instead of repopulating the map we are about to clear.
    this.reloadGeneration++;
    const tasks: Promise<void>[] = [];
    for (const t of this.transports.values()) {
      tasks.push(t.close().catch(() => { /* best effort */ }));
    }
    this.transports.clear();
    // Clear the in-flight init registry AND its parallel identity tokens in
    // lockstep. A stale initializer that resolves after this only deletes the
    // slot when it still holds its own token (see get()), so dropping the
    // tokens here lets the NEXT get() install a fresh, unambiguously-current
    // initializer for the same name.
    this.initPromises.clear();
    this.initTokens.clear();
    await Promise.allSettled(tasks);
  }

  /**
   * Connection-relevant equality between two ServerConfigs. Compares ONLY the
   * fields that decide how a transport dials/authenticates — NOT `name` (the
   * map key), `description`, or `approval` (which never affect the live
   * connection). Two configs that differ only in description/approval are
   * considered the SAME connection, so {@link closeChanged} keeps that source's
   * live persistent transport across a reload.
   */
  private connectionParamsEqual(a: ServerConfig, b: ServerConfig): boolean {
    // For ssh2 key_path sources, privateKey is runtime/lazily derived from the
    // key file by prepareKeyContents(). A reload reparses the same TOML with the
    // same keyPath but no privateKey yet; that derived in-memory material must
    // not make an unchanged source look like a connection-parameter edit. Inline
    // private_key (no keyPath) is still part of the dial/auth signature.
    const comparablePrivateKeyA = a.keyPath ? undefined : a.privateKey;
    const comparablePrivateKeyB = b.keyPath ? undefined : b.privateKey;
    return (
      a.host === b.host &&
      a.port === b.port &&
      a.username === b.username &&
      a.password === b.password &&
      comparablePrivateKeyA === comparablePrivateKeyB &&
      a.suPassword === b.suPassword &&
      a.sudoPassword === b.sudoPassword &&
      a.transport === b.transport &&
      a.authMode === b.authMode &&
      a.keyPath === b.keyPath &&
      a.kerberos === b.kerberos &&
      a.gssapiDelegateCredentials === b.gssapiDelegateCredentials &&
      a.knownHostsFile === b.knownHostsFile &&
      a.strictHostKeyChecking === b.strictHostKeyChecking
    );
  }

  /**
   * Close ONLY the transports whose source was removed or whose connection
   * parameters changed relative to `previousConfigs`, preserving the live
   * persistent transport of every source whose connection params are unchanged
   * (PR-9). This is the reload path's replacement for {@link closeAll}: a save
   * that only edits descriptions or approval policy must NOT tear down a healthy
   * ssh2 `Client` out from under an in-flight command. Called AFTER
   * `replaceAll()` has committed the new configs, so `this.configs` is the NEW
   * set and `previousConfigs` is the pre-swap map (`snapshotState().configs`).
   */
  async closeChanged(previousConfigs: Map<string, ServerConfig>): Promise<void> {
    // Bump the reload generation FIRST — exactly like closeAll — so any get()
    // whose init() is still in flight (captured the old generation) discards a
    // transport it dialed against now-stale params and re-resolves against the
    // CURRENT config, instead of caching it after this returns. Unlike closeAll
    // this does NOT close the transports of unchanged sources, so their live
    // persistent connections (and any command running on them) survive.
    this.reloadGeneration++;

    const toClose: string[] = [];
    const candidates = new Set<string>([
      ...this.transports.keys(),
      ...this.initPromises.keys(),
    ]);
    for (const name of candidates) {
      const prev = previousConfigs.get(name);
      const curr = this.configs.get(name);
      // Removed (no longer in the new set), newly-appearing under a cached name
      // (defensive: prev missing), or connection params changed → drop it so it
      // re-dials lazily with the new config on next use. Include pending-only
      // initializers too: during first get(), a source lives only in
      // initPromises until init() resolves, and changed/removed configs must
      // invalidate that stale in-flight init even when no transport is cached.
      if (!curr || !prev || !this.connectionParamsEqual(prev, curr)) {
        toClose.push(name);
      }
    }

    const tasks: Promise<void>[] = [];
    for (const name of toClose) {
      const t = this.transports.get(name);
      if (t) tasks.push(t.close().catch(() => { /* best effort */ }));
      this.transports.delete(name);
      // Clear any in-flight init for a dropped name so the next get() installs a
      // fresh, unambiguously-current initializer (mirrors closeAll's cleanup,
      // scoped to just the changed/removed names).
      this.initPromises.delete(name);
      this.initTokens.delete(name);
    }
    await Promise.allSettled(tasks);
  }

  /**
   * Current monotonic reload generation (bumped by {@link closeAll}). Callers
   * that captured a generation BEFORE an awaited operation (e.g. a manual
   * approval prompt) compare against this AFTER the await to detect that a
   * config hot-reload landed underneath them and revalidate accordingly.
   */
  getReloadGeneration(): number {
    return this.reloadGeneration;
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
   * the ServerConfig objects are treated as immutable *after registration*
   * (only boot-time prep like `prepareKeyContents()` mutates a cfg in place,
   * before it is ever registered/snapshotted), so sharing their references in
   * the snapshot is safe — a rollback restores the same objects. Live
   * transports are intentionally NOT captured — they re-init lazily from
   * whatever config is active on the next call.
   */
  snapshotState(): RegistryStateSnapshot {
    return {
      configs: new Map(this.configs),
      defaultName: this.defaultName,
      defaultExplicit: this.defaultExplicit,
      requireConnectionWhenMulti: this.requireConnectionWhenMulti,
      descriptionOverrides: new Map(this.descriptionOverrides),
    };
  }

  /** Restore a previously captured state (rollback after a failed swap). */
  restoreState(snap: RegistryStateSnapshot): void {
    this.configs = new Map(snap.configs);
    this.defaultName = snap.defaultName;
    this.defaultExplicit = snap.defaultExplicit;
    this.requireConnectionWhenMulti = snap.requireConnectionWhenMulti;
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
    let nextExplicit: boolean;
    if (defaultName) {
      if (!next.has(defaultName)) {
        throw new Error(`Cannot set default to unknown server: ${defaultName}`);
      }
      nextDefault = defaultName;
      // A reload that names a default is the analog of a boot-time setDefault():
      // it re-enables the omit-name shortcut even with multiple servers.
      nextExplicit = true;
    } else {
      nextDefault = sources[0].name;
      // No explicit default → first-registered fallback, exactly like boot via
      // register(). The multi-server omit-name guard in resolveName() stays armed.
      nextExplicit = false;
    }
    // Commit — every check above passed, so this can't half-apply.
    this.configs = next;
    this.defaultName = nextDefault;
    this.defaultExplicit = nextExplicit;
    this.descriptionOverrides = new Map();
  }
}
