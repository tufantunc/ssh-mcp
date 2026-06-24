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
      description: cfg.description,
      approval: cfg.approval,
    };
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
