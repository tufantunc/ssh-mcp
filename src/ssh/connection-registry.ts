import { getProfile as getConfigProfile } from '../config/loader.js';
import type { AppConfig, Profile, ConnectionInfo } from '../types.js';
import { resolveCredentials } from '../config/credential-resolver.js';
import { SSHConnection } from './connection.js';
import type { HostKeyMode } from './host-key.js';

export class ConnectionRegistry {
  private connections = new Map<string, SSHConnection>();
  private pending = new Map<string, Promise<SSHConnection>>();
  private knownHostsStore = new Map<string, string>();
  private hostKeyMode: HostKeyMode;
  private config: AppConfig;

  constructor(config: AppConfig, hostKeyMode: HostKeyMode = 'tofu') {
    this.config = config;
    this.hostKeyMode = hostKeyMode;
  }

  async getOrCreate(profileName?: string): Promise<SSHConnection> {
    const profile = this.getProfile(profileName);

    const existing = this.connections.get(profile.name);
    if (existing && existing.isConnected()) {
      return existing;
    }

    const inFlight = this.pending.get(profile.name);
    if (inFlight) {
      return inFlight;
    }

    const promise = (async () => {
      let conn = this.connections.get(profile.name);
      if (!conn) {
        conn = new SSHConnection(profile, await resolveCredentials(profile), this.knownHostsStore, this.hostKeyMode);
        this.connections.set(profile.name, conn);
      }
      await conn.ensureConnected();
      this.pending.delete(profile.name);
      return conn;
    })();

    this.pending.set(profile.name, promise);
    return promise;
  }

  get(profileName?: string): SSHConnection | undefined {
    const profile = this.getProfile(profileName);
    return this.connections.get(profile.name);
  }

  getProfile(profileName?: string): Profile {
    return getConfigProfile(this.config, profileName);
  }

  listConnections(): ConnectionInfo[] {
    return Array.from(this.connections.values()).map((c) => c.toInfo());
  }

  listAllProfiles(): Profile[] {
    return this.config.profiles;
  }

  reapIdleConnections(): void {
    const idleThreshold = Date.now() - this.config.defaults.connectionIdleReapMs;
    for (const [name, conn] of this.connections) {
      const info = conn.toInfo();
      if (info.sessionCount === 0 && info.lastActivity && info.lastActivity.getTime() < idleThreshold) {
        conn.close().catch(() => {});
        this.connections.delete(name);
      }
    }
  }

  async closeAll(): Promise<void> {
    for (const conn of this.connections.values()) {
      await conn.close().catch(() => {});
    }
    this.connections.clear();
  }
}
