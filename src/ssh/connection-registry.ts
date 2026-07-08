import type { AppConfig, Profile, ConnectionInfo } from '../types.js';
import { resolveCredentials } from '../config/credential-resolver.js';
import { SSHConnection } from './connection.js';
import type { HostKeyMode } from './host-key.js';

export class ConnectionRegistry {
  private connections = new Map<string, SSHConnection>();
  private knownHostsStore = new Map<string, string>();
  private hostKeyMode: HostKeyMode;
  private config: AppConfig;

  constructor(config: AppConfig, hostKeyMode: HostKeyMode = 'tofu') {
    this.config = config;
    this.hostKeyMode = hostKeyMode;
  }

  async getOrCreate(profileName?: string): Promise<SSHConnection> {
    const profile = this.getProfile(profileName);

    let conn = this.connections.get(profile.name);
    if (conn && conn.isConnected()) {
      return conn;
    }

    if (!conn) {
      conn = new SSHConnection(profile, await resolveCredentials(profile), this.knownHostsStore, this.hostKeyMode);
      this.connections.set(profile.name, conn);
    }

    await conn.ensureConnected();
    return conn;
  }

  get(profileName?: string): SSHConnection | undefined {
    const profile = this.getProfile(profileName);
    return this.connections.get(profile.name);
  }

  getProfile(profileName?: string): Profile {
    const name = profileName || this.config.defaults.defaultProfile;
    if (!name) {
      return this.config.profiles[0];
    }
    const profile = this.config.profiles.find((p) => p.name === name);
    if (!profile) throw new Error(`Profile "${name}" not found`);
    return profile;
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
