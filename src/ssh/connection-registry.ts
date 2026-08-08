import { getProfile as getConfigProfile } from '../config/loader.js';
import type { AppConfig, Profile, ConnectionInfo } from '../types.js';
import { resolveCredentials } from '../config/credential-resolver.js';
import { SSHConnection } from './connection.js';
import type { HostKeyMode } from './host-key.js';
import type { ClientChannel } from 'ssh2';

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
      try {
        let conn = this.connections.get(profile.name);

        // A ProxyJump connection runs over a forwarded channel on the bastion.
        // Once the connection drops, that channel is dead, so reconnecting the
        // same SSHConnection reuses a corpse and always fails — which used to
        // burn one tool call on every reconnect before the retry rebuilt it.
        // Discard the object so the hop is re-established below.
        if (conn && profile.via && !conn.isConnected()) {
          await conn.close().catch(() => {});
          this.connections.delete(profile.name);
          conn = undefined;
        }

        if (!conn) {
          let bastionSock: ClientChannel | undefined;
          if (profile.via) {
            const bastionConn = await this.getOrCreate(profile.via);
            const bastionClient = bastionConn.getClient();
            bastionSock = await new Promise<ClientChannel>((resolve, reject) => {
              bastionClient.forwardOut('', 0, profile.host, profile.port, (err: Error | undefined, stream: ClientChannel) => {
                if (err) reject(new Error(`ProxyJump via "${profile.via}" failed: ${err.message}`));
                else resolve(stream);
              });
            });
          }
          conn = new SSHConnection(
            profile,
            await resolveCredentials(profile),
            this.knownHostsStore,
            this.hostKeyMode,
            bastionSock,
          );
          this.connections.set(profile.name, conn);
        }
        await conn.ensureConnected();
        return conn;
      } catch (err) {
        this.connections.delete(profile.name);
        throw err;
      } finally {
        this.pending.delete(profile.name);
      }
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
    const viaTargets = new Set(
      this.config.profiles
        .map((p) => p.via)
        .filter((v): v is string => !!v),
    );
    for (const [name, conn] of this.connections) {
      if (viaTargets.has(name)) continue;
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
