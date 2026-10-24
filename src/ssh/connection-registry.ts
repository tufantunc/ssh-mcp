import { getProfile as getConfigProfile, getConfigPath } from '../config/loader.js';
import { OperatorError, UnconfiguredError } from '../errors.js';
import type { AppConfig, Defaults, Profile, ConnectionInfo } from '../types.js';
import { resolveCredentials } from '../config/credential-resolver.js';
import { SSHConnection } from './connection.js';
import type { HostKeyMode } from './host-key.js';
import type { ClientChannel } from 'ssh2';
import {
  planReload,
  type CloseReason,
  type ProfileChange,
  type ProfileDiff,
} from '../config/reload-diff.js';

export interface ApplyResult {
  diff: ProfileDiff;
  /** Already out of the registry; the caller closes them. */
  toClose: { conn: SSHConnection; profile: string; reason: CloseReason }[];
  /** Profiles with an open connection, kept open, whose session-fixed fields changed: only those fields named. */
  sessionFieldsChanged: ProfileChange[];
}

const RELOADED_WHILE_CONNECTING = 'The configuration was reloaded while connecting; retry the call.';

export class ConnectionRegistry {
  private connections = new Map<string, SSHConnection>();
  private pending = new Map<string, Promise<SSHConnection>>();
  private knownHostsStore = new Map<string, string>();
  private hostKeyMode: HostKeyMode;
  private config: AppConfig;
  private configGeneration = 0;
  /**
   * Per profile name, the last generation whose applyConfig closed it (removed, connection
   * field changed, or its bastion closing). A new connect that started before that is
   * discarded; see getOrCreate.
   */
  private closedAt = new Map<string, number>();

  constructor(config: AppConfig, hostKeyMode: HostKeyMode = 'tofu') {
    this.config = config;
    this.hostKeyMode = hostKeyMode;
  }

  /**
   * Increments on every applyConfig. A connection that was still being opened under an
   * older generation is checked when it would be stored: a new one is discarded if a
   * reload since then closed its profile (removed, a connection field changed, or its
   * bastion closing), and otherwise stored with the current profile; a stored one being
   * reconnected is kept if the swap updated it in place, and refused if the swap took it
   * out of the registry. Approval grants count only under the generation they were
   * recorded in.
   */
  get generation(): number {
    return this.configGeneration;
  }

  /** Whether an applyConfig after generation `gen` closed this profile name. */
  private closedSince(name: string, gen: number): boolean {
    return (this.closedAt.get(name) ?? -1) > gen;
  }

  async getOrCreate(profileName?: string): Promise<SSHConnection> {
    const profile = this.getProfile(profileName);
    const gen = this.generation;

    const existing = this.connections.get(profile.name);
    if (existing && existing.isConnected()) {
      return existing;
    }

    const inFlight = this.pending.get(profile.name);
    if (inFlight) {
      return inFlight;
    }

    let attempt: SSHConnection | undefined;
    let reused = false;
    // `let`, not `const`: the finally below can run before the assignment if the body
    // throws synchronously, and must not hit the temporal dead zone.
    let promise: Promise<SSHConnection> | undefined;
    const connect = (async () => {
      try {
        let conn = this.connections.get(profile.name);

        // A ProxyJump connection runs over a forwarded channel on the bastion.
        // Once the connection drops, that channel is dead, so reconnecting the
        // same SSHConnection reuses a corpse and always fails — which used to
        // burn one tool call on every reconnect before the retry rebuilt it.
        // Discard the object so the hop is re-established below.
        if (conn && profile.via && !conn.isConnected()) {
          const dead = conn;
          await dead.close().catch(() => {});
          if (this.connections.get(profile.name) === dead) this.connections.delete(profile.name);
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
        } else {
          reused = true;
        }
        attempt = conn;
        await conn.ensureConnected();
        // A reload landed while this connect was in flight.
        if (this.generation !== gen) {
          if (reused) {
            // A stored connection being reconnected was seen by applyConfig: still stored
            // means its profile was swapped in place and it is current; gone means it is in
            // a toClose list.
            if (this.connections.get(profile.name) !== conn) throw new OperatorError(RELOADED_WHILE_CONNECTING);
          } else {
            // A new connection was built from the profile as it was, and applyConfig never
            // saw it. If the reload would have closed it (profile removed, a connection field
            // changed, its bastion closing), storing it would leave the old posture running
            // after the swap: discard it, rather than wait for connects to drain, which one
            // hung connect could turn into a blocked security reload. Otherwise the link is
            // still the one the config describes, and only the profile object is stale: store
            // it with the current one, as applyConfig would have swapped it in place. Failing
            // it instead let a client reloading in a loop fail every other session's connects.
            const current = this.closedSince(profile.name, gen)
              ? undefined
              : this.config.profiles.find((p) => p.name === profile.name);
            if (!current) throw new OperatorError(RELOADED_WHILE_CONNECTING);
            conn.replaceProfile(current);
          }
        }
        // Stored only once connected and current, so no caller can pick up a stale object
        // mid-connect.
        this.connections.set(profile.name, conn);
        return conn;
      } catch (err) {
        if (attempt) {
          // Identity check: applyConfig may already have dropped the entry, and a newer
          // call may have stored its own since.
          if (this.connections.get(profile.name) === attempt) this.connections.delete(profile.name);
          // A reused connection that applyConfig dropped is its caller's to close.
          if (!reused && this.generation !== gen) await attempt.close().catch(() => {});
        }
        throw err;
      } finally {
        if (this.pending.get(profile.name) === promise) this.pending.delete(profile.name);
      }
    })();

    promise = connect;
    this.pending.set(profile.name, connect);
    return connect;
  }

  get(profileName?: string): SSHConnection | undefined {
    const profile = this.getProfile(profileName);
    return this.connections.get(profile.name);
  }

  /**
   * Refuse everything while nothing is configured.
   *
   * The server now starts with `profiles: []` so a directory or a client's "add server"
   * flow can read `tools/list` (see cli.ts). This is where that state stops being
   * readable and starts being refused, and it sits here rather than in the loader's
   * `getProfile` for one measured reason: the loader's empty check can only live in the
   * no-profile-named branch, so a client calling `run-command` with `profile: "prod"`
   * against an unconfigured server got `Profile "prod" not found` — a message telling the
   * operator they mistyped a name when in fact they have no config at all, and omitting
   * the config path this whole change exists to deliver. Checking before the lookup
   * covers both.
   */
  assertConfigured(): void {
    if (this.config.profiles.length === 0) throw new UnconfiguredError(getConfigPath());
  }

  getProfile(profileName?: string): Profile {
    this.assertConfigured();
    return getConfigProfile(this.config, profileName);
  }

  listConnections(): ConnectionInfo[] {
    return Array.from(this.connections.values()).map((c) => c.toInfo());
  }

  /** Every stored connection, with no profile lookup (the profile may have been removed by a reload). */
  liveConnections(): SSHConnection[] {
    return Array.from(this.connections.values());
  }

  listAllProfiles(): Profile[] {
    return this.config.profiles;
  }

  /** The live config's defaults: read at each use, so a reload takes effect without a rebuild. */
  currentDefaults(): Defaults {
    return this.config.defaults;
  }

  /**
   * Swap in a reloaded config, in one synchronous step so no tool call observes a mix.
   *
   * The registry object stays: rebuilding it would drop the in-memory TOFU host-key pins.
   * A connection whose profile is gone, whose connection fields changed, or that runs
   * through a bastion closing for either reason leaves the maps and comes back in
   * `toClose`, unclosed: closing awaits session kill ladders, and the caller does it after
   * the swap is committed. Every other open connection gets its new profile in place.
   * planReload decides what closes and why; this carries it out.
   */
  applyConfig(next: AppConfig): ApplyResult {
    const { diff, closing, sessionFieldsChanged } = planReload(
      this.config.profiles,
      next.profiles,
      this.connections.keys(),
    );
    const nextByName = new Map(next.profiles.map((p) => [p.name, p]));

    this.config = next;
    this.configGeneration++;

    const toClose: ApplyResult['toClose'] = [];
    for (const [name, reason] of closing) {
      // A new connect in flight for it will be discarded when it would be stored (see
      // getOrCreate); forget it so the next call starts fresh instead of joining it. An
      // in-flight connect for any other profile is kept, and stays joinable.
      this.closedAt.set(name, this.configGeneration);
      this.pending.delete(name);
      const conn = this.connections.get(name);
      if (!conn) continue;
      this.connections.delete(name);
      // Terminal from here on: a tool call that resolved it before the swap must not be
      // able to redial it with the old profile before the reloader gets to close it.
      conn.retire();
      toClose.push({ conn, profile: name, reason });
    }

    for (const change of diff.changed) {
      if (closing.has(change.name)) continue;
      // Only a profile with an open connection: there is nothing to swap otherwise.
      const conn = this.connections.get(change.name);
      const profile = nextByName.get(change.name);
      if (!conn || !profile) continue;
      conn.replaceProfile(profile);
    }

    return { diff, toClose, sessionFieldsChanged };
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
    // Concurrently, for the reason SessionManager.closeAll gives: each connection now waits
    // for its sessions' kill ladders, and serialising multiplied that wait by the number of
    // profiles.
    await Promise.all([...this.connections.values()].map((conn) => conn.close().catch(() => {})));
    this.connections.clear();
  }
}
