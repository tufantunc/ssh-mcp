import type { AppConfig, Profile, Defaults } from '../../src/types.js';
import type { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import type { PolicyEngine } from '../../src/policy/engine.js';
import type { SSHConnection } from '../../src/ssh/connection.js';
import type { HostKeyMode } from '../../src/ssh/host-key.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import { ConnectionRegistry as Registry } from '../../src/ssh/connection-registry.js';
import { PolicyEngine as Engine, DEFAULT_RULES } from '../../src/policy/engine.js';
import { SSHConnection as Conn } from '../../src/ssh/connection.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';

export const PORTS = { admin: 2222, viewer: 2223, operator: 2224 };

const baseProfile: Omit<Profile, 'name' | 'host' | 'port' | 'user' | 'role'> = {
  auth: 'password',
  // Explicit tier: these fixtures are dev hosts. Without it the strictest tier
  // applies, since names like "admin"/"operator" say nothing about environment.
  group: 'dev',
  tty: false,
  timeout: 15000,
  maxChars: 5000,
  maxOutputBytes: 1048576,
  maxTransferBytes: 1_073_741_824,
  readOnly: false,
  approvalPolicy: 'ask-destructive',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60000,
  sessionBackgroundMaxMs: 3600000,
  commandQuotaPerDay: 0,
};

export const profiles: Record<string, Profile> = {
  admin: { ...baseProfile, name: 'admin', host: SSH_HOST, port: PORTS.admin, user: 'admin', role: 'admin' },
  operator: { ...baseProfile, name: 'operator', host: SSH_HOST, port: PORTS.operator, user: 'operator', role: 'operator' },
  viewer: { ...baseProfile, name: 'viewer', host: SSH_HOST, port: PORTS.viewer, user: 'viewer', role: 'viewer', readOnly: true },
};

const PASSWORDS: Record<string, string> = {
  admin: 'secret',
  operator: 'oppass',
  viewer: 'viewpass',
};

const SUDO_PASSWORDS: Record<string, string | undefined> = {
  admin: 'secret',
  operator: 'oppass',
  viewer: undefined,
};

export interface ServerStatus {
  admin: boolean;
  operator: boolean;
  viewer: boolean;
}

let cachedStatus: ServerStatus | null = null;

export async function checkAllServers(): Promise<ServerStatus> {
  if (cachedStatus) return cachedStatus;
  const [admin, operator, viewer] = await Promise.all([
    isSshServerUp(SSH_HOST, PORTS.admin),
    isSshServerUp(SSH_HOST, PORTS.operator),
    isSshServerUp(SSH_HOST, PORTS.viewer),
  ]);
  cachedStatus = { admin, operator, viewer };
  const down = Object.entries(cachedStatus).filter(([, up]) => !up).map(([name]) => name);
  // Fails loudly in CI rather than letting the whole integration suite skip.
  assertAvailable(down.length === 0, `down: ${down.join(', ') || 'none'}`);
  return cachedStatus;
}

export function allServersUp(s: ServerStatus): boolean {
  return s.admin && s.operator && s.viewer;
}

export function setupEnv(): { save(): void; restore(): void } {
  const saved = { ...process.env };
  for (const [name, pwd] of Object.entries(PASSWORDS)) {
    process.env[`SSH_MCP_${name.toUpperCase()}_PASSWORD`] = pwd;
  }
  for (const [name, pwd] of Object.entries(SUDO_PASSWORDS)) {
    if (pwd) process.env[`SSH_MCP_${name.toUpperCase()}_SUDO_PASSWORD`] = pwd;
  }
  return {
    save() { Object.assign(saved, process.env); },
    restore() { process.env = saved; },
  };
}

export function createAppConfig(): AppConfig {
  const defaults: Defaults = {
    sessionMaxPerConnection: 5,
    sessionIdleTimeoutMs: 60000,
    sessionBackgroundMaxMs: 3600000,
    commandTimeoutMs: 15000,
    commandMaxChars: 5000,
    commandMaxOutputBytes: 1048576,
    transferMaxBytes: 1_073_741_824,
    connectionIdleReapMs: 60000,
    commandQuotaPerDay: 0,
    approvalGrantTtlMs: 0,
    approvalMode: 'ask-destructive',
  };
  return { defaults, profiles: Object.values(profiles) };
}

export function createRegistry(hostKeyMode: HostKeyMode = 'insecure'): ConnectionRegistry {
  return new Registry(createAppConfig(), hostKeyMode);
}

export function createPolicyEngine(): PolicyEngine {
  return new Engine(DEFAULT_RULES);
}

export async function createConnection(profileName: string): Promise<SSHConnection> {
  const profile = profiles[profileName];
  if (!profile) throw new Error(`Unknown profile: ${profileName}`);
  process.env[`SSH_MCP_${profileName.toUpperCase()}_PASSWORD`] = PASSWORDS[profileName];
  const knownHosts = new Map<string, string>();
  const creds = await resolveCredentials(profile);
  const conn = new Conn(profile, creds, knownHosts, 'insecure');
  await conn.ensureConnected();
  return conn;
}
