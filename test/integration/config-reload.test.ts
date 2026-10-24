import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { SSHConnection } from '../../src/ssh/connection.js';
import { loadConfigWithDigest } from '../../src/config/loader.js';
import { registerTools } from '../../src/tools/registry.js';
import { textOf } from '../unit/tools/harness.js';
import { buildReloader } from '../unit/config/reload-rig.js';
import type { AppConfig, AuditRecord } from '../../src/types.js';
import { isSshServerUp, assertAvailable, SSH_HOST } from './helpers.js';
import { PORTS, allServersUp, checkAllServers, createAppConfig, createRegistry, setupEnv } from './fixtures.js';

/** The same config with one profile's fields overridden. */
function withProfile(name: string, overrides: Record<string, unknown>): AppConfig {
  const config = createAppConfig();
  return {
    ...config,
    profiles: config.profiles.map((p) => (p.name === name ? { ...p, ...overrides } : p)),
  };
}

const up = await isSshServerUp(SSH_HOST, PORTS.admin);
assertAvailable(up, `admin (${SSH_HOST}:${PORTS.admin})`);

describe.skipIf(!up)('config reload during an in-flight connect (Review Focus 2)', () => {
  const env = setupEnv();
  let registry: ConnectionRegistry;

  beforeAll(() => env.save());
  afterAll(() => env.restore());
  afterEach(async () => {
    vi.restoreAllMocks();
    await registry?.closeAll();
  });

  it('discards and closes a connect that resolves after a connection-field swap', async () => {
    const close = vi.spyOn(SSHConnection.prototype, 'close');
    registry = createRegistry();
    const connecting = registry.getOrCreate('admin');

    const result = registry.applyConfig(withProfile('admin', { user: 'operator' }));
    expect(result.diff.changed).toEqual([{ name: 'admin', fields: ['user'] }]);

    await expect(connecting).rejects.toThrow(
      'The configuration was reloaded while connecting; retry the call.',
    );
    expect(registry.get('admin')).toBeUndefined();
    expect(registry.liveConnections()).toEqual([]);
    // The discarded connection was closed, not left open outside the registry.
    expect(close).toHaveBeenCalledTimes(1);
    const discarded = close.mock.contexts[0] as SSHConnection;
    expect(discarded.isConnected()).toBe(false);

    // Back to the original user: the retry builds a new connection, not the closed one.
    registry.applyConfig(createAppConfig());
    const retried = await registry.getOrCreate('admin');
    expect(retried.isConnected()).toBe(true);
    expect(registry.get('admin')).toBe(retried);
    expect(retried).not.toBe(discarded);
  });

  it('stores a connect that resolves after a policy-only swap, under the new profile', async () => {
    const close = vi.spyOn(SSHConnection.prototype, 'close');
    registry = createRegistry();
    const connecting = registry.getOrCreate('admin');

    registry.applyConfig(withProfile('admin', { role: 'viewer' }));

    const conn = await connecting;
    expect(conn.isConnected()).toBe(true);
    expect(conn.profile.role).toBe('viewer');
    expect(conn.profile).toBe(registry.getProfile('admin'));
    expect(registry.get('admin')).toBe(conn);
    expect(close).not.toHaveBeenCalled();
  });

  it('keeps a stored connection reconnecting across a policy-only swap', async () => {
    // applyConfig saw this one (it is in the map) and swapped its profile in place, so it
    // is current: discarding it would kill its sessions for nothing.
    registry = createRegistry();
    const conn = await registry.getOrCreate('admin');
    await conn.close();
    expect(conn.isConnected()).toBe(false);

    const reconnecting = registry.getOrCreate('admin');
    const result = registry.applyConfig(withProfile('admin', { role: 'viewer' }));
    expect(result.toClose).toEqual([]);

    await expect(reconnecting).resolves.toBe(conn);
    expect(conn.isConnected()).toBe(true);
    expect(conn.profile.role).toBe('viewer');
    expect(registry.get('admin')).toBe(conn);
  });

  it('refuses a stored connection reconnecting across a connection-field swap', async () => {
    registry = createRegistry();
    const conn = await registry.getOrCreate('admin');
    await conn.close();

    const reconnecting = registry.getOrCreate('admin');
    const result = registry.applyConfig(withProfile('admin', { user: 'operator' }));
    expect(result.toClose.map((c) => c.conn)).toEqual([conn]);

    await expect(reconnecting).rejects.toThrow(/reloaded while connecting/);
    expect(registry.get('admin')).toBeUndefined();
    await conn.close();
  });
});

/**
 * A reload as a client reaches it: a real config file, a real reloader over the real
 * registry and policy engine, the MCP tools in front, and the compose SSH servers behind.
 */

const allUp = allServersUp(await checkAllServers());

type Target = keyof typeof PORTS;

/**
 * One `[[profiles]]` entry pointing at a compose server. Role "admin" throughout, so the
 * role never refuses a command and a refusal below is the approvalPolicy's doing.
 */
const profileToml = (name: string, target: Target, extra = '') => `
[[profiles]]
name = "${name}"
host = "${SSH_HOST}"
port = ${PORTS[target]}
user = "${target}"
auth = "password"
role = "admin"
group = "dev"
${extra}
`;

interface Live {
  registry: ConnectionRegistry;
  /** Approval prompts the client answered (always accepted). */
  prompts: string[];
  call(name: string, args?: Record<string, unknown>): Promise<any>;
  rewrite(toml: string): Promise<void>;
  auditRecords(): Promise<AuditRecord[]>;
  close(): Promise<void>;
}


async function startLive(toml: string): Promise<Live> {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-reload-int-'));
  const path = join(dir, 'config.toml');
  const auditPath = join(dir, 'audit.log');
  await writeFile(path, toml, 'utf8');
  await chmod(path, 0o600);

  const { config, sha256 } = await loadConfigWithDigest(path, {});
  const { registry, policy, audit, reloader } = buildReloader({ config, path, auditPath, sha256 });

  const server = new McpServer({ name: 'test', version: '0.0.0' }, { capabilities: { tools: {} } });
  registerTools(server, registry, policy, audit, { reloader });
  const client = new Client({ name: 'test-client', version: '0.0.0' }, { capabilities: { elicitation: {} } });
  const prompts: string[] = [];
  client.setRequestHandler(ElicitRequestSchema, async (req) => {
    prompts.push(req.params.message);
    return { action: 'accept', content: { confirm: true } };
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);

  return {
    registry,
    prompts,
    call: (name, args = {}) => client.callTool({ name, arguments: args }) as Promise<any>,
    rewrite: (next) => writeFile(path, next, 'utf8'),
    async auditRecords() {
      await audit.close();
      const text = await readFile(auditPath, 'utf8').catch(() => '');
      return text.split('\n').filter(Boolean).map((l) => JSON.parse(l) as AuditRecord);
    },
    async close() {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
      await registry.closeAll().catch(() => {});
      await rm(dir, { recursive: true, force: true });
    },
  };
}

describe.skipIf(!allUp)('reload-config against live connections', () => {
  const env = setupEnv();
  let live: Live | undefined;

  beforeAll(() => env.save());
  afterAll(() => env.restore());
  afterEach(async () => {
    vi.restoreAllMocks();
    await live?.close();
    live = undefined;
  });

  it('applies an approvalPolicy change to an open connection without reconnecting', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    live = await startLive(profileToml('operator', 'operator'));
    const marker = '/tmp/ssh-mcp-reload-policy-marker';

    const ls = await live.call('read-command', { profile: 'operator', command: 'ls /' });
    expect(ls.isError).toBeFalsy();
    const conn = live.registry.get('operator');
    expect(conn?.isConnected()).toBe(true);

    // Under the startup policy the destructive command is put to the client, which approves.
    const before = await live.call('run-command', { profile: 'operator', command: `rm -rf ${marker}` });
    expect(before.isError).toBeFalsy();
    expect(live.prompts).toHaveLength(1);

    await live.rewrite(profileToml('operator', 'operator', 'approvalPolicy = "deny"'));
    const reload = await live.call('reload-config', { action: 'reload' });
    expect(reload.isError).toBeFalsy();
    expect(textOf(reload)).toContain('Profiles: changed operator (approvalPolicy).');
    expect(textOf(reload)).not.toContain('Closed connection');

    const after = await live.call('run-command', { profile: 'operator', command: `rm -rf ${marker}` });
    expect(after.isError).toBe(true);
    expect(textOf(after)).toMatch(/POLICY_DENIED/);
    // Refused by policy, not put to the client.
    expect(live.prompts).toHaveLength(1);
    // The same connection, still open: the new policy reached it in place.
    expect(live.registry.get('operator')).toBe(conn);
    expect(conn?.isConnected()).toBe(true);
  }, 60000);

  it('closes the connection on a user change, and the next call connects as the new user', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    live = await startLive(profileToml('admin', 'admin'));

    const first = await live.call('run-command', { profile: 'admin', command: 'id -un' });
    expect(first.isError).toBeFalsy();
    expect(textOf(first).trim()).toBe('admin');
    const conn = live.registry.get('admin')!;

    // Same profile name, now pointing at the operator server as operator. The password
    // comes from the profile-named env var, so it moves with the profile. Restored even
    // on a failure, so a failing assertion here cannot break the next test's login.
    const savedPassword = process.env.SSH_MCP_ADMIN_PASSWORD;
    process.env.SSH_MCP_ADMIN_PASSWORD = 'oppass';
    try {
      await live.rewrite(profileToml('admin', 'operator'));
      const reload = await live.call('reload-config', { action: 'reload' });
      expect(reload.isError).toBeFalsy();
      expect(textOf(reload)).toMatch(/Profiles: changed admin \((?=[^)]*\bport\b)(?=[^)]*\buser\b)[^)]*\)\./);
      expect(textOf(reload)).toContain('Closed connection admin (connection field changed), no sessions.');

      expect(conn.isConnected()).toBe(false);
      expect(live.registry.get('admin')).toBeUndefined();

      const second = await live.call('run-command', { profile: 'admin', command: 'id -un' });
      expect(second.isError).toBeFalsy();
      expect(textOf(second).trim()).toBe('operator');
      expect(live.registry.get('admin')).not.toBe(conn);
    } finally {
      if (savedPassword === undefined) delete process.env.SSH_MCP_ADMIN_PASSWORD;
      else process.env.SSH_MCP_ADMIN_PASSWORD = savedPassword;
    }
  }, 60000);

  it('closes a removed profile\'s connection and sessions, and audits each session close', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    live = await startLive(profileToml('operator', 'operator') + profileToml('admin', 'admin'));

    const opened = await live.call('open-session', {
      profile: 'operator',
      name: 'sleeper',
      type: 'background',
      command: 'sleep 300',
    });
    expect(opened.isError).toBeFalsy();
    const conn = live.registry.get('operator')!;
    expect(conn.listSessions().map((s) => s.name)).toEqual(['sleeper']);

    await live.rewrite(profileToml('admin', 'admin'));
    const reload = await live.call('reload-config', { action: 'reload' });
    expect(reload.isError).toBeFalsy();
    expect(textOf(reload)).toContain('Profiles: removed operator.');
    expect(textOf(reload)).toContain('Closed connection operator (profile removed), sessions closed: sleeper.');

    expect(conn.isConnected()).toBe(false);
    expect(conn.listSessions()).toEqual([]);
    expect(live.registry.liveConnections().map((c) => c.profile.name)).not.toContain('operator');
    const sessions = await live.call('list-sessions', { profile: 'operator' });
    expect(sessions.isError).toBe(true);

    const records = await live.auditRecords();
    const closes = records.filter((r) => r.binary === 'session:close');
    expect(closes).toHaveLength(1);
    expect(closes[0]).toMatchObject({
      profile: 'operator',
      user: 'operator',
      command: 'session:close background sleeper (reload)',
      decision: 'allow',
      ruleId: 'session-release',
    });
    const reloads = records.filter((r) => r.binary === 'config:reload');
    expect(reloads.map((r) => r.decision)).toEqual(['allow']);
  }, 60000);
});
