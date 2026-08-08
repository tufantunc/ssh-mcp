import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { checkAllServers, allServersUp, setupEnv, createAppConfig } from './fixtures.js';
import { isSshServerUp, SSH_HOST } from './helpers.js';
import type { AppConfig, Profile } from '../../src/types.js';

// ProxyJump (profile.via) had no test at all: the recursive getOrCreate, the
// forwardOut error path and the reaping exemption were all unguarded, which is
// how the "reconnect reuses a dead bastion channel" bug survived.
//
// `operator` is reached by forwarding a channel through `admin`. Note that for
// a `via` profile the host/port are resolved from the *bastion's* network, not
// the client's — same semantics as OpenSSH ProxyJump — so the target here is
// the compose service name, reachable only from inside the bastion container.
const TARGET_FROM_BASTION = { host: 'ssh-operator', port: 2222 };
const BASTION_PORT = 2225;

let env: ReturnType<typeof setupEnv>;
let registry: ConnectionRegistry;

function configWithBastion(): AppConfig {
  const base = createAppConfig();
  const template = base.profiles.find((p) => p.name === 'operator')!;
  // The stock test images ship AllowTcpForwarding no, so the hop runs through a
  // dedicated ssh-bastion service (docker-compose) that enables it.
  const bastion: Profile = {
    ...template,
    name: 'bastion',
    host: SSH_HOST,
    port: BASTION_PORT,
    user: 'bastion',
    role: 'admin',
  };
  const jumped: Profile = {
    ...template,
    name: 'behind-bastion',
    host: TARGET_FROM_BASTION.host,
    port: TARGET_FROM_BASTION.port,
    user: 'operator',
    via: 'bastion',
  };
  return { ...base, profiles: [...base.profiles, bastion, jumped] };
}

const bastionUp = isSshServerUp(SSH_HOST, BASTION_PORT);

beforeAll(async () => {
  if (!allServersUp(await checkAllServers())) return;
  env = setupEnv();
  process.env.SSH_MCP_BEHIND_BASTION_PASSWORD = 'oppass';
  process.env.SSH_MCP_BASTION_PASSWORD = 'bastionpass';
  registry = new ConnectionRegistry(configWithBastion(), 'insecure');
});

afterAll(async () => {
  await registry?.closeAll();
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()) || !(await bastionUp))('ProxyJump (profile.via)', () => {
  it('reaches the target host through the bastion', async () => {
    const conn = await registry.getOrCreate('behind-bastion');
    const result = await conn.exec('whoami');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('operator');

    // The bastion connection is established as a side effect.
    expect(registry.get('bastion')?.isConnected()).toBe(true);
  }, 30000);

  it('reconnects through a fresh bastion channel after a drop', async () => {
    const conn = await registry.getOrCreate('behind-bastion');
    expect(conn.isConnected()).toBe(true);

    await conn.close();
    expect(conn.isConnected()).toBe(false);

    // Regression: the registry used to keep the disconnected SSHConnection and
    // call ensureConnected() on it, reusing the dead forwardOut channel — so
    // this first call after a drop always failed and only a retry recovered.
    const again = await registry.getOrCreate('behind-bastion');
    const result = await again.exec('whoami');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('operator');
  }, 30000);

  it('does not reap a bastion that a live connection depends on', async () => {
    await registry.getOrCreate('behind-bastion');
    // connectionIdleReapMs is 60s in the fixture; force the check anyway.
    registry.reapIdleConnections();
    expect(registry.get('bastion')).toBeDefined();
  }, 30000);

  it('fails clearly when the bastion profile does not exist', async () => {
    const base = createAppConfig();
    const broken: Profile = {
      ...base.profiles[0],
      name: 'bad-jump',
      via: 'no-such-profile',
    };
    const r = new ConnectionRegistry({ ...base, profiles: [...base.profiles, broken] }, 'insecure');
    await expect(r.getOrCreate('bad-jump')).rejects.toThrow(/not found/i);
    await r.closeAll();
  }, 30000);
});
