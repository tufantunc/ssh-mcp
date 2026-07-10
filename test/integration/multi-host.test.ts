import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkAllServers, allServersUp, setupEnv, createRegistry, type ServerStatus } from './fixtures.js';
import type { ConnectionRegistry } from '../../src/ssh/connection-registry.js';

let status: ServerStatus;
let env: ReturnType<typeof setupEnv>;
let registry: ConnectionRegistry;

beforeAll(async () => {
  status = await checkAllServers();
  if (!allServersUp(status)) return;
  env = setupEnv();
  registry = createRegistry();
});

afterAll(async () => {
  await registry?.closeAll();
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()))('ConnectionRegistry multi-host', () => {
  it('connects to all 3 profiles independently', async () => {
    const admin = await registry.getOrCreate('admin');
    const operator = await registry.getOrCreate('operator');
    const viewer = await registry.getOrCreate('viewer');
    expect(admin.isConnected()).toBe(true);
    expect(operator.isConnected()).toBe(true);
    expect(viewer.isConnected()).toBe(true);
    expect(admin).not.toBe(operator);
    expect(admin).not.toBe(viewer);
  });

  it('parallel exec across 3 hosts returns correct results', async () => {
    const [adminRes, opRes, viewerRes] = await Promise.all([
      (await registry.getOrCreate('admin')).exec('echo admin'),
      (await registry.getOrCreate('operator')).exec('echo operator'),
      (await registry.getOrCreate('viewer')).exec('echo viewer'),
    ]);
    expect(adminRes.stdout.trim()).toBe('admin');
    expect(opRes.stdout.trim()).toBe('operator');
    expect(viewerRes.stdout.trim()).toBe('viewer');
  });

  it('cached connection reuse returns same object', async () => {
    const conn1 = await registry.getOrCreate('admin');
    const conn2 = await registry.getOrCreate('admin');
    expect(conn1).toBe(conn2);
  });

  it('listConnections reports all 3 profiles', () => {
    const infos = registry.listConnections();
    expect(infos.length).toBe(3);
    const names = infos.map((i) => i.profile).sort();
    expect(names).toEqual(['admin', 'operator', 'viewer']);
  });

  it('close one profile does not affect others', async () => {
    const viewer = registry.get('viewer')!;
    await viewer.close();
    expect(viewer.isConnected()).toBe(false);
    expect(registry.get('admin')!.isConnected()).toBe(true);
    expect(registry.get('operator')!.isConnected()).toBe(true);
  });

  it('nonexistent profile name throws', async () => {
    await expect(registry.getOrCreate('nonexistent')).rejects.toThrow(/not found/i);
  });
});
