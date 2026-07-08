/**
 * TransportRegistry.closeChanged() (PR-9, Codex V5 finding): a successful
 * config reload must close ONLY the transports of sources that were removed or
 * whose connection parameters changed, preserving the live persistent
 * transport of every source whose connection params are unchanged. A save that
 * only edits a description or approval policy must NOT tear down a healthy ssh2
 * Client out from under an in-flight command.
 *
 * These tests inject fake transports directly into the registry's cache (no
 * sandbox sshd needed) and assert exactly which ones closeChanged() closes.
 */
import { describe, it, expect } from 'vitest';

import { TransportRegistry } from '../registry.js';
import type { ServerConfig, ISshTransport } from '../types.js';

function cfg(name: string, over: Partial<ServerConfig> = {}): ServerConfig {
  return {
    name,
    host: `${name}.example`,
    port: 22,
    username: 'root',
    authMode: 'kerberos',
    transport: 'openssh',
    kerberos: true,
    ...over,
  };
}

/** A fake transport that records whether close() was called. */
function fakeTransport(): ISshTransport & { closed: boolean } {
  const t = {
    name: 'ssh2' as const,
    closed: false,
    async init() {},
    async exec() { return { stdout: '', stderr: '', exitCode: 0 }; },
    async execElevated() { return { stdout: '', stderr: '', exitCode: 0 }; },
    async close() { t.closed = true; },
  };
  return t;
}

/**
 * Seed a registry with the given configs AND a live fake transport cached for
 * each, so closeChanged() has real entries to preserve/close. Returns the
 * registry, the injected transports keyed by name, and a pre-swap config-map
 * snapshot suitable to pass to closeChanged() after replaceAll().
 */
function seedWithTransports(configs: ServerConfig[]): {
  reg: TransportRegistry;
  transports: Record<string, ISshTransport & { closed: boolean }>;
  prevConfigs: Map<string, ServerConfig>;
} {
  const reg = new TransportRegistry();
  for (const c of configs) reg.register(c);
  const transports: Record<string, ISshTransport & { closed: boolean }> = {};
  const cache: Map<string, ISshTransport> = (reg as any).transports;
  for (const c of configs) {
    const t = fakeTransport();
    transports[c.name] = t;
    cache.set(c.name, t);
  }
  const prevConfigs = reg.snapshotState().configs;
  return { reg, transports, prevConfigs };
}

describe('TransportRegistry.closeChanged', () => {
  it('preserves the live transport of a source whose connection params are unchanged', async () => {
    const { reg, transports, prevConfigs } = seedWithTransports([cfg('alpha'), cfg('beta')]);

    // Reload edits ONLY beta's description — connection params identical.
    reg.replaceAll([cfg('alpha'), cfg('beta', { description: 'edited label' })]);
    await reg.closeChanged(prevConfigs);

    // Nothing closed: both connections' params are unchanged.
    expect(transports.alpha.closed).toBe(false);
    expect(transports.beta.closed).toBe(false);
    // Both live transports remain cached.
    const cache: Map<string, ISshTransport> = (reg as any).transports;
    expect(cache.has('alpha')).toBe(true);
    expect(cache.has('beta')).toBe(true);
  });

  it('closes ONLY the transport whose connection params changed', async () => {
    const { reg, transports, prevConfigs } = seedWithTransports([cfg('alpha'), cfg('beta')]);

    // beta's host changes (a real connection-param edit); alpha untouched.
    reg.replaceAll([cfg('alpha'), cfg('beta', { host: 'beta2.example' })]);
    await reg.closeChanged(prevConfigs);

    expect(transports.alpha.closed).toBe(false);
    expect(transports.beta.closed).toBe(true);
    const cache: Map<string, ISshTransport> = (reg as any).transports;
    expect(cache.has('alpha')).toBe(true);   // healthy connection preserved
    expect(cache.has('beta')).toBe(false);   // stale connection dropped → re-dials lazily
  });

  it('closes the transport of a removed source', async () => {
    const { reg, transports, prevConfigs } = seedWithTransports([cfg('alpha'), cfg('beta')]);

    // beta is dropped from the source set entirely.
    reg.replaceAll([cfg('alpha')]);
    await reg.closeChanged(prevConfigs);

    expect(transports.alpha.closed).toBe(false);
    expect(transports.beta.closed).toBe(true);
    const cache: Map<string, ISshTransport> = (reg as any).transports;
    expect(cache.has('beta')).toBe(false);
  });

  it('treats an approval-only edit as unchanged (keeps the live transport)', async () => {
    const { reg, transports, prevConfigs } = seedWithTransports([cfg('alpha')]);

    reg.replaceAll([cfg('alpha', { approval: { mode: 'manual' } })]);
    await reg.closeChanged(prevConfigs);

    expect(transports.alpha.closed).toBe(false);
    expect(((reg as any).transports as Map<string, ISshTransport>).has('alpha')).toBe(true);
  });

  it('bumps the reload generation so a mid-flight init discards a stale transport', async () => {
    const { reg, prevConfigs } = seedWithTransports([cfg('alpha')]);
    const before = reg.getReloadGeneration();
    reg.replaceAll([cfg('alpha')]);
    await reg.closeChanged(prevConfigs);
    expect(reg.getReloadGeneration()).toBe(before + 1);
  });

  it('closes an auth-param change (keyPath) even when host/port/user are identical', async () => {
    const { reg, transports, prevConfigs } = seedWithTransports([
      cfg('keyhost', { transport: 'ssh2', authMode: 'key', kerberos: false, keyPath: '/keys/old' }),
    ]);

    reg.replaceAll([
      cfg('keyhost', { transport: 'ssh2', authMode: 'key', kerberos: false, keyPath: '/keys/new' }),
    ]);
    await reg.closeChanged(prevConfigs);

    expect(transports.keyhost.closed).toBe(true);
  });
});
