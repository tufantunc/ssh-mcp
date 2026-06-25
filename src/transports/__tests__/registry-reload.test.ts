/**
 * TransportRegistry config-hot-reload surface (PR-9): getAllConfigs /
 * snapshotState / restoreState / replaceAll.
 *
 * replaceAll must validate-before-swap (dup names / unknown default leave the
 * registry untouched), default to the first source when no default is given,
 * and drop live description overrides. snapshot/restore must round-trip the
 * config maps for rollback. No transport is ever created (config map only), so
 * no sandbox sshd is needed.
 */
import { describe, it, expect } from 'vitest';

import { TransportRegistry } from '../registry.js';
import type { ServerConfig } from '../types.js';

function cfg(name: string, host = `${name}.example`): ServerConfig {
  return { name, host, port: 22, username: 'root', authMode: 'kerberos', transport: 'openssh', kerberos: true };
}

function seed(): TransportRegistry {
  const r = new TransportRegistry();
  r.register(cfg('alpha'));
  r.register(cfg('beta'));
  return r;
}

describe('TransportRegistry.replaceAll', () => {
  it('atomically swaps the whole source set and defaults to the first', () => {
    const r = seed();
    r.replaceAll([cfg('gamma'), cfg('delta')]);
    expect(r.names()).toEqual(['gamma', 'delta']);
    expect(r.getDefaultName()).toBe('gamma');
  });

  it('honours an explicit default name', () => {
    const r = seed();
    r.replaceAll([cfg('gamma'), cfg('delta')], 'delta');
    expect(r.getDefaultName()).toBe('delta');
  });

  it('rejects an empty source list, leaving the registry untouched', () => {
    const r = seed();
    expect(() => r.replaceAll([])).toThrow(/at least one source/);
    expect(r.names()).toEqual(['alpha', 'beta']);
  });

  it('rejects duplicate names before mutating (validate-before-swap)', () => {
    const r = seed();
    expect(() => r.replaceAll([cfg('gamma'), cfg('gamma')])).toThrow(/Duplicate server name/);
    // Old set preserved — the swap never half-applied.
    expect(r.names()).toEqual(['alpha', 'beta']);
  });

  it('rejects an unknown explicit default before mutating', () => {
    const r = seed();
    expect(() => r.replaceAll([cfg('gamma')], 'nope')).toThrow(/unknown server/);
    expect(r.names()).toEqual(['alpha', 'beta']);
  });

  it('drops live description overrides on swap', () => {
    const r = seed();
    r.setDescription('alpha', 'live edit');
    expect(r.getDescriptionOverride('alpha')).toBe('live edit');
    r.replaceAll([cfg('alpha'), cfg('beta')]);
    expect(r.getDescriptionOverride('alpha')).toBeUndefined();
  });
});

describe('TransportRegistry snapshot/restore (rollback support)', () => {
  it('round-trips the config set + default + overrides', () => {
    const r = seed();
    r.setDescription('alpha', 'live edit');
    const snap = r.snapshotState();

    // Mutate away from the snapshot.
    r.replaceAll([cfg('gamma')]);
    expect(r.names()).toEqual(['gamma']);
    expect(r.getEffectiveDescription('gamma')).toBe('');

    // Restore puts everything back.
    r.restoreState(snap);
    expect(r.names()).toEqual(['alpha', 'beta']);
    expect(r.getDefaultName()).toBe('alpha');
    expect(r.getDescriptionOverride('alpha')).toBe('live edit');
  });

  it('getAllConfigs returns the registered configs in order', () => {
    const r = seed();
    expect(r.getAllConfigs().map(c => c.name)).toEqual(['alpha', 'beta']);
  });
});
