import { describe, it, expect, vi } from 'vitest';
import { TransportRegistry } from '../src/transports/registry.js';
import type { ServerConfig, ISshTransport } from '../src/transports/types.js';

/**
 * TransportRegistry connectionName guard contract.
 *
 * - one source + omitted name resolves to the lone source;
 * - multiple sources + omitted name fails fast and lists valid names;
 * - an explicit default or an explicit guard opt-out restores omission;
 * - an unknown explicit name remains an error.
 *
 * The transport factory is stubbed, so success paths never open a socket.
 */
vi.mock('../src/transports/factory.js', () => ({
  createTransport: vi.fn(
    (): ISshTransport => ({
      name: 'openssh',
      init: async () => {},
      exec: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
      execElevated: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
      close: async () => {},
    }),
  ),
}));

function cfg(name: string): ServerConfig {
  return {
    name,
    host: `${name}.example`,
    port: 22,
    username: 'u',
    authMode: 'kerberos',
    kerberos: true,
    transport: 'openssh',
  };
}

describe('TransportRegistry resolveName — source-count-aware fail-fast (D-A1 guard)', () => {
  it('single source + omitted name: resolves through the full get() path (omission UX preserved)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('only'));

    // No throw: omission is intentional, safe convenience UX for true
    // single-server deployments. Reaches the (stubbed) transport, no socket.
    const t = await r.get(undefined);
    expect(t).toBeTruthy();
    expect(t.name).toBe('openssh');
    expect(r.getDefaultName()).toBe('only');
  });

  it('multi source + omitted name: FAIL-FAST throw listing valid names (R1 landmine removed — was silent fallback to first)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('first')); // first-registered-wins -> would have been silent default
    r.register(cfg('second'));
    r.register(cfg('third'));

    await expect(r.get(undefined)).rejects.toThrow(
      /connectionName is required when multiple servers are configured/,
    );

    // Error must be actionable: list the available names so the caller can fix it.
    const err = await r.get(undefined).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toContain('first');
    expect((err as Error).message).toContain('second');
    expect((err as Error).message).toContain('third');
  });

  it('multi source + valid name: resolves and routes to that source', async () => {
    const r = new TransportRegistry();
    r.register(cfg('first'));
    r.register(cfg('second'));

    const t = await r.get('second');
    expect(t).toBeTruthy();
    expect(t.name).toBe('openssh');
  });

  it('unknown non-empty name remains fail-fast (R2 regression guard — must NOT regress, and must NOT be masked by the new required-name message)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('a'));
    r.register(cfg('b'));

    // resolveName throws on unknown names BEFORE any transport is created.
    await expect(r.get('nonesuch')).rejects.toThrow(/Unknown connection name/);
    const err = await r.get('nonesuch').catch((e: Error) => e);
    expect((err as Error).message).not.toMatch(/connectionName is required/);
  });

  it('empty registry + omitted name: fail-fast "No servers registered" (no socket opened)', async () => {
    const r = new TransportRegistry();
    expect(r.hasAny()).toBe(false);

    await expect(r.get(undefined)).rejects.toThrow(/No servers registered/);
  });
});

describe('TransportRegistry — explicit selection compatibility seam', () => {
  it('permits omission after an explicit default or the evolved guard opt-out', async () => {
    const r = new TransportRegistry();
    r.register(cfg('first'));
    r.register(cfg('second'));

    const evolved = r as TransportRegistry & {
      setRequireConnectionWhenMulti?: (required: boolean) => void;
    };
    if (evolved.setRequireConnectionWhenMulti) {
      evolved.setRequireConnectionWhenMulti(false);
    } else {
      r.setDefault('first');
    }

    await expect(r.get(undefined)).resolves.toBeTruthy();
    expect(r.list().find((s) => s.name === 'first')?.isDefault).toBe(true);
  });
});

describe('TransportRegistry — preserved invariants (must NOT regress)', () => {
  it('single source: that source becomes the default', () => {
    const r = new TransportRegistry();
    r.register(cfg('only'));

    expect(r.getDefaultName()).toBe('only');
    expect(r.names()).toEqual(['only']);
    expect(r.list().find((s) => s.name === 'only')?.isDefault).toBe(true);
  });

  it('names().length reflects the REAL source count (the signal the guard branches on — NOT the CLI isMultiHost flag)', () => {
    const r = new TransportRegistry();
    expect(r.hasAny()).toBe(false);
    expect(r.names().length).toBe(0);

    r.register(cfg('a'));
    expect(r.names().length).toBe(1); // size === 1 -> guard PRESERVES omission UX
    expect(r.hasAny()).toBe(true);

    r.register(cfg('b'));
    expect(r.names().length).toBe(2); // size > 1  -> guard REQUIRES connectionName
  });

  it('explicit default restores omission and routes to the selected source', async () => {
    const r = new TransportRegistry();
    r.register(cfg('first'));
    r.register(cfg('second'));

    r.setDefault('second');
    expect(r.getDefaultName()).toBe('second');
    await expect(r.get(undefined)).resolves.toBeTruthy();
    expect(r.list().find((s) => s.name === 'second')?.isDefault).toBe(true);
  });

  it('register rejects duplicate names', () => {
    const r = new TransportRegistry();
    r.register(cfg('dup'));
    expect(() => r.register(cfg('dup'))).toThrow(/Duplicate server name/);
  });
});
