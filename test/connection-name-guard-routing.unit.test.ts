import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TransportRegistry } from '../src/transports/registry.js';
import { createTransport } from '../src/transports/factory.js';
import type { ServerConfig, ISshTransport } from '../src/transports/types.js';

/**
 * Connection-name routing smoke tests.
 *
 * The factory spy proves ambiguous/unknown requests fail before transport
 * construction, while explicit and single-source requests route correctly.
 * The transport is an in-memory fake, so no socket is opened.
 */
vi.mock('../src/transports/factory.js', () => ({
  createTransport: vi.fn(
    (cfg: ServerConfig): ISshTransport => ({
      // Echo the resolved name back so routing assertions can read it.
      name: cfg.name as any,
      init: async () => {},
      exec: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
      execElevated: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
      close: async () => {},
    }),
  ),
}));

const factory = vi.mocked(createTransport);

function cfg(name: string): ServerConfig {
  return {
    name,
    host: `${name}.invalid.example`, // bogus host: if ever reached, a real connect would fail
    port: 22,
    username: 'u',
    authMode: 'kerberos',
    kerberos: true,
    transport: 'openssh',
  };
}

beforeEach(() => {
  factory.mockClear();
});

describe('D-A3 smoke: multi-source fail-fast occurs BEFORE transport routing', () => {
  it('multi-source + omitted name: throws the guard error AND never constructs a transport', async () => {
    const r = new TransportRegistry();
    r.register(cfg('EIP2-DB')); // first-registered would have been the silent default
    r.register(cfg('dc03'));
    r.register(cfg('UOFProdAP'));

    await expect(r.get(undefined)).rejects.toThrow(
      /connectionName is required when multiple servers are configured/,
    );

    // The whole point: no transport was created, so no socket was opened toward
    // any of the (production) hosts. The failure is purely the routing guard.
    expect(factory).not.toHaveBeenCalled();
  });

  it('blank/whitespace explicit names remain unknown and fail before transport creation', async () => {
    const r = new TransportRegistry();
    r.register(cfg('EIP2-DB'));
    r.register(cfg('dc03'));

    for (const blank of ['   ', '\t']) {
      factory.mockClear();
      await expect(r.get(blank)).rejects.toThrow(/Unknown connection name/);
      expect(factory).not.toHaveBeenCalled();
    }
  });

  it('multi-source + valid explicit name: routes through get() to exactly that source (one transport, correct config)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('EIP2-DB'));
    r.register(cfg('dc03'));
    r.register(cfg('UOFProdAP'));

    const t = await r.get('dc03');
    expect(t.name).toBe('dc03');
    // Routed to the named source — and only it — exactly once.
    expect(factory).toHaveBeenCalledTimes(1);
    expect(factory.mock.calls[0][0]).toMatchObject({ name: 'dc03' });
  });

  it('unknown name still fail-fast before transport (R2 guard not masked by the required-name message)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('EIP2-DB'));
    r.register(cfg('dc03'));

    await expect(r.get('nonesuch')).rejects.toThrow(/Unknown connection name/);
    expect(factory).not.toHaveBeenCalled();
  });

  it('single-source + omitted name: omission UX preserved (transport built for the lone source)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('only'));

    const t = await r.get(undefined);
    expect(t.name).toBe('only');
    expect(factory).toHaveBeenCalledTimes(1);
  });
});
