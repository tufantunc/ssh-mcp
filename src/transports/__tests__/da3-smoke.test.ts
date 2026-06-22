import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TransportRegistry } from '../registry.js';
import { createTransport } from '../factory.js';
import type { ServerConfig, ISshTransport } from '../types.js';

/**
 * D-A3 safe multi-source smoke (card t_de9a0113, task §3).
 *
 * The earlier guard tests (registry.test.ts) assert that an omitted/blank
 * connectionName REJECTS in multi-source mode. This file pins the stronger,
 * deliverable-critical property the task asks us to prove:
 *
 *   the fail-fast happens BEFORE any transport is constructed/connected.
 *
 * We spy on the transport factory and assert its call count. In the omitted
 * multi-source case the spy is NEVER invoked — the guard throws inside
 * resolveName, so no socket is ever opened against a real host (card redline:
 * no real production command execution). In the valid-name and opt-out cases
 * the spy IS invoked exactly once, with the config that proves correct routing.
 *
 * Network safety: createTransport is mocked to an in-memory fake — get() never
 * opens a socket even on the success paths.
 *
 * Self-containment note (PR-1, guard-only lane): this file deliberately drives
 * the registry guard DIRECTLY via the TransportRegistry constructor option and
 * the setRequireConnectionWhenMulti setter (both shipped in the registry guard
 * commit). The original D-A3 file also carried an end-to-end
 * resolveConfig -> bootstrapRegistry parity block; that block depends on the
 * TOML [server].require_connection opt-out (src/config/, PR-1b) which is NOT in
 * this PR, so it is intentionally omitted here and lives with PR-1b.
 */
vi.mock('../factory.js', () => ({
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
      /connectionName is required when multiple SSH connections are configured/,
    );

    // The whole point: no transport was created, so no socket was opened toward
    // any of the (production) hosts. The failure is purely the routing guard.
    expect(factory).not.toHaveBeenCalled();
  });

  it('multi-source + blank/whitespace name: same before-transport fail-fast', async () => {
    const r = new TransportRegistry();
    r.register(cfg('EIP2-DB'));
    r.register(cfg('dc03'));

    for (const blank of ['', '   ', '\t']) {
      factory.mockClear();
      await expect(r.get(blank)).rejects.toThrow(/connectionName is required/);
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

  it('opt-out (requireConnectionWhenMulti=false): multi-source + omitted reverts to silent default (transport built for the default only)', async () => {
    const r = new TransportRegistry({ requireConnectionWhenMulti: false });
    r.register(cfg('EIP2-DB'));
    r.register(cfg('dc03'));

    const t = await r.get(undefined);
    expect(t.name).toBe('EIP2-DB'); // first-registered default restored
    expect(factory).toHaveBeenCalledTimes(1);
    expect(factory.mock.calls[0][0]).toMatchObject({ name: 'EIP2-DB' });
  });

  it('opt-out via setter (setRequireConnectionWhenMulti(false)): same legacy silent-default fallback', async () => {
    const r = new TransportRegistry();
    r.setRequireConnectionWhenMulti(false);
    r.register(cfg('EIP2-DB'));
    r.register(cfg('dc03'));

    const t = await r.get(undefined);
    expect(t.name).toBe('EIP2-DB');
    expect(factory).toHaveBeenCalledTimes(1);
    expect(factory.mock.calls[0][0]).toMatchObject({ name: 'EIP2-DB' });
  });

  it('single-source + omitted name: omission UX preserved (transport built for the lone source)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('only'));

    const t = await r.get(undefined);
    expect(t.name).toBe('only');
    expect(factory).toHaveBeenCalledTimes(1);
  });
});
