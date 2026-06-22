import { describe, it, expect, vi } from 'vitest';
import { TransportRegistry } from '../registry.js';
import type { ServerConfig, ISshTransport } from '../types.js';

/**
 * TransportRegistry name-resolution contract.
 *
 * History: D-0 (card t_997d701a) seeded this file as a *characterization* golden
 * master that PINNED the pre-fix R1 landmine — multi-source + omitted
 * connectionName silently resolving to the first-registered source (live
 * default = EIP2-DB production PostgreSQL). D-A1 (card t_7e1261d2) lands the
 * source-count-aware fail-fast guard, so the landmine case is now REPLACED by a
 * positive throw assertion. That replacement is the whole point of a golden
 * master: the behavior change shows up as a change to the test (P1-plan §7
 * Branch A Step 1).
 *
 * Post-fix contract pinned here:
 *   - single source  + omitted name  -> resolves (omission UX preserved)
 *   - multi  source  + omitted name  -> THROWS, listing valid names (R1 fixed)
 *   - multi  source  + blank/ws name -> THROWS too (no '' slipping past as omit)
 *   - any    source  + unknown name  -> THROWS (R2 regression guard, unchanged)
 *   - opt-out (D-A2 seam)            -> multi + omitted reverts to default
 *
 * Network safety (card redline — never touch a real host): we stub the transport
 * factory so get() NEVER opens a socket. This lets the single-source success
 * case exercise the FULL get() path (resolveName -> createTransport -> init)
 * with an in-memory fake, while the throw cases reject inside resolveName before
 * the factory is ever reached.
 */
vi.mock('../factory.js', () => ({
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
      /connectionName is required when multiple SSH connections are configured/,
    );

    // Error must be actionable: list the available names so the caller can fix it.
    const err = await r.get(undefined).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toContain('first');
    expect((err as Error).message).toContain('second');
    expect((err as Error).message).toContain('third');
  });

  it('multi source + blank/whitespace name: FAIL-FAST equivalently (empty/ws must not slip through as omitted/default)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('alpha'));
    r.register(cfg('beta'));

    await expect(r.get('')).rejects.toThrow(
      /connectionName is required when multiple SSH connections are configured/,
    );
    await expect(r.get('   ')).rejects.toThrow(
      /connectionName is required when multiple SSH connections are configured/,
    );
    await expect(r.get('\t')).rejects.toThrow(
      /connectionName is required when multiple SSH connections are configured/,
    );
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

describe('TransportRegistry — D-A2 opt-out seam (default must be safe: require-when-multi)', () => {
  it('default (no opt-out): multi source + omitted name throws (safe default)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('first'));
    r.register(cfg('second'));

    await expect(r.get(undefined)).rejects.toThrow(/connectionName is required/);
  });

  it('opt-out enabled: multi source + omitted name reverts to silent default (escape hatch D-A2 will wire from config)', async () => {
    const r = new TransportRegistry({ requireConnectionWhenMulti: false });
    r.register(cfg('first'));
    r.register(cfg('second'));

    // Opt-out explicitly restores legacy convenience: omission -> first default.
    const t = await r.get(undefined);
    expect(t).toBeTruthy();
    expect(r.getDefaultName()).toBe('first');
  });

  it('setter form (D-A2 may inject post-construction) toggles the same behavior', async () => {
    const r = new TransportRegistry();
    r.register(cfg('first'));
    r.register(cfg('second'));

    r.setRequireConnectionWhenMulti(false);
    await expect(r.get(undefined)).resolves.toBeTruthy();

    r.setRequireConnectionWhenMulti(true);
    await expect(r.get(undefined)).rejects.toThrow(/connectionName is required/);
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

  it('setDefault overrides first-registered-wins (default need not be source[0])', () => {
    const r = new TransportRegistry();
    r.register(cfg('first'));
    r.register(cfg('second'));

    r.setDefault('second');
    expect(r.getDefaultName()).toBe('second');
  });

  it('register rejects duplicate names', () => {
    const r = new TransportRegistry();
    r.register(cfg('dup'));
    expect(() => r.register(cfg('dup'))).toThrow(/Duplicate server name/);
  });
});
