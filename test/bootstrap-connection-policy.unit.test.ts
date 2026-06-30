import { describe, it, expect, vi } from 'vitest';
import type { ISshTransport, ServerConfig } from '../src/transports/types';
import type { ResolvedConfig } from '../src/config/types';

// Mock the transport factory so a successful get() never opens a real SSH
// connection. We only care about WHICH name resolveName() lands on and whether
// the multi-source omit-name guard fires.
const { createTransportMock } = vi.hoisted(() => ({ createTransportMock: vi.fn() }));
vi.mock('../src/transports/factory.js', () => ({ createTransport: createTransportMock }));

import { TransportRegistry } from '../src/transports/registry';
import { applyRegistryConnectionPolicy } from '../src/index';

function makeConfig(name: string): ServerConfig {
  return { name, host: `${name}.example`, port: 22, username: 'u', transport: 'ssh2', authMode: 'password', password: 'pw' };
}

function stub(): ISshTransport {
  return {
    name: 'ssh2',
    init: vi.fn().mockResolvedValue(undefined),
    exec: vi.fn(),
    execElevated: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  } as unknown as ISshTransport;
}

/**
 * Build a registry with the given source names registered, then apply the real
 * boot-time connection policy from a ResolvedConfig-shaped object. This is the
 * exact composition bootstrapRegistry() performs in src/index.ts, minus the
 * SSH/key side effects — so it pins the security contract end-to-end.
 *
 * `requireConnection` is attached via cast so this test compiles on the base
 * branch (whose ResolvedConfig predates the field — the helper reads it
 * defensively) and stays valid once the field lands downstream.
 */
function bootstrap(
  names: string[],
  policy: { defaultName?: string; defaultExplicit: boolean; requireConnection?: boolean },
): TransportRegistry {
  const r = new TransportRegistry();
  const sources = names.map(makeConfig);
  for (const c of sources) r.register(c);
  const config = {
    sources,
    perSourceApproval: {},
    defaultName: policy.defaultName,
    defaultExplicit: policy.defaultExplicit,
    ...(policy.requireConnection !== undefined
      ? { requireConnection: policy.requireConnection }
      : {}),
  } as ResolvedConfig;
  applyRegistryConnectionPolicy(r, config);
  return r;
}

describe('applyRegistryConnectionPolicy — boot-time connection guard wiring', () => {
  // A1 (headline fix): multi-source, NO explicit default, omit name → throws.
  it('A1: multi-source + no explicit default + omitted name THROWS', async () => {
    const r = bootstrap(['a', 'b'], { defaultName: 'a', defaultExplicit: false });
    await expect(r.get()).rejects.toThrow(
      /connectionName is required when multiple servers are configured: a, b/,
    );
  });

  // A2: multi-source WITH an explicit user-chosen default, omit name → routes
  // to that default, no throw.
  it('A2: multi-source + explicit default + omitted name routes to the default (no throw)', async () => {
    const s = stub();
    createTransportMock.mockReturnValue(s);
    const r = bootstrap(['a', 'b'], { defaultName: 'b', defaultExplicit: true });
    await expect(r.get()).resolves.toBe(s);
    expect(r.getDefaultName()).toBe('b');
  });

  // A3: single-source, omit name → routes to it, no throw (unchanged behavior).
  it('A3: single-source + omitted name routes to the lone source (no throw)', async () => {
    const s = stub();
    createTransportMock.mockReturnValue(s);
    const r = bootstrap(['solo'], { defaultName: 'solo', defaultExplicit: false });
    await expect(r.get()).resolves.toBe(s);
  });

  // A4: require_connection = false (opt-out), multi-source + omit → guard
  // disabled, routes to first/default, no throw.
  it('A4: require_connection=false opt-out disables the guard (multi-source omit routes to first)', async () => {
    const s = stub();
    createTransportMock.mockReturnValue(s);
    const r = bootstrap(['a', 'b'], {
      defaultName: 'a',
      defaultExplicit: false,
      requireConnection: false,
    });
    await expect(r.get()).resolves.toBe(s);
  });

  // A5: require_connection = true (or absent), multi-source + omit, no explicit
  // default → throws (safe default posture).
  it('A5a: require_connection=true (explicit) + multi-source + no default + omit THROWS', async () => {
    const r = bootstrap(['a', 'b'], {
      defaultName: 'a',
      defaultExplicit: false,
      requireConnection: true,
    });
    await expect(r.get()).rejects.toThrow(/connectionName is required/);
  });

  it('A5b: require_connection ABSENT defaults to safe (multi-source + no default + omit THROWS)', async () => {
    // Mirrors the older ResolvedConfig shape that carries no requireConnection
    // field — the policy helper must default to guard ON.
    const r = bootstrap(['a', 'b'], { defaultName: 'a', defaultExplicit: false });
    await expect(r.get()).rejects.toThrow(/connectionName is required/);
  });

  // Cross-check: an explicit name always resolves regardless of guard state.
  it('explicit connectionName resolves under every policy', async () => {
    const s = stub();
    createTransportMock.mockReturnValue(s);
    const guarded = bootstrap(['a', 'b'], { defaultName: 'a', defaultExplicit: false });
    await expect(guarded.get('b')).resolves.toBe(s);
  });
});
