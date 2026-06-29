import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { ISshTransport, ServerConfig } from '../src/transports/types';

// The registry lazily builds transports via the factory's createTransport. Mock
// it so we can drive init() success/failure deterministically without any real
// SSH connection. vi.hoisted keeps the mock fn available inside the hoisted
// vi.mock factory.
const { createTransportMock } = vi.hoisted(() => ({ createTransportMock: vi.fn() }));
vi.mock('../src/transports/factory.js', () => ({ createTransport: createTransportMock }));

import { TransportRegistry } from '../src/transports/registry';

function makeConfig(name: string): ServerConfig {
  return { name, host: `${name}.example`, port: 22, username: 'u', transport: 'ssh2', authMode: 'password', password: 'pw' };
}

function makeStub(init: () => Promise<void>): ISshTransport {
  return {
    name: 'ssh2',
    init,
    exec: vi.fn(),
    execElevated: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  } as unknown as ISshTransport;
}

beforeEach(() => {
  createTransportMock.mockReset();
});

describe('TransportRegistry.register / names / duplicate', () => {
  it('registers configs and lists names in registration order', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    expect(r.names()).toEqual(['a', 'b']);
    expect(r.hasAny()).toBe(true);
    expect(r.getDefaultName()).toBe('a'); // first registered is the default
  });

  it('rejects a config with no name', () => {
    const r = new TransportRegistry();
    expect(() => r.register({ ...makeConfig('x'), name: '' })).toThrow(/name is required/);
  });

  it('rejects a duplicate server name', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    expect(() => r.register(makeConfig('a'))).toThrow(/Duplicate server name: a/);
  });
});

describe('TransportRegistry.resolveName (finding 3: omitted name in multi-host)', () => {
  it('throws when name omitted and >1 server configured with no explicit default', async () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    await expect(r.get()).rejects.toThrow(
      /connectionName is required when multiple SSH connections are configured\. Specify one of: a, b\./,
    );
  });

  it('still resolves by explicit name when multiple servers are configured', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    await expect(r.get('b')).resolves.toBe(stub);
  });

  it('allows omitted name after an explicit setDefault() even with multiple servers', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    r.setDefault('b');
    await expect(r.get()).resolves.toBe(stub);
  });

  it('resolves the lone server when only one is configured and name is omitted', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('solo'));
    await expect(r.get()).resolves.toBe(stub);
  });

  it('throws a descriptive error for an unknown name', async () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    await expect(r.get('nope')).rejects.toThrow(/Unknown connection name: nope\. Registered: a/);
  });
});

describe('TransportRegistry.get (finding 1: rejected init must not be cached)', () => {
  it('retries init on a later get() after the first init rejects', async () => {
    const init = vi
      .fn<[], Promise<void>>()
      .mockRejectedValueOnce(new Error('connect timeout'))
      .mockResolvedValue(undefined);
    const stub = makeStub(init);
    createTransportMock.mockReturnValue(stub);

    const r = new TransportRegistry();
    r.register(makeConfig('flaky'));

    // First get(): init rejects.
    await expect(r.get('flaky')).rejects.toThrow(/connect timeout/);
    // Second get(): the rejected promise must NOT be cached, so init runs again
    // and now resolves.
    await expect(r.get('flaky')).resolves.toBe(stub);
    expect(init).toHaveBeenCalledTimes(2);
  });

  it('caches the live transport on success (init runs once across repeated gets)', async () => {
    const init = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);
    const stub = makeStub(init);
    createTransportMock.mockReturnValue(stub);

    const r = new TransportRegistry();
    r.register(makeConfig('stable'));

    const a = await r.get('stable');
    const b = await r.get('stable');
    expect(a).toBe(b);
    expect(init).toHaveBeenCalledTimes(1);
  });

  it('serializes concurrent gets so init runs once for parallel callers', async () => {
    let resolveInit: () => void = () => {};
    const init = vi.fn<() => Promise<void>>().mockImplementation(
      () => new Promise<void>((res) => { resolveInit = res; }),
    );
    const stub = makeStub(init);
    createTransportMock.mockReturnValue(stub);

    const r = new TransportRegistry();
    r.register(makeConfig('p'));

    const p1 = r.get('p');
    const p2 = r.get('p');
    resolveInit();
    const [t1, t2] = await Promise.all([p1, p2]);
    expect(t1).toBe(stub);
    expect(t2).toBe(stub);
    expect(init).toHaveBeenCalledTimes(1);
  });
});

describe('TransportRegistry.list / closeAll', () => {
  it('reports connection status and default flag', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));

    let rows = r.list();
    expect(rows.map((x) => x.name)).toEqual(['a', 'b']);
    expect(rows.find((x) => x.name === 'a')!.isDefault).toBe(true);
    expect(rows.every((x) => x.connected === false)).toBe(true);

    await r.get('a');
    rows = r.list();
    expect(rows.find((x) => x.name === 'a')!.connected).toBe(true);
    expect(rows.find((x) => x.name === 'b')!.connected).toBe(false);
  });

  it('closeAll closes connected transports and clears state', async () => {
    const close = vi.fn().mockResolvedValue(undefined);
    const stub = { name: 'ssh2', init: vi.fn().mockResolvedValue(undefined), exec: vi.fn(), execElevated: vi.fn(), close } as unknown as ISshTransport;
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    await r.get('a');
    await r.closeAll();
    expect(close).toHaveBeenCalledTimes(1);
    expect(r.list().find((x) => x.name === 'a')!.connected).toBe(false);
  });
});
