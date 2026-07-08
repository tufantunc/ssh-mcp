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
    await expect(r.get()).rejects.toThrow(/connectionName is required when multiple servers are configured: a, b/);
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

describe('TransportRegistry.setRequireConnectionWhenMulti (require_connection opt-out)', () => {
  it('opts out of the multi-host omit-name guard when set false (routes to first-registered)', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    // Opt out: the guard must NOT fire, and an omitted name routes to the
    // first-registered fallback ('a') without throwing.
    r.setRequireConnectionWhenMulti(false);
    await expect(r.get()).resolves.toBe(stub);
  });

  it('keeps the guard armed when set true explicitly (multi-host omit still throws)', async () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    r.setRequireConnectionWhenMulti(true);
    await expect(r.get()).rejects.toThrow(/connectionName is required when multiple servers are configured: a, b/);
  });

  it('guard is ON by default (no setter call) for multi-host omit', async () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    await expect(r.get()).rejects.toThrow(/connectionName is required/);
  });

  it('opt-out does not affect single-source omit (always resolves the lone source)', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('solo'));
    r.setRequireConnectionWhenMulti(false);
    await expect(r.get()).resolves.toBe(stub);
  });

  it('an explicit name still routes correctly even when the guard is opted out', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    r.setRequireConnectionWhenMulti(false);
    await expect(r.get('b')).resolves.toBe(stub);
  });
});

describe('TransportRegistry.wouldRejectOmittedName (Codex R2: audit/gating attribution guard mirror)', () => {
  // index.ts resolvedProfileName() calls this BEFORE registry.get() to decide
  // how to attribute an omitted/blank connectionName for gating + audit. It
  // must return exactly the condition under which resolveName() rejects an
  // omitted name, so a guard-rejected call is never attributed to (nor gated
  // as) the first-registered host.
  it('true for multi-source, no explicit default, guard ON (the reject case)', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    expect(r.wouldRejectOmittedName()).toBe(true);
  });

  it('false for a single source (omitted name always resolves the lone host)', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('solo'));
    expect(r.wouldRejectOmittedName()).toBe(false);
  });

  it('false after an explicit setDefault() (omit-name shortcut re-enabled)', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    r.setDefault('b');
    expect(r.wouldRejectOmittedName()).toBe(false);
  });

  it('false when the guard is opted out via setRequireConnectionWhenMulti(false)', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    r.setRequireConnectionWhenMulti(false);
    expect(r.wouldRejectOmittedName()).toBe(false);
  });

  it('false for an empty registry', () => {
    const r = new TransportRegistry();
    expect(r.wouldRejectOmittedName()).toBe(false);
  });

  it('matches resolveName(): predicate true <=> get() rejects an omitted name', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    // Guard armed: predicate true AND get() rejects.
    expect(r.wouldRejectOmittedName()).toBe(true);
    await expect(r.get()).rejects.toThrow(/connectionName is required/);
    // Explicit default flips both to the resolve path.
    r.setDefault('a');
    expect(r.wouldRejectOmittedName()).toBe(false);
    await expect(r.get()).resolves.toBe(stub);
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

  // finding: per-host key reads must be deferred to get(name), not run at
  // register()/bootstrap time, so a missing key on one host cannot break
  // startup or list-servers for the other healthy hosts.
  it('runs prepareConfig lazily on first get(name), never at register()', async () => {
    const prepare = vi.fn<[ServerConfig], Promise<void>>().mockResolvedValue(undefined);
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);

    const r = new TransportRegistry(prepare);
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    // Not called at register / list time.
    expect(prepare).not.toHaveBeenCalled();
    r.list();
    expect(prepare).not.toHaveBeenCalled();

    // Called exactly once, only for the selected host, on first get.
    await r.get('a');
    expect(prepare).toHaveBeenCalledTimes(1);
    expect(prepare.mock.calls[0][0].name).toBe('a');
  });

  it('a prepareConfig failure for one host is not cached and does not affect other hosts', async () => {
    const prepare = vi.fn<[ServerConfig], Promise<void>>()
      .mockRejectedValueOnce(new Error('ENOENT: missing key'))
      .mockResolvedValue(undefined);
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);

    const r = new TransportRegistry(prepare);
    r.register(makeConfig('broken'));
    r.register(makeConfig('healthy'));

    // First get('broken'): prepare rejects -> get rejects, nothing cached.
    await expect(r.get('broken')).rejects.toThrow(/missing key/);
    // The other host is unaffected.
    await expect(r.get('healthy')).resolves.toBe(stub);
    // A later get('broken') retries prepare (now resolves).
    await expect(r.get('broken')).resolves.toBe(stub);
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

  // Migrated from the dropped index.unit.test `getOrCreateInitializedTransport`
  // suite (base pr/kerberos-transport, Codex-P2). The single-host init-race
  // primitive (getOrCreateInitializedTransport + activeTransportCache) was
  // dropped in favor of TransportRegistry.get as the sole lifecycle owner, so
  // its concurrency-PUBLISH guarantee must survive as a registry-level guard:
  // two concurrent get(name) calls share one in-flight init and NO live
  // transport is published (observable via list().connected) until init
  // resolves — otherwise a concurrent OpenSSH/password caller could enter
  // runSsh before SSH_ASKPASS exists.
  it('does not publish a live transport until the shared in-flight init resolves', async () => {
    let resolveInit!: () => void;
    const init = vi.fn<() => Promise<void>>().mockImplementation(
      () => new Promise<void>((res) => { resolveInit = res; }),
    );
    const stub = makeStub(init);
    createTransportMock.mockReturnValue(stub);

    const r = new TransportRegistry();
    r.register(makeConfig('race'));

    const p1 = r.get('race');
    const p2 = r.get('race');

    // Both concurrent callers share ONE in-flight init.
    expect(createTransportMock).toHaveBeenCalledTimes(1);
    expect(init).toHaveBeenCalledTimes(1);
    // Critical regression guard: while init is still pending, no half-initialized
    // transport is observable — list() reports the connection as not-connected.
    expect(r.list().find((x) => x.name === 'race')!.connected).toBe(false);

    resolveInit();
    const [t1, t2] = await Promise.all([p1, p2]);

    // Only after init resolves is the single live transport published to both
    // callers and reflected as connected.
    expect(t1).toBe(stub);
    expect(t2).toBe(stub);
    expect(r.list().find((x) => x.name === 'race')!.connected).toBe(true);
    // A subsequent get() reuses the published transport without re-initializing.
    await expect(r.get('race')).resolves.toBe(stub);
    expect(init).toHaveBeenCalledTimes(1);
  });
});

describe('TransportRegistry.get (finding 1: stale in-flight init must not survive a reload)', () => {
  it('discards a transport whose init resolves AFTER a reload (closeAll) completes', async () => {
    // Deferred init: hold the first get('alpha') open across a full reload.
    let resolveOldInit: () => void = () => {};
    const oldInit = vi.fn<() => Promise<void>>().mockImplementation(
      () => new Promise<void>((res) => { resolveOldInit = res; }),
    );
    const oldStub = makeStub(oldInit);
    oldStub.close = vi.fn().mockResolvedValue(undefined);

    // The post-reload re-dial uses a brand-new transport that inits instantly.
    const newStub = makeStub(vi.fn().mockResolvedValue(undefined));

    // First createTransport() (pre-reload) -> oldStub; second (post-reload re-get) -> newStub.
    createTransportMock.mockReturnValueOnce(oldStub).mockReturnValue(newStub);

    const r = new TransportRegistry();
    r.register(makeConfig('alpha'));

    // 1. Kick off a get() whose init() is now parked mid-flight.
    const inflight = r.get('alpha');
    // 2. A config hot-reload swaps params for 'alpha' and drops stale transports.
    r.replaceAll([{ ...makeConfig('alpha'), host: 'alpha2.example' }]);
    await r.closeAll();
    // 3. NOW let the old init resolve — it must NOT repopulate the registry.
    resolveOldInit();
    const got = await inflight;

    // The in-flight get re-resolved against the current config and returned the
    // fresh transport, not the stale one. The stale transport was closed.
    expect(got).toBe(newStub);
    expect(oldStub.close).toHaveBeenCalledTimes(1);

    // A subsequent get() returns the cached fresh transport (no re-init).
    const next = await r.get('alpha');
    expect(next).toBe(newStub);
    // 'alpha' is connected via the NEW transport only.
    expect(r.list().find((x) => x.name === 'alpha')!.connected).toBe(true);
  });

  it('does not cache the stale transport even when the reloaded config dropped its name', async () => {
    let resolveOldInit: () => void = () => {};
    const oldInit = vi.fn<() => Promise<void>>().mockImplementation(
      () => new Promise<void>((res) => { resolveOldInit = res; }),
    );
    const oldStub = makeStub(oldInit);
    oldStub.close = vi.fn().mockResolvedValue(undefined);
    const newStub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValueOnce(oldStub).mockReturnValue(newStub);

    const r = new TransportRegistry();
    r.register(makeConfig('alpha'));

    const inflight = r.get('alpha');
    // Reload replaces 'alpha' with a different source entirely.
    r.replaceAll([makeConfig('beta')]);
    await r.closeAll();
    resolveOldInit();

    // 'alpha' no longer exists -> the re-resolve surfaces a clear error, and the
    // stale transport is still discarded/closed (never cached).
    await expect(inflight).rejects.toThrow(/Unknown connection name: alpha/);
    expect(oldStub.close).toHaveBeenCalledTimes(1);
    expect(r.list().map((x) => x.name)).toEqual(['beta']);
  });
});

describe('TransportRegistry.get (Codex R4 finding 1: stale init finally must not evict a newer in-flight init)', () => {
  // Flush all pending microtasks so a parked async chain (init finally →
  // generation re-check → recursive re-get) runs to its next await point.
  const flush = () => new Promise<void>((res) => setTimeout(res, 0));

  it('a stale initializer completing after a reload does not delete the newer init, so no duplicate init runs', async () => {
    // init #1 (pre-reload) and init #2 (post-reload) are both parked; init #2
    // uses a fresh transport. A THIRD createTransport call would mean init #1's
    // finally wrongly evicted init #2's in-flight entry, letting a later get()
    // start a duplicate init (the leak this finding is about).
    let resolveInit1: () => void = () => {};
    const init1 = vi.fn<() => Promise<void>>().mockImplementation(
      () => new Promise<void>((res) => { resolveInit1 = res; }),
    );
    const stub1 = makeStub(init1);
    stub1.close = vi.fn().mockResolvedValue(undefined);

    let resolveInit2: () => void = () => {};
    const init2 = vi.fn<() => Promise<void>>().mockImplementation(
      () => new Promise<void>((res) => { resolveInit2 = res; }),
    );
    const stub2 = makeStub(init2);

    // A third stub only ever materializes if the bug lets a duplicate init run.
    const stub3 = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock
      .mockReturnValueOnce(stub1)
      .mockReturnValueOnce(stub2)
      .mockReturnValue(stub3);

    const r = new TransportRegistry();
    r.register(makeConfig('alpha'));

    // 1. First get parks init #1 mid-flight.
    const p1 = r.get('alpha');
    // 2. A hot-reload swaps params for 'alpha' and drops stale transports —
    //    this clears the in-flight init map + tokens and bumps the generation.
    r.replaceAll([{ ...makeConfig('alpha'), host: 'alpha2.example' }]);
    await r.closeAll();
    // 3. A fresh get installs init #2 under the SAME name (its own token).
    const p2 = r.get('alpha');
    expect(createTransportMock).toHaveBeenCalledTimes(2);

    // 4. NOW the stale init #1 resolves. Its finally must NOT evict init #2's
    //    entry (the slot holds init #2's token, not init #1's). Flush so init
    //    #1's finally + generation re-check + recursive re-get all run.
    resolveInit1();
    await flush();

    // 5. A concurrent get while init #2 is still parked must SHARE init #2's
    //    in-flight promise — not start a third init. If the finally had evicted
    //    init #2, this would call createTransport a 3rd time (stub3).
    const p3 = r.get('alpha');
    expect(createTransportMock).toHaveBeenCalledTimes(2);

    // 6. Finish init #2; every waiter resolves to the single post-reload stub.
    resolveInit2();
    const [t1, t2, t3] = await Promise.all([p1, p2, p3]);
    expect(t2).toBe(stub2);
    expect(t3).toBe(stub2); // shared the same in-flight init, no duplicate
    expect(t1).toBe(stub2); // stale init #1 re-resolved against the new config
    // The stale transport was closed, and only two transports were ever built.
    expect(stub1.close).toHaveBeenCalledTimes(1);
    expect(createTransportMock).toHaveBeenCalledTimes(2);
    // 'alpha' is connected via the post-reload transport only.
    expect(r.list().find((x) => x.name === 'alpha')!.connected).toBe(true);
  });
});

describe('TransportRegistry.get (Codex R4 finding 2: lazy key prep survives a reload)', () => {
  it('runs prepareConfig lazily per-host after replaceAll, isolating one source\'s bad key', async () => {
    // The registry keeps its lazy prepareConfig hook across a reload (replaceAll
    // swaps configs, not the registry). A source whose key is unreadable must
    // fail ONLY when that host is selected — never at reload time, and never
    // breaking an unrelated healthy host. This is the mechanism the fixed
    // buildConfigReloader relies on (no eager prepareSources on reload).
    const prepare = vi.fn<[ServerConfig], Promise<void>>().mockImplementation(async (cfg) => {
      if (cfg.host === 'broken.example') throw new Error('ENOENT: unreadable key file');
    });
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);

    const r = new TransportRegistry(prepare);
    r.register(makeConfig('orig'));

    // Reload swaps in one healthy source + one whose key would be unreadable.
    r.replaceAll([
      { ...makeConfig('healthy'), host: 'healthy.example' },
      { ...makeConfig('broken'), host: 'broken.example' },
    ]);
    // The swap itself read NO keys — prepareConfig is deferred to get().
    expect(prepare).not.toHaveBeenCalled();

    // The healthy host works; the bad key on the other source is irrelevant.
    await expect(r.get('healthy')).resolves.toBe(stub);
    // The broken host fails only now, when actually selected (lazy) — a reload
    // was never rolled back by it.
    await expect(r.get('broken')).rejects.toThrow(/unreadable key file/);
    // A later get('broken') retries prepare (the rejection was not cached).
    prepare.mockResolvedValue(undefined);
    await expect(r.get('broken')).resolves.toBe(stub);
  });
});

describe('TransportRegistry.getReloadGeneration (Codex R4 finding 4: post-approval revalidation signal)', () => {
  it('starts at 0, increments once per closeAll, and is stable across get()/register()', async () => {
    const stub = makeStub(vi.fn().mockResolvedValue(undefined));
    createTransportMock.mockReturnValue(stub);

    const r = new TransportRegistry();
    r.register(makeConfig('solo'));
    // Baseline: no reload has happened.
    expect(r.getReloadGeneration()).toBe(0);

    // A get() (lazy init) does not bump the generation.
    await r.get('solo');
    expect(r.getReloadGeneration()).toBe(0);

    // Each reload (closeAll drops stale transports) bumps it exactly once — the
    // exec/sudo-exec handlers compare this before/after an awaited approval to
    // detect that a config hot-reload landed during the wait.
    await r.closeAll();
    expect(r.getReloadGeneration()).toBe(1);
    await r.closeAll();
    expect(r.getReloadGeneration()).toBe(2);
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
    // finding 6: with >1 server and no explicit setDefault(), get() rejects an
    // omitted connectionName, so NO host is advertised as a usable default.
    expect(rows.every((x) => x.isDefault === false)).toBe(true);
    expect(rows.every((x) => x.connected === false)).toBe(true);

    await r.get('a');
    rows = r.list();
    expect(rows.find((x) => x.name === 'a')!.connected).toBe(true);
    expect(rows.find((x) => x.name === 'b')!.connected).toBe(false);
  });

  it('marks the lone server as the default (single-server case)', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('solo'));
    expect(r.list().find((x) => x.name === 'solo')!.isDefault).toBe(true);
  });

  it('marks only the explicitly-set default when multiple servers are configured', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    r.setDefault('b');
    const rows = r.list();
    expect(rows.find((x) => x.name === 'a')!.isDefault).toBe(false);
    expect(rows.find((x) => x.name === 'b')!.isDefault).toBe(true);
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

describe('TransportRegistry.resolveProfileName (audit attribution, non-throwing)', () => {
  it('returns the single registered name when connectionName is omitted', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('only'));
    expect(r.resolveProfileName()).toBe('only');
  });

  it('returns (unresolved) for an ambiguous multi-host call (omitted name, >1 server, no explicit default)', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    // This is exactly the case registry.get() rejects as ambiguous — the audit
    // record must NOT be attributed to the first server ('a').
    expect(r.resolveProfileName()).toBe('(unresolved)');
  });

  it('returns the explicit default when setDefault() re-enabled the omit-name shortcut', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    r.setDefault('b');
    expect(r.resolveProfileName()).toBe('b');
  });

  it('echoes an explicitly-requested name even if unknown (accurate caller intent)', () => {
    const r = new TransportRegistry();
    r.register(makeConfig('a'));
    r.register(makeConfig('b'));
    expect(r.resolveProfileName('b')).toBe('b');
    expect(r.resolveProfileName('nope')).toBe('nope');
  });

  it('falls back to "default" when no servers are registered', () => {
    const r = new TransportRegistry();
    expect(r.resolveProfileName()).toBe('default');
  });
});
