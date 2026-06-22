import { describe, it, expect } from 'vitest';
import { TransportRegistry } from '../registry.js';
import type { ServerConfig } from '../types.js';

/**
 * Characterization (golden master) test for TransportRegistry name resolution.
 *
 * Purpose (D-0 / card t_997d701a): pin the CURRENT behavior of the registry
 * BEFORE the source-count-aware guard (D-A1) changes it, so the behavioral
 * delta becomes visible and reviewable in the diff. This file asserts the
 * CURRENT (pre-fix) contract — including the R1 landmine we intend to remove:
 *
 *   multi-source + omitted connectionName  ->  silently resolves to the
 *   first-registered source (registry.ts resolveName fallback, `return
 *   this.defaultName`). In the live deployment that first source is the
 *   EIP2-DB production PostgreSQL host.
 *
 * These tests MUST pass on the clean base (fab9d80). When D-A1 lands the
 * fail-fast guard, the "CURRENT LANDMINE" case below is expected to be
 * REPLACED by a positive throw assertion (see P1-plan §7 Branch A). That
 * replacement should be a deliberate, reviewed edit to THIS file — that is the
 * whole point of a golden master: the change of behavior shows up as a change
 * to the test.
 *
 * Network safety (card redline — never touch a real host): we never trigger an
 * outbound connection. get() only reaches createTransport()/init() when a name
 * resolves to a real default; we therefore exercise get() ONLY on its throw
 * paths (unknown name / empty registry), which reject inside resolveName()
 * before any transport is created. The silent-fallback landmine itself is
 * pinned via the public surface (getDefaultName / names / list), not by
 * opening a socket.
 */
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

describe('TransportRegistry resolveName — CURRENT behavior (characterization / golden master)', () => {
  it('single source: that source becomes the default (intended omission UX — to be PRESERVED)', () => {
    const r = new TransportRegistry();
    r.register(cfg('only'));

    expect(r.getDefaultName()).toBe('only');
    expect(r.names()).toEqual(['only']);
    expect(r.list().find(s => s.name === 'only')?.isDefault).toBe(true);
  });

  it('CURRENT LANDMINE (to be CHANGED by D-A1): multi source defaults to the first-registered source, so an omitted connectionName would silently resolve here', () => {
    const r = new TransportRegistry();
    r.register(cfg('first'));   // first-registered-wins -> becomes default
    r.register(cfg('second'));
    r.register(cfg('third'));

    // Today resolveName(undefined) returns this default with NO source-count
    // check. This is the R1 silent fallback the D-A1 source guard will remove:
    // post-fix, omission with >1 source must fail-fast instead of landing here.
    expect(r.getDefaultName()).toBe('first');
    expect(r.names()).toEqual(['first', 'second', 'third']);
  });

  it('guard surface: names().length reflects the REAL source count (the signal the future guard branches on — NOT the CLI isMultiHost flag)', () => {
    const r = new TransportRegistry();
    expect(r.hasAny()).toBe(false);
    expect(r.names().length).toBe(0);

    r.register(cfg('a'));
    expect(r.names().length).toBe(1); // size === 1 -> guard will PRESERVE omission UX
    expect(r.hasAny()).toBe(true);

    r.register(cfg('b'));
    expect(r.names().length).toBe(2); // size > 1  -> guard will REQUIRE connectionName
  });

  it('setDefault overrides first-registered-wins (default need not be source[0])', () => {
    const r = new TransportRegistry();
    r.register(cfg('first'));
    r.register(cfg('second'));

    r.setDefault('second');
    expect(r.getDefaultName()).toBe('second');
  });

  it('register rejects duplicate names (existing invariant — must NOT regress)', () => {
    const r = new TransportRegistry();
    r.register(cfg('dup'));
    expect(() => r.register(cfg('dup'))).toThrow(/Duplicate server name/);
  });

  it('unknown connectionName already fail-fast today (R2 — regression guard, must NOT regress)', async () => {
    const r = new TransportRegistry();
    r.register(cfg('a'));
    r.register(cfg('b'));

    // resolveName throws on unknown names BEFORE any transport is created, so
    // this never opens a socket.
    await expect(r.get('nonesuch')).rejects.toThrow(/Unknown connection name/);
  });

  it('empty registry: omitted name fail-fast with "No servers registered" (no socket opened)', async () => {
    const r = new TransportRegistry();
    expect(r.hasAny()).toBe(false);

    await expect(r.get(undefined)).rejects.toThrow(/No servers registered/);
  });
});
