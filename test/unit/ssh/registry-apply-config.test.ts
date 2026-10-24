import { describe, it, expect } from 'vitest';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import type { SSHConnection } from '../../../src/ssh/connection.js';
import type { Profile } from '../../../src/types.js';
import { makeProfile as fixtureProfile } from '../../fixtures/profile.js';
import { configOf, plant } from '../../helpers/registry.js';

/** The fixture under `name`; `deploy` is the user the closed-keeps-its-profile case reads back. */
const makeProfile = (name: string, overrides: Partial<Profile> = {}): Profile =>
  fixtureProfile({ name, user: 'deploy', ...overrides });

const reasons = (toClose: { profile: string; reason: string }[]) =>
  Object.fromEntries(toClose.map((c) => [c.profile, c.reason]));

describe('ConnectionRegistry.applyConfig', () => {
  it('swaps the profile in place on a policy-only change', () => {
    const before = makeProfile('web', { role: 'operator' });
    const registry = new ConnectionRegistry(configOf(before));
    const conn = plant(registry, before);

    const result = registry.applyConfig(configOf(makeProfile('web', { role: 'viewer' })));

    expect(result.toClose).toEqual([]);
    expect(registry.liveConnections()).toEqual([conn]);
    expect(registry.listConnections()).toHaveLength(1);
    expect(registry.get('web')).toBe(conn);
    expect(conn.profile.role).toBe('viewer');
    expect(result.diff.changed).toEqual([{ name: 'web', fields: ['role'] }]);
  });

  it('closes a connection whose user changed', () => {
    const before = makeProfile('web');
    const registry = new ConnectionRegistry(configOf(before));
    const conn = plant(registry, before);

    const result = registry.applyConfig(configOf(makeProfile('web', { user: 'other' })));

    expect(result.toClose).toEqual([{ conn, profile: 'web', reason: 'connection-field' }]);
    expect(registry.liveConnections()).toEqual([]);
    expect(registry.get('web')).toBeUndefined();
    // The closed connection keeps the profile it was opened with.
    expect(conn.profile.user).toBe('deploy');
  });

  it('closes a connection whose profile was removed', () => {
    const web = makeProfile('web');
    const db = makeProfile('db');
    const registry = new ConnectionRegistry(configOf(web, db));
    const conn = plant(registry, web);

    const result = registry.applyConfig(configOf(db));

    expect(result.toClose).toEqual([{ conn, profile: 'web', reason: 'removed' }]);
    expect(result.diff.removed).toEqual(['web']);
    expect(registry.liveConnections()).toEqual([]);
  });

  it('closes the dependents of a bastion whose host changed', () => {
    const bastion = makeProfile('bastion');
    const inner = makeProfile('inner', { via: 'bastion' });
    const registry = new ConnectionRegistry(configOf(bastion, inner));
    const bastionConn = plant(registry, bastion);
    const innerConn = plant(registry, inner);

    const result = registry.applyConfig(
      configOf(makeProfile('bastion', { host: 'moved.example.test' }), inner),
    );

    expect(reasons(result.toClose)).toEqual({ bastion: 'connection-field', inner: 'bastion-closed' });
    expect(result.toClose.find((c) => c.profile === 'bastion')?.conn).toBe(bastionConn);
    expect(result.toClose.find((c) => c.profile === 'inner')?.conn).toBe(innerConn);
    expect(registry.liveConnections()).toEqual([]);
  });

  it('follows via transitively', () => {
    const a = makeProfile('a');
    const b = makeProfile('b', { via: 'a' });
    const c = makeProfile('c', { via: 'b' });
    const other = makeProfile('other');
    const registry = new ConnectionRegistry(configOf(a, b, c, other));
    plant(registry, a);
    plant(registry, b);
    plant(registry, c);
    const otherConn = plant(registry, other);

    const result = registry.applyConfig(configOf(makeProfile('a', { port: 2200 }), b, c, other));

    expect(reasons(result.toClose)).toEqual({ a: 'connection-field', b: 'bastion-closed', c: 'bastion-closed' });
    expect(registry.liveConnections()).toEqual([otherConn]);
  });

  it('closes both a removed bastion and the connection that ran through it', () => {
    // Review Focus 5: the dependent was re-pointed (the loader refuses a via that names a
    // missing profile), so its own reason is the via change; its old via still counts.
    const bastion = makeProfile('bastion');
    const inner = makeProfile('inner', { via: 'bastion' });
    const registry = new ConnectionRegistry(configOf(bastion, inner));
    plant(registry, bastion);
    plant(registry, inner);

    const result = registry.applyConfig(configOf(makeProfile('inner')));

    expect(reasons(result.toClose)).toEqual({ bastion: 'removed', inner: 'connection-field' });
    expect(registry.liveConnections()).toEqual([]);
  });

  it('closes a dependent whose bastion changed even with no live bastion connection', () => {
    // The dependent's channel was opened through the bastion as it was configured before.
    const bastion = makeProfile('bastion');
    const inner = makeProfile('inner', { via: 'bastion' });
    const registry = new ConnectionRegistry(configOf(bastion, inner));
    const innerConn = plant(registry, inner);

    const result = registry.applyConfig(configOf(makeProfile('bastion', { user: 'root' }), inner));

    expect(result.toClose).toEqual([{ conn: innerConn, profile: 'inner', reason: 'bastion-closed' }]);
  });

  it('keeps the connection on a workdir change and reports it', () => {
    const before = makeProfile('web');
    const registry = new ConnectionRegistry(configOf(before));
    const conn = plant(registry, before);

    const result = registry.applyConfig(configOf(makeProfile('web', { workdir: '/srv/app', role: 'viewer' })));

    expect(result.toClose).toEqual([]);
    expect(registry.get('web')).toBe(conn);
    expect(conn.profile.workdir).toBe('/srv/app');
    expect(result.sessionFieldsChanged).toEqual([{ name: 'web', fields: ['workdir'] }]);
  });

  // A session-fixed field matters only where a session could have fixed it: a profile
  // with no open connection has none.
  it('does not report session fields for a profile with no open connection', () => {
    const registry = new ConnectionRegistry(configOf(makeProfile('web'), makeProfile('idle')));
    plant(registry, makeProfile('web'));

    const result = registry.applyConfig(configOf(
      makeProfile('web', { workdir: '/srv/app' }),
      makeProfile('idle', { workdir: '/srv/app' }),
    ));

    expect(result.diff.changed.map((c) => c.name).sort()).toEqual(['idle', 'web']);
    expect(result.sessionFieldsChanged).toEqual([{ name: 'web', fields: ['workdir'] }]);
  });

  it('does not report session fields for a connection it closes', () => {
    const before = makeProfile('web');
    const registry = new ConnectionRegistry(configOf(before));
    plant(registry, before);

    const result = registry.applyConfig(configOf(makeProfile('web', { workdir: '/srv/app', host: 'x.test' })));

    expect(result.sessionFieldsChanged).toEqual([]);
  });

  it('drops an in-flight connect for a closed profile so the next call starts fresh', () => {
    const before = makeProfile('web');
    const registry = new ConnectionRegistry(configOf(before));
    const pending = (registry as any).pending as Map<string, Promise<SSHConnection>>;
    pending.set('web', new Promise(() => {}));

    registry.applyConfig(configOf(makeProfile('web', { user: 'other' })));

    expect(pending.has('web')).toBe(false);
  });

  it('increments generation on every apply', () => {
    const before = makeProfile('web');
    const registry = new ConnectionRegistry(configOf(before));
    expect(registry.generation).toBe(0);

    registry.applyConfig(configOf(makeProfile('web', { role: 'viewer' })));
    expect(registry.generation).toBe(1);

    registry.applyConfig(configOf(makeProfile('web', { role: 'viewer' })));
    expect(registry.generation).toBe(2);
    expect(registry.listAllProfiles()[0]?.role).toBe('viewer');
  });
});
