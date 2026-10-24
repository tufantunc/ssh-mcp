import { describe, it, expect } from 'vitest';
import { planReload } from '../../../src/config/reload-diff.js';
import type { Profile } from '../../../src/types.js';
import { makeProfile } from '../../fixtures/profile.js';

const p = (name: string, overrides: Partial<Profile> = {}) => makeProfile({ name, ...overrides });

/**
 * The deciding half of ConnectionRegistry.applyConfig, with no registry: what closes and
 * why, and which kept connections had a session-fixed field change. `closing` is
 * compared as entries, in order, because the registry hands connections back in it.
 */
describe('planReload', () => {
  it('closes a removed profile', () => {
    const plan = planReload([p('web'), p('db')], [p('db')], ['web']);

    expect(plan.diff.removed).toEqual(['web']);
    expect([...plan.closing]).toEqual([['web', 'removed']]);
    expect(plan.sessionFieldsChanged).toEqual([]);
  });

  it('closes a live name the new config does not have, even one the old did not list', () => {
    const plan = planReload([p('web')], [p('web')], ['web', 'stray']);

    expect([...plan.closing]).toEqual([['stray', 'removed']]);
  });

  it('closes a profile whose connection field changed', () => {
    const plan = planReload([p('web')], [p('web', { user: 'other' })], ['web']);

    expect(plan.diff.changed).toEqual([{ name: 'web', fields: ['user'] }]);
    expect([...plan.closing]).toEqual([['web', 'connection-field']]);
  });

  it('does not close on a policy-only change', () => {
    const plan = planReload([p('web')], [p('web', { role: 'viewer' })], ['web']);

    expect(plan.diff.changed).toEqual([{ name: 'web', fields: ['role'] }]);
    expect(plan.closing.size).toBe(0);
    expect(plan.sessionFieldsChanged).toEqual([]);
  });

  it('reports a session-fixed change only for a name in live, and names only those fields', () => {
    const plan = planReload(
      [p('web'), p('idle')],
      [p('web', { workdir: '/srv/app', role: 'viewer' }), p('idle', { workdir: '/srv/app' })],
      ['web'],
    );

    expect(plan.diff.changed.map((c) => c.name)).toEqual(['web', 'idle']);
    expect(plan.closing.size).toBe(0);
    expect(plan.sessionFieldsChanged).toEqual([{ name: 'web', fields: ['workdir'] }]);
  });

  it('does not report a session-fixed change for a live name it closes', () => {
    const plan = planReload([p('web')], [p('web', { workdir: '/srv/app', host: 'x.test' })], ['web']);

    expect([...plan.closing]).toEqual([['web', 'connection-field']]);
    expect(plan.sessionFieldsChanged).toEqual([]);
  });

  it('closes what runs through a closing bastion', () => {
    const inner = p('inner', { via: 'bastion' });
    const plan = planReload([p('bastion'), inner], [p('bastion', { host: 'moved.test' }), inner], []);

    expect([...plan.closing]).toEqual([
      ['bastion', 'connection-field'],
      ['inner', 'bastion-closed'],
    ]);
  });

  it('follows via transitively: c -> b -> a', () => {
    const b = p('b', { via: 'a' });
    const c = p('c', { via: 'b' });
    const plan = planReload([p('a'), b, c, p('other')], [p('a', { port: 2200 }), b, c, p('other')], []);

    expect([...plan.closing]).toEqual([
      ['a', 'connection-field'],
      ['b', 'bastion-closed'],
      ['c', 'bastion-closed'],
    ]);
  });

  it('closes a profile whose new via names a closing bastion', () => {
    // Added by this reload, so only the new config's via links it to the bastion.
    const plan = planReload(
      [p('bastion')],
      [p('bastion', { user: 'root' }), p('fresh', { via: 'bastion' })],
      [],
    );

    expect(plan.diff.added).toEqual(['fresh']);
    expect([...plan.closing]).toEqual([
      ['bastion', 'connection-field'],
      ['fresh', 'bastion-closed'],
    ]);
  });

  it('a dependent re-pointed away from a closing bastion closes for its own via change', () => {
    // An old-only hop can never change the result: a profile whose via changed or was
    // removed is already closing (via is a connection field; names are unique).
    // `inner` closes for its via change; `leaf` through leaf -> inner, in both configs.
    const leaf = p('leaf', { via: 'inner' });
    const plan = planReload(
      [p('bastion'), p('elsewhere'), p('inner', { via: 'bastion' }), leaf],
      [p('bastion', { host: 'moved.test' }), p('elsewhere'), p('inner', { via: 'elsewhere' }), leaf],
      ['inner', 'leaf'],
    );

    expect([...plan.closing]).toEqual([
      ['bastion', 'connection-field'],
      ['inner', 'connection-field'],
      ['leaf', 'bastion-closed'],
    ]);
  });

  it('terminates on a cycle in via', () => {
    const plan = planReload(
      [p('a', { via: 'b' }), p('b', { via: 'a' })],
      [p('a', { via: 'b', host: 'moved.test' }), p('b', { via: 'a' })],
      ['a', 'b'],
    );

    expect([...plan.closing]).toEqual([
      ['a', 'connection-field'],
      ['b', 'bastion-closed'],
    ]);
  });

  it('accepts a one-shot iterator for live, as the registry passes its map keys', () => {
    const live = new Map([['web', 1]]).keys();
    const plan = planReload([p('web')], [p('web', { workdir: '/w' })], live);

    expect(plan.sessionFieldsChanged).toEqual([{ name: 'web', fields: ['workdir'] }]);
  });
});
