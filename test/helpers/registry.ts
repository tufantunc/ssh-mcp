import type { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { SSHConnection } from '../../src/ssh/connection.js';
import { defaultsFromArgv } from '../../src/cli.js';
import type { AppConfig, Defaults, Profile } from '../../src/types.js';

/** A config of these profiles under the defaults a bare argv gives, some overridden. */
export const configWithDefaults = (defaults: Partial<Defaults>, ...profiles: Profile[]): AppConfig => ({
  defaults: { ...defaultsFromArgv({}), ...defaults },
  profiles,
});

/** A config of these profiles under the defaults a bare argv gives. */
export const configOf = (...profiles: Profile[]): AppConfig => configWithDefaults({}, ...profiles);

/**
 * Put `conn` in the registry's private connection map under `name`, as if getOrCreate
 * had stored it. Takes any object, so a stand-in with only what the code under test
 * touches can be stored too.
 */
export function store(registry: ConnectionRegistry, name: string, conn: object): void {
  (registry as any).connections.set(name, conn);
}

/**
 * A real SSHConnection, never connected, planted in the registry's map: the registry
 * hands it out and swaps or retires it on reload exactly as it would a live one.
 */
export function plant(registry: ConnectionRegistry, profile: Profile): SSHConnection {
  const conn = new SSHConnection(profile, { password: 'x' } as never, new Map(), 'insecure');
  store(registry, profile.name, conn);
  return conn;
}
