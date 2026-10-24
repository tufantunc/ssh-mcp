import type { ConnectionRegistry } from './connection-registry.js';

/**
 * One pass of the idle reaper.
 *
 * Walks the stored connections directly rather than resolving each through its profile name:
 * a config reload can remove a profile while its connection is still open, and a profile
 * lookup for it throws. Nothing here depends on the profile still existing.
 */
export async function reapOnce(registry: ConnectionRegistry): Promise<void> {
  // Session reaping is awaited before connection reaping, and that order is load-bearing:
  // closing a background session now signals its command, and `reapIdleConnections` gates
  // on `sessionCount`, which drops to zero as soon as a session is closed. Fired without
  // awaiting, the connection was torn down microseconds after the first signal and the
  // TERM and KILL rungs were discarded — so a command that ignores INT survived its own
  // reaping.
  await Promise.all(
    registry.liveConnections().map((conn) => conn.reapExpiredSessions().catch(() => {})),
  );
  registry.reapIdleConnections();
}
