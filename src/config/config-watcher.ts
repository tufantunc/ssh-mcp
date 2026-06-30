/**
 * Debounced TOML config-file watcher for ssh-mcp-kerberos.
 *
 * Ported from dbhub's `src/utils/config-watcher.ts` pattern (debounce +
 * re-entrancy guard + `unref()` + best-effort error handling), adapted to
 * ssh-mcp's architecture: the WHAT-of-reload (parse / validate-before-swap /
 * rollback / SSE) lives in `ConfigReloader` (`./reloader.ts`); this module owns
 * only the WHEN — turning a noisy stream of `fs.watch` change events into a
 * single coalesced `onChange()` call.
 *
 * Why split it: editors emit several `change` events per save (truncate +
 * write + rename-into-place), so a naive watcher would reload 3-5x per save.
 * The 500ms debounce collapses a burst into one reload; the re-entrancy guard
 * coalesces events that land *during* an in-flight reload into exactly one
 * trailing reload. Both behaviours are unit-tested without any SSH host.
 *
 * STDIO caveat (inherited from dbhub, see README): the MCP tool list
 * (`exec`/`sudo-exec`/`list-servers`) is registered once at startup. Hot reload
 * refreshes connections, per-source descriptions, and approval policy — it does
 * NOT add or remove tools, so a STDIO client never needs to reconnect. (Tool
 * set is static here, so this is a non-issue in practice — documented for
 * parity with dbhub, where the tool list IS config-derived.)
 */

import * as fs from 'fs';
import * as path from 'path';

/** Default debounce window. Matches dbhub. Editors fire multiple change events. */
export const DEFAULT_DEBOUNCE_MS = 500;

export interface ConfigWatcherOptions {
  /** Absolute path to the TOML config file to watch. */
  configPath: string;
  /**
   * Called (at most once per debounce window, never re-entrantly) when the
   * file changes. Any thrown error / rejected promise is swallowed and logged
   * so a bad reload never crashes the watcher.
   */
  onChange: () => void | Promise<void>;
  /** Debounce window in ms. Defaults to {@link DEFAULT_DEBOUNCE_MS}. */
  debounceMs?: number;
  /** Optional log sink (defaults to console.error). Injected for tests. */
  log?: (msg: string) => void;
}

/**
 * Start watching `configPath`. Returns a cleanup function that stops the
 * watcher and cancels any pending debounce, or `null` when the path is empty
 * (CLI / `--ssh` mode with no TOML — nothing to watch, exactly like dbhub).
 */
export function startConfigWatcher(options: ConfigWatcherOptions): (() => void) | null {
  const { configPath, onChange } = options;
  if (!configPath) return null;

  const debounceMs = options.debounceMs ?? DEFAULT_DEBOUNCE_MS;
  const log = options.log ?? ((m: string) => console.error(m));

  let debounceTimer: NodeJS.Timeout | null = null;
  let isReloading = false;
  let reloadPending = false;
  // Set by cleanup(). Once closed, no further reload may be scheduled OR run —
  // this closes the race where a change arrives during an in-flight reload
  // (reloadPending = true), cleanup() runs, and the in-flight reload's `finally`
  // then re-schedules a reload that fires onChange() AFTER the watcher was
  // closed. Both runReload() and scheduleReload() bail when closed.
  let closed = false;

  const runReload = async () => {
    // Never run a reload after cleanup, even if a debounce timer had already
    // fired into the macrotask queue before close() cancelled it.
    if (closed) return;
    // Re-entrancy guard: if a reload is already running, remember that another
    // change arrived and re-schedule a single trailing reload in `finally`.
    if (isReloading) {
      reloadPending = true;
      return;
    }
    isReloading = true;
    reloadPending = false;
    try {
      await onChange();
    } catch (err: any) {
      // A failing reload must never take down the watcher.
      log(`Config watcher: reload callback threw, keeping watcher alive: ${err?.message || err}`);
    } finally {
      isReloading = false;
      if (reloadPending) {
        reloadPending = false;
        scheduleReload();
      }
    }
  };

  const scheduleReload = () => {
    // Don't arm a new debounce timer once the watcher has been cleaned up.
    if (closed) return;
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      void runReload();
    }, debounceMs);
    // Never let the debounce timer keep the process alive.
    if (typeof (debounceTimer as any).unref === 'function') (debounceTimer as any).unref();
  };

  // Watch the PARENT DIRECTORY and filter events for the config file's
  // basename, rather than watching the file inode directly. Editors and tools
  // (and many deploy scripts) save via atomic rename: they write a temp file
  // and rename it over config.toml, which REPLACES the inode. A watcher bound
  // to the old inode (`fs.watch(configPath)`) receives the first rename and is
  // then attached to a unlinked inode, so subsequent edits to the new file are
  // never seen — the README "watches that file and hot-reloads on change"
  // contract silently breaks after one save. A directory watcher survives the
  // rename because the directory inode is stable, and still sees plain in-place
  // writes (filename === basename). This mirrors dbhub's chokidar behaviour
  // using only Node's built-in fs.watch.
  const dir = path.dirname(configPath);
  const base = path.basename(configPath);

  let watcher: fs.FSWatcher;
  try {
    watcher = fs.watch(dir, (eventType, filename) => {
      // Most platforms emit 'change'; some emit 'rename' on save-via-replace
      // or temp-file churn. Treat both as "the watched file might have changed"
      // and let the parse step in onChange be the real validator. fs.watch on a
      // directory reports the affected entry in `filename`; when the platform
      // omits it (rare) we conservatively schedule a reload rather than miss an
      // edit. Events for OTHER files in the directory are ignored.
      if (eventType !== 'change' && eventType !== 'rename') return;
      if (filename != null && path.basename(filename.toString()) !== base) return;
      scheduleReload();
    });
  } catch (err: any) {
    log(`Config watcher: failed to watch ${configPath}: ${err?.message || err}`);
    return null;
  }

  // Don't block process exit on the watcher.
  watcher.unref?.();
  watcher.on('error', (err: Error) => {
    log(`Config watcher: file watch error on ${configPath}: ${err?.message || err}`);
  });

  log(`Watching ${configPath} for changes (hot reload enabled)`);

  return () => {
    // Mark closed FIRST so any reload still in-flight won't re-schedule from its
    // `finally`, and any debounce timer that already fired becomes a no-op.
    closed = true;
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    try { watcher.close(); } catch { /* best effort */ }
  };
}
