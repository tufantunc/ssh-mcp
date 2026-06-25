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

  const runReload = async () => {
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
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      void runReload();
    }, debounceMs);
    // Never let the debounce timer keep the process alive.
    if (typeof (debounceTimer as any).unref === 'function') (debounceTimer as any).unref();
  };

  let watcher: fs.FSWatcher;
  try {
    watcher = fs.watch(configPath, (eventType) => {
      // Most platforms emit 'change'; some emit 'rename' on save-via-replace.
      // Treat both as "the file might have changed" and let the parse step in
      // onChange be the real validator.
      if (eventType === 'change' || eventType === 'rename') {
        scheduleReload();
      }
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
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    try { watcher.close(); } catch { /* best effort */ }
  };
}
