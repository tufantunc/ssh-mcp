import type { AppConfig } from '../types.js';

/** Where the live config came from. */
export type ConfigSource = 'file' | 'unconfigured' | 'flags';

/** A loaded config, with what the reloader needs to know about where it came from. */
export interface LoadedConfig {
  config: AppConfig;
  source: ConfigSource;
  /** The file that was read, or the default path for `unconfigured` and `flags`. */
  path: string;
  /** Of the bytes that were parsed; null when no file was (`unconfigured`, `flags`). */
  sha256: string | null;
  /** When the config was loaded, as an ISO timestamp. */
  loadedAt: string;
}
