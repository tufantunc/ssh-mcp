/**
 * Precedence resolver for ssh-mcp-kerberos boot-time configuration.
 *
 * Order (high -> low):
 *   1. CLI flags (legacy single-host flags, OR repeated --ssh=<JSON>)
 *   2. --config=<path> TOML
 *   3. SSH_MCP_CONFIG env -> TOML
 *   4. $XDG_CONFIG_HOME/ssh-mcp/config.toml or ~/.ssh-mcp/config.toml
 *
 * The resolver is pure: it accepts pre-parsed CLI inputs and an env map,
 * walks the four candidate sources in order, and returns a single
 * `ResolvedConfig`. The src/index.ts boot path stays in charge of parsing
 * argv (the `parseArgv` / `collectSshJsonArgs` helpers already exist).
 *
 * "CLI wins" semantics:
 *   - Any CLI source provided (legacy single-host OR --ssh=<JSON>) suppresses
 *     the entire TOML sources list. Mixing modes is rejected upstream by
 *     `validateConfig` in src/index.ts. This keeps existing CLI tests untouched.
 *   - Top-level TOML sections (server/webui/approval) survive even when CLI
 *     sources are present, so a future user can use legacy flags AND a TOML
 *     just for [webui]. (Source-level overrides land in later tasks.)
 */

import { discoverConfigPath, loadTomlFile } from './toml-loader.js';
import type { ResolvedConfig } from './types.js';
import type { ServerConfig } from '../transports/types.js';

export interface ResolverInputs {
  /** Parsed CLI ServerConfig entries (from --ssh=<JSON> or legacy single-host). */
  cliSources: ServerConfig[];
  /** Explicit --config=<path>, if the user supplied one. */
  cliConfigPath?: string;
  /** Override env for tests; defaults to process.env. */
  env?: NodeJS.ProcessEnv;
}

export function resolveConfig(inputs: ResolverInputs): ResolvedConfig {
  const env = inputs.env ?? process.env;

  // --- locate a TOML, if any ---------------------------------------------
  let tomlPath: string | undefined = inputs.cliConfigPath;
  if (!tomlPath && env.SSH_MCP_CONFIG) tomlPath = env.SSH_MCP_CONFIG;
  if (!tomlPath) tomlPath = discoverConfigPath(env);

  // When CLI sources are present they win and suppress the TOML source list
  // (see "CLI wins" semantics above). In that case a TOML that exists only to
  // supply top-level sections (e.g. just [webui]) is legitimate and must not be
  // rejected for having zero [[sources]]. Tolerate empty sources accordingly.
  const hasCliSources = inputs.cliSources.length > 0;

  const fromToml: ResolvedConfig | undefined = tomlPath
    ? loadTomlFile(tomlPath, { env, allowEmptySources: hasCliSources })
    : undefined;

  // --- assemble final ResolvedConfig -------------------------------------

  // Per spec: CLI sources win and SUPPRESS the TOML source list (avoid
  // confusing union semantics + double-registration). Top-level TOML
  // sections still apply so e.g. [webui] from disk is respected.
  const sources: ServerConfig[] = hasCliSources
    ? inputs.cliSources
    : (fromToml?.sources ?? []);

  // defaultName: when CLI is in charge, first registered wins (matches
  // existing TransportRegistry behavior).
  let defaultName: string | undefined;
  if (hasCliSources) {
    defaultName = inputs.cliSources[0]?.name;
  } else {
    defaultName = fromToml?.defaultName ?? fromToml?.sources?.[0]?.name;
  }

  return {
    sources,
    defaultName,
    perSourceApproval: hasCliSources ? {} : (fromToml?.perSourceApproval ?? {}),
    server: fromToml?.server,
    webui: fromToml?.webui,
    approval: fromToml?.approval,
    configPath: tomlPath,
  };
}
