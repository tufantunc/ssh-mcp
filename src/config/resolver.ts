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
  /** Explicit CLI `--webui` override; undefined delegates to TOML enabled. */
  webuiEnabled?: boolean;
}

export function resolveConfig(inputs: ResolverInputs): ResolvedConfig {
  const env = inputs.env ?? process.env;

  // --- locate a TOML, if any ---------------------------------------------
  // Precedence: explicit --config wins outright. Otherwise defer to
  // discoverConfigPath(env), which probes SSH_MCP_CONFIG first and then the
  // XDG/home candidates, returning the first that actually EXISTS. Reading
  // env.SSH_MCP_CONFIG directly here would diverge from that discovery
  // contract: a set-but-missing SSH_MCP_CONFIG falls through to XDG/home,
  // while an inaccessible SSH_MCP_CONFIG fails closed in discovery.
  const tomlPath: string | undefined =
    inputs.cliConfigPath ?? discoverConfigPath(env);

  // When CLI sources are present they win and suppress the TOML source list
  // (see "CLI wins" semantics above). In that case a TOML that exists only to
  // supply top-level sections (e.g. just [webui]) is legitimate and must not be
  // rejected for having zero [[sources]]. Beyond tolerating empty sources, we
  // must also SKIP parsing/validating any [[sources]] that ARE present but
  // suppressed: a suppressed source with an unset `password = "env:PROD_PASS"`
  // or another source-only error would otherwise abort startup even though only
  // the top-level sections survive. ignoreSources handles both.
  const hasCliSources = inputs.cliSources.length > 0;
  const hasExplicitCliConfig = inputs.cliConfigPath !== undefined;

  const fromToml: ResolvedConfig | undefined = tomlPath
    ? loadTomlFile(tomlPath, {
        env,
        webuiEnabled: inputs.webuiEnabled,
        allowEmptySources: hasCliSources,
        ignoreSources: hasCliSources,
      })
    : undefined;

  // --- assemble final ResolvedConfig -------------------------------------

  // Per spec: CLI sources win and SUPPRESS the TOML source list (avoid
  // confusing union semantics + double-registration). Top-level TOML
  // sections still apply so e.g. [webui] from disk is respected.
  const sources: ServerConfig[] = hasCliSources
    ? inputs.cliSources
    : (fromToml?.sources ?? []);

  // defaultName: when CLI is in charge, first registered wins (matches
  // existing TransportRegistry behavior). defaultExplicit tracks whether that
  // default was a deliberate user choice (TOML `default = true`) versus a mere
  // positional fallback — the boot path only calls registry.setDefault() for an
  // explicit default, so a multi-source config without one keeps the omit-name
  // guard armed instead of silently routing to the first host.
  let defaultName: string | undefined;
  let defaultExplicit: boolean;
  if (hasCliSources) {
    // A CLI invocation never carries an explicit-default marker; the first
    // --ssh source is a positional fallback only.
    defaultName = inputs.cliSources[0]?.name;
    defaultExplicit = false;
  } else if (fromToml?.defaultName !== undefined) {
    // The TOML loader sets defaultName ONLY from an explicit `default = true`.
    defaultName = fromToml.defaultName;
    defaultExplicit = true;
  } else {
    // No explicit default anywhere: fall back to the first source positionally
    // for routing, but mark it non-explicit so the guard still fires.
    defaultName = fromToml?.sources?.[0]?.name;
    defaultExplicit = false;
  }

  return {
    sources,
    defaultName,
    defaultExplicit,
    perSourceApproval: hasCliSources ? {} : (fromToml?.perSourceApproval ?? {}),
    // An auto-discovered TOML must not weaken the connectionName guard for
    // explicit CLI sources. In particular, a stale default config containing
    // require_connection=false must not make a multi-`--ssh` invocation silently
    // route omitted connectionName calls to its first CLI host. The opt-out is
    // honored with CLI sources only when the user explicitly supplied --config.
    requireConnection: hasCliSources && !hasExplicitCliConfig
      ? undefined
      : fromToml?.requireConnection,
    server: fromToml?.server,
    webui: fromToml?.webui,
    approval: fromToml?.approval,
    configPath: tomlPath,
  };
}
