import { readFile, stat } from 'fs/promises';
import { homedir, platform } from 'os';
import { join, dirname } from 'path';
import { parse as parseTOML } from 'smol-toml';
import { configSchema, type RawConfig } from './schema.js';
import type { AppConfig, Profile, Defaults } from '../types.js';

export function getConfigPath(customPath?: string): string {
  if (customPath) return customPath;

  const home = homedir();
  const p = platform();

  if (p === 'darwin') {
    return join(home, 'Library', 'Application Support', 'ssh-mcp', 'config.toml');
  }
  if (p === 'win32') {
    return join(process.env.APPDATA || join(home, 'AppData', 'Roaming'), 'ssh-mcp', 'config.toml');
  }
  const xdgConfig = process.env.XDG_CONFIG_HOME || join(home, '.config');
  return join(xdgConfig, 'ssh-mcp', 'config.toml');
}

export async function checkPermissions(filePath: string): Promise<void> {
  try {
    const fileStat = await stat(filePath);
    const mode = fileStat.mode & 0o777;
    if (mode & 0o077) {
      throw new Error(
        `Config file ${filePath} is group/world accessible (mode ${mode.toString(8)}). Required: 0600. Run: chmod 600 ${filePath}`,
      );
    }
    const dirMode = (await stat(dirname(filePath))).mode & 0o777;
    if (dirMode & 0o077) {
      throw new Error(
        `Config directory is group/world accessible (mode ${dirMode.toString(8)}). Required: 0700.`,
      );
    }
  } catch (err: any) {
    if (err.code === 'ENOENT') return;
    throw err;
  }
}

export async function loadConfig(customPath?: string): Promise<AppConfig> {
  const configPath = getConfigPath(customPath);

  let raw: string;
  try {
    raw = await readFile(configPath, 'utf8');
  } catch (err: any) {
    if (err.code === 'ENOENT' && !customPath) {
      throw new Error(
        `No config file found at ${configPath}. Create one or use --config <path>. See documentation for the TOML schema.`,
      );
    }
    throw err;
  }

  await checkPermissions(configPath);

  let parsed: unknown;
  try {
    parsed = parseTOML(raw);
  } catch (err: any) {
    throw new Error(`Failed to parse TOML config at ${configPath}: ${err.message}`);
  }

  const result = configSchema.safeParse(parsed);
  if (!result.success) {
    // A root-level issue has an empty path, which used to render as a bare
    // colon. Unreachable while the root schema accepted anything; an unknown
    // top-level section reaches it now.
    const issues = result.error.issues
      .map((i) => `  ${i.path.length ? i.path.join('.') : '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(`Config validation error:\n${issues}`);
  }

  return normalizeConfig(result.data);
}

/**
 * `0` means unlimited, the convention `commandQuotaPerDay` and
 * `approvalGrantTtlMs` already use in this config file.
 *
 * It has to be *mapped* rather than merely permitted. `sanitizeCommand` tests
 * `cleaned.length > maxChars`, so a literal `0` arriving there rejects every
 * non-empty command with "Command is too long (max 0 characters)" — a worse
 * failure than the one this spelling exists to fix.
 *
 * MAX_SAFE_INTEGER is the value `parseMaxChars` produces for `--maxChars=none`,
 * so the flag and the config file hand the rest of the code an identical
 * Profile rather than two spellings of uncapped (#123).
 */
function uncapZero(maxChars: number): number {
  return maxChars === 0 ? Number.MAX_SAFE_INTEGER : maxChars;
}

/**
 * Resolve every profile against [defaults]. Each of these keys is documented as
 * a default that profiles inherit, so all of them must cascade — a key that is
 * accepted by the schema but never applied silently ignores the operator's
 * configuration (an `approvalMode` that never takes effect is a security
 * downgrade, not just a papercut).
 */
function normalizeConfig(raw: RawConfig): AppConfig {
  const defaults: Defaults = {
    ...raw.defaults,
  };

  const profiles: Profile[] = raw.profiles.map((p) => ({
    ...p,
    timeout: p.timeout ?? defaults.commandTimeoutMs,
    maxChars: uncapZero(p.maxChars ?? defaults.commandMaxChars),
    maxOutputBytes: p.maxOutputBytes ?? defaults.commandMaxOutputBytes,
    approvalPolicy: p.approvalPolicy ?? defaults.approvalMode,
    sessionMaxPerConnection: p.sessionMaxPerConnection ?? defaults.sessionMaxPerConnection,
    sessionIdleTimeoutMs: p.sessionIdleTimeoutMs ?? defaults.sessionIdleTimeoutMs,
    sessionBackgroundMaxMs: p.sessionBackgroundMaxMs ?? defaults.sessionBackgroundMaxMs,
    commandQuotaPerDay: p.commandQuotaPerDay ?? defaults.commandQuotaPerDay,
  }));

  // Passed through untouched. mergePolicyRules() owns the layering over
  // DEFAULT_RULES, so the loader has no policy semantics of its own to get
  // wrong.
  return { defaults, profiles, policy: raw.policy };
}

export function getProfile(config: AppConfig, name?: string): Profile {
  const targetName = name || config.defaults.defaultProfile;
  if (!targetName) {
    // Falling back to profiles[0] meant that with several hosts configured and
    // no default chosen, a command with no profile argument ran against
    // whichever host happened to be listed first — silently, and typically the
    // one written down first, which tends to be production. One profile is
    // unambiguous; more than one is a question the caller has to answer.
    if (config.profiles.length > 1) {
      const names = config.profiles.map((p) => p.name).join(', ');
      throw new Error(
        `No profile selected and no default configured, but ${config.profiles.length} profiles exist: ${names}. ` +
        `Pass a "profile" argument, or set defaults.defaultProfile in the config.`,
      );
    }
    return config.profiles[0];
  }
  const profile = config.profiles.find((p) => p.name === targetName);
  if (!profile) throw new Error(`Profile "${targetName}" not found`);
  return profile;
}
