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
    const issues = result.error.issues
      .map((i) => `  ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Config validation error:\n${issues}`);
  }

  return normalizeConfig(result.data);
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
    maxChars: p.maxChars ?? defaults.commandMaxChars,
    maxOutputBytes: p.maxOutputBytes ?? defaults.commandMaxOutputBytes,
    approvalPolicy: p.approvalPolicy ?? defaults.approvalMode,
    sessionMaxPerConnection: p.sessionMaxPerConnection ?? defaults.sessionMaxPerConnection,
    sessionIdleTimeoutMs: p.sessionIdleTimeoutMs ?? defaults.sessionIdleTimeoutMs,
    sessionBackgroundMaxMs: p.sessionBackgroundMaxMs ?? defaults.sessionBackgroundMaxMs,
    commandQuotaPerDay: p.commandQuotaPerDay ?? defaults.commandQuotaPerDay,
  }));

  return { defaults, profiles };
}

export function getProfile(config: AppConfig, name?: string): Profile {
  const targetName = name || config.defaults.defaultProfile;
  if (!targetName) {
    return config.profiles[0];
  }
  const profile = config.profiles.find((p) => p.name === targetName);
  if (!profile) throw new Error(`Profile "${targetName}" not found`);
  return profile;
}
