import { readFile, stat } from 'fs/promises';
import { homedir, platform } from 'os';
import { join, dirname } from 'path';
import { parse as parseTOML } from 'smol-toml';
import { configSchema, type RawConfig } from './schema.js';
import { OperatorError, ConfigNotFoundError, UnconfiguredError } from '../errors.js';
import { assertPrivateOnWindows, type AclOptions } from './windows-acl.js';
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

/**
 * Check that nobody but the owner can reach a config file, because it holds the hosts,
 * roles and policy rules that decide what this server will run.
 *
 * The two platforms answer differently on purpose. POSIX refuses: "only the owner" is
 * unambiguous there and `chmod` is a one-line fix. Windows refuses a config another
 * account can *change* and reports one it can only *read*, because read exposure is where
 * the platform is genuinely muddier — see `waived` in windows-acl.ts.
 *
 * Mode bits are POSIX's answer and are meaningless on Windows, which is the whole of #138:
 * Node synthesises `0o666` for every readable file there, so `& 0o077` was non-zero
 * unconditionally and every Windows config that has ever existed was rejected. The
 * `chmod 600` it prescribed could not lift that rejection — measured on Windows 11,
 * `chmod(path, 0o600)` leaves the mode at `0o666`, because `fs.chmod` there only toggles
 * the read-only bit. Following the instruction exactly returned the operator to where
 * they started.
 */
export async function checkPermissions(filePath: string, opts: AclOptions = {}): Promise<void> {
  return platform() === 'win32'
    ? assertPrivateOnWindows(filePath, opts)
    : checkPosixMode(filePath);
}

/**
 * Split out so its own refusals do not pass back through the `catch` that
 * tolerates ENOENT. They survived it only because an OperatorError carries no
 * `.code`, which was a coincidence rather than a design.
 */
async function checkPosixMode(filePath: string): Promise<void> {
  const dir = dirname(filePath);
  const modeOf = async (path: string): Promise<number | null> => {
    try {
      return (await stat(path)).mode & 0o777;
    } catch (err: any) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  };

  // The file is tested before the directory is even stat'd, which is the order
  // main used: batching both stats first meant a 0644 file whose directory
  // vanished in between took the ENOENT path and was accepted.
  const fileMode = await modeOf(filePath);
  if (fileMode === null) return;

  if (fileMode & 0o077) {
    throw new OperatorError(
      `Config file ${filePath} is group/world accessible (mode ${fileMode.toString(8)}). ` +
      `Required: 0600. Run: chmod 600 ${filePath}`,
    );
  }
  const dirMode = await modeOf(dir);
  if (dirMode !== null && dirMode & 0o077) {
    throw new OperatorError(
      `Config directory ${dir} is group/world accessible (mode ${dirMode.toString(8)}). ` +
      `Required: 0700. Run: chmod 700 ${dir}\n` +
      // The published Docker image created this directory 0755, so a container
      // with a config bind-mounted at the default path met this on every start
      // with no way to chmod a path baked into the image.
      'If the directory is not yours to change — a container image, or a mount point — ' +
      'bind-mount a 0700 directory over it, or point --config at one you control.',
    );
  }
}

export async function loadConfig(customPath?: string, opts: AclOptions = {}): Promise<AppConfig> {
  const configPath = getConfigPath(customPath);

  let raw: string;
  try {
    raw = await readFile(configPath, 'utf8');
  } catch (err: any) {
    // Also for an explicit --config that points nowhere. That used to escape
    // as the raw system error ("ENOENT: no such file or directory, open ..."),
    // which says the same thing in the vocabulary of a syscall.
    if (err.code === 'ENOENT') throw new ConfigNotFoundError(configPath);
    // Everything else here is still the operator's file — a directory passed as
    // --config, a mode or ACL that denies reading, a mount that went away. Those
    // escaped raw too, so `reportFatal` printed them with a stack through our
    // own frames: the presentation this change exists to remove.
    // `.code` is carried through for the same reason ConfigNotFoundError keeps it: a
    // wrapper script distinguishing "unreadable, remount and retry" from "absent, run the
    // installer" was matching on it, and preserving it on one branch while dropping it on
    // the adjacent one is a half-applied rule.
    throw Object.assign(
      new OperatorError(`Config file ${configPath} could not be read: ${err.message}`),
      { code: err.code, cause: err },
    );
  }

  await checkPermissions(configPath, opts);

  let parsed: unknown;
  try {
    parsed = parseTOML(raw);
  } catch (err: any) {
    throw new OperatorError(`Failed to parse TOML config at ${configPath}: ${err.message}`);
  }

  const result = configSchema.safeParse(parsed);
  if (!result.success) {
    // A root-level issue has an empty path, which used to render as a bare
    // colon. Unreachable while the root schema accepted anything; an unknown
    // top-level section reaches it now.
    const issues = result.error.issues
      .map((i) => `  ${i.path.length ? i.path.join('.') : '(root)'}: ${i.message}`)
      .join('\n');
    throw new OperatorError(`Config validation error:\n${issues}`);
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
  // commandMaxChars is mapped here as well as on the profile below, so no `0`
  // survives anywhere in AppConfig. Leaving the raw value on `defaults` left one
  // object carrying two encodings of "unlimited" — `profile.maxChars` as
  // MAX_SAFE_INTEGER, `defaults.commandMaxChars` as 0 — with nothing in the
  // types to tell them apart. buildAppConfig's quick-start path already copies it
  // straight across (`maxChars: defaults.commandMaxChars`), and was correct only
  // because that path's value comes from parseMaxChars, which never returns 0.
  // Correct by
  // coincidence of another surface is not a property to leave standing when the
  // wrong encoding rejects every non-empty command.
  const defaults: Defaults = {
    ...raw.defaults,
    commandMaxChars: uncapZero(raw.defaults.commandMaxChars),
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
      throw new OperatorError(
        `No profile selected and no default configured, but ${config.profiles.length} profiles exist: ${names}. ` +
        `Pass a "profile" argument, or set defaults.defaultProfile in the config.`,
      );
    }
    // Defensive: a lookup helper must not hand back `undefined` typed as `Profile`, which
    // is what `profiles[0]` on an empty list used to do — a TypeError somewhere downstream
    // rather than an explanation here. This is the invariant, not the product rule. The
    // decision that an unconfigured server refuses work lives in `ConnectionRegistry`,
    // which guards this branch AND the named-profile one below; reaching this line means
    // a caller went around the registry.
    if (config.profiles.length === 0) throw new UnconfiguredError(getConfigPath());
    return config.profiles[0];
  }
  const profile = config.profiles.find((p) => p.name === targetName);
  if (!profile) throw new OperatorError(`Profile "${targetName}" not found`);
  return profile;
}
