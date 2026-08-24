/**
 * The command line: argv into an AppConfig.
 *
 * Split out of index.ts, which runs `main()` at import time unless
 * `SSH_MCP_DISABLE_MAIN=1` is set *and* `SSH_MCP_TEST` is not `1` — the gate is a
 * disjunction, so the test variable overrides the disable one. That made every test of a
 * pure argv helper a test that could start connecting to real hosts on a machine with a
 * real config; one of them carried a six-line comment and a `vi.stubEnv` about exactly
 * that, both removed by this split. Nothing in this file has a side effect at import
 * time, so importing it is safe.
 *
 * Not *everything* argv-shaped lives here: index.ts still reads the transport, OTEL and
 * OPA flags at the wiring site, where they are used. What moved is the part that had to
 * escape the boot gate to be testable.
 */

import { loadConfig, getConfigPath } from './config/loader.js';
import { OperatorError, ConfigNotFoundError, UnconfiguredError } from './errors.js';
import type { AclFinding } from './config/windows-acl.js';
import { HOST_GROUPS } from './policy/engine.js';
import type { HostKeyMode } from './ssh/host-key.js';
import type { AppConfig, Profile, Defaults } from './types.js';

/**
 * Whether the operator asked for a quick start at all.
 *
 * Presence, not truthiness — the same #91 trap `flagEnabled` was written for. `parseArgv`
 * stores `null` for a flag written without `=` and drops bare words, so all three of
 * `--host example.com --user root` (space instead of `=`, the commonest slip), `--host`
 * alone, and `--host= --user=` (a wrapper interpolating unset env vars) produce falsy
 * values while the flags were plainly given. Testing truthiness sent every one of them
 * down the soft path: a server that starts and looks healthy, with the explanation only
 * on a stderr stream an MCP client typically swallows. Only "asked for nothing" softens;
 * a half-given or empty-valued quick start is a typo and still refuses.
 */
function nothingRequested(argv: Record<string, string | null>): boolean {
  return !('host' in argv) && !('user' in argv);
}

export function parseArgv(args: string[] = process.argv.slice(2)): Record<string, string | null> {
  const config: Record<string, string | null> = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq === -1) {
        config[arg.slice(2)] = null;
      } else {
        config[arg.slice(2, eq)] = arg.slice(eq + 1);
      }
    }
  }
  return config;
}

/**
 * Whether a boolean flag was passed at all.
 *
 * `parseArgv` stores `null` for a flag written without `=`, which is how every
 * documented boolean flag is written. Testing that value for truthiness makes
 * the flag a no-op: `--disableApproval`, `--auditEntropyScan` and
 * `--auditTamperEvident` all did nothing unless spelled `--flag=1`, which
 * nothing documents (#91). The two call sites that got it right already used
 * `!== undefined`; this gives the check a name so the next one cannot miss it.
 *
 * `--flag=false` and `--flag=0` turn it off, because a flag that cannot be
 * turned off once written into a wrapper script is its own annoyance.
 */
export function flagEnabled(argv: Record<string, string | null>, name: string): boolean {
  if (!(name in argv)) return false;
  const value = argv[name];
  if (value === null || value === '') return true;
  return !['false', '0', 'no', 'off'].includes(value.toLowerCase());
}

/**
 * v1 flags that v2 removed. Silently ignoring them means the user only finds
 * out at the first command, as an auth failure with no hint about the cause.
 */
const REMOVED_V1_FLAGS: Record<string, string> = {
  password: 'Use the SSH_MCP_PASSWORD env var (or a per-profile SSH_MCP_<PROFILE>_PASSWORD).',
  suPassword: 'Use the SSH_MCP_SUDO_PASSWORD env var.',
  sudoPassword: 'Use the SSH_MCP_SUDO_PASSWORD env var.',
  disableSudo: 'Sudo is now a separate tool; restrict it with a role/policy that disallows the "privileged" class.',
};

export function checkRemovedFlags(argv: Record<string, string | null>): void {
  const found = Object.keys(REMOVED_V1_FLAGS).filter((f) => f in argv);
  if (found.length === 0) return;
  throw new OperatorError(
    'These flags were removed in v2:\n' +
    found.map((f) => `  --${f}: ${REMOVED_V1_FLAGS[f]}`).join('\n') +
    '\nSee the "Migrating from v1" section of the README.',
  );
}

/**
 * v1 documented `--maxChars=none` (and 0/negative) as "no limit". Parsing it
 * with `parseInt(...) || 5000` silently turned that into a 5000-char cap.
 */
export function parseMaxChars(raw: string | null | undefined): number {
  if (typeof raw !== 'string' || raw === '') return 5_000;
  if (raw.toLowerCase() === 'none') return Number.MAX_SAFE_INTEGER;
  const parsed = parseInt(raw);
  if (isNaN(parsed)) return 5_000;
  return parsed <= 0 ? Number.MAX_SAFE_INTEGER : parsed;
}

/**
 * `strict` was previously unreachable: nothing but test code could select it,
 * yet host-key.ts pointed users at a `--acceptNewHostKey` flag that never
 * existed. `--insecureHostKey` is kept as an alias for the documented flag.
 */
export function resolveHostKeyMode(argv: Record<string, string | null>): HostKeyMode {
  if (flagEnabled(argv, 'insecureHostKey')) return 'insecure';
  const mode = argv.hostKeyMode;
  if (mode === null || mode === undefined) return 'tofu';
  if (mode === 'tofu' || mode === 'strict' || mode === 'insecure') return mode;
  throw new OperatorError(`Invalid --hostKeyMode=${mode}. Expected one of: tofu, strict, insecure.`);
}

/**
 * Which policy tier a CLI-configured host belongs to.
 *
 * Without this there was no way to say it from the command line at all. The
 * inline profile carries no group, so it fell to the strictest tier, where the
 * `admin` role has no `privileged` — meaning `sudo` could never run for anyone
 * who had not written a config file (#91).
 *
 * The default stays `prod`. Guessing an unknown host is production is the safe
 * direction; what was missing was a way to correct the guess.
 */
export function resolveHostGroup(argv: Record<string, string | null>): string {
  const group = argv.group;
  if (group === null || group === undefined) return 'prod';
  if ((HOST_GROUPS as readonly string[]).includes(group)) return group;
  // Falling through would silently apply the prod bindings to a typo, and the
  // operator would read the refusal as policy rather than as their own slip.
  throw new OperatorError(
    `Invalid --group=${group}. Expected one of: ${HOST_GROUPS.join(', ')}.`,
  );
}

/**
 * The defaults a quick-start profile inherits, from flags alone.
 *
 * Named because an unconfigured start needs them too — `approvalGrantTtlMs` is read while
 * wiring the tools, long before any profile exists, so the two paths have to agree.
 */
export function defaultsFromArgv(argv: Record<string, string | null>): Defaults {
  return {
    sessionMaxPerConnection: parseInt(argv.sessionMax as string) || 5,
    sessionIdleTimeoutMs: parseInt(argv.sessionTtl as string) || 600_000,
    sessionBackgroundMaxMs: 3_600_000,
    commandTimeoutMs: parseInt(argv.timeout as string) || 60_000,
    commandMaxChars: parseMaxChars(argv.maxChars),
    commandMaxOutputBytes: 1_048_576,
    connectionIdleReapMs: 900_000,
    commandQuotaPerDay: parseInt(argv.commandQuota as string) || 0,
    approvalGrantTtlMs: parseInt(argv.approvalGrantTtl as string) || 0,
    approvalMode: 'ask-destructive',
  };
}

export async function buildAppConfig(argv: Record<string, string | null>): Promise<AppConfig> {
  // The way past an ACL that could not be read, rather than an operator with no
  // exit. See assertPrivateOnWindows.
  // The sink is supplied here rather than left to the module's default, which is the
  // point of having one: "this security check did not run" is a decision about what the
  // operator must be told, and the loader is not the layer that owns that. Routing it to
  // the audit store as well needs an AuditRecord variant for a startup event — that type
  // is hash-chained and tamper-evident, so it is its own change, and it is queued.
  //
  // An earlier version also pushed every finding into a module-level array "so main() can
  // act on them". Nothing ever read it, and this split made the claim impossible — main()
  // is in another module and the array was not exported. Re-adding a collection point is
  // one line when there is a consumer to write it against.
  const aclOpts = {
    enforce: flagEnabled(argv, 'strictConfigAcl'),
    allowUnchecked: flagEnabled(argv, 'allowUncheckedConfigAcl'),
    onFinding: (f: AclFinding) => {
      console.error(`Warning: ${f.message}`);
    },
  };

  if (argv.config !== undefined) {
    // `parseArgv` stores null for a flag written without `=`, so a bare `--config` used to
    // be falsy here and fall into the default-path branch — which now refuses rather than
    // silently ignoring an unusable file, so the operator got a refusal naming a path they
    // never asked for.
    if (argv.config === null || argv.config === '') {
      throw new OperatorError('--config needs a path: --config=<path>');
    }
    return loadConfig(argv.config, aclOpts);
  }

  try {
    const fromFile = await loadConfig(undefined, aclOpts);
    // Before #138 every Windows config was rejected by the mode-bit check and
    // the rejection was swallowed, so an operator who also passed --host/--user
    // was silently running off the flags. Now that the file loads, it takes
    // precedence — a flip worth one line rather than a surprise about which host
    // a command reached.
    if (argv.host || argv.user) {
      console.error(
        `Note: ${getConfigPath()} was loaded, so --host/--user are ignored. ` +
        'Pass --config <path> to choose a different file.',
      );
    }
    return fromFile;
  } catch (err) {
    // Only "there is no file" means fall through. A file that exists and is
    // unusable — malformed TOML, a schema violation, a permission failure —
    // used to be swallowed here too and reported as a missing config, which is
    // how #138 stayed unfindable: the operator's file was in the right place,
    // and the real error was discarded before anyone could read it.
    //
    // Falling through would also be wrong on its own terms whenever
    // --host/--user happen to be present: the server would start, silently
    // ignoring every profile, policy and role binding the operator wrote.
    if (!(err instanceof ConfigNotFoundError)) throw err;
  }

  // Nothing configured, and nothing named on the command line either. Start anyway, with
  // no profiles: an MCP client or directory can then complete the handshake and read
  // `tools/list`, and every tool call is refused by `ConnectionRegistry` with the message
  // below — including `list-connections`, which resolves no profile and so had to be told.
  //
  // Measured before this: `initialize` and `tools/list` against our own image drew no
  // JSON-RPC response at all — the process exited on this check first — so every directory
  // and every "add this server" flow saw a crash. Tool definitions are static metadata and
  // the config decides what they may *reach*, so coupling the two bought no safety.
  //
  // A half-given quick start is not this case: `--host` without `--user` is a typo, and an
  // explicit `--config` that points nowhere already threw above. Only "configured nothing"
  // softens — see `nothingRequested`, which tests for the flags being absent rather than
  // falsy so that a valueless or space-separated one stays a typo.
  if (nothingRequested(argv)) {
    console.error(`Warning: starting unconfigured — every tool call will be refused.\n${new UnconfiguredError(getConfigPath()).message}`);
    return { defaults: defaultsFromArgv(argv), profiles: [] };
  }

  if (!argv.host || !argv.user) {
    throw new UnconfiguredError(getConfigPath());
  }

  const defaults = defaultsFromArgv(argv);

  const profile: Profile = {
    name: 'default',
    host: argv.host,
    port: parseInt(argv.port as string) || 22,
    user: argv.user,
    auth: argv.key ? 'key' : 'password',
    keyRef: argv.key || undefined,
    workdir: argv.workdir || undefined,
    tty: false,
    timeout: defaults.commandTimeoutMs,
    maxChars: defaults.commandMaxChars,
    maxOutputBytes: defaults.commandMaxOutputBytes,
    role: 'admin',
    group: resolveHostGroup(argv),
    readOnly: false,
    approvalPolicy: flagEnabled(argv, 'disableApproval') ? 'auto' : defaults.approvalMode,
    cert: false,
    sessionMaxPerConnection: defaults.sessionMaxPerConnection,
    sessionIdleTimeoutMs: defaults.sessionIdleTimeoutMs,
    sessionBackgroundMaxMs: defaults.sessionBackgroundMaxMs,
    commandQuotaPerDay: defaults.commandQuotaPerDay,
  };

  return { defaults, profiles: [profile] };
}
