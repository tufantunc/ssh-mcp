import type { CommandClass, ParsedCommand } from '../types.js';

/**
 * Anything through which the shell can start a second command.
 *
 * This gate decides whether an allowlisted binary counts as read-only, and the
 * allowlist only vouches for the binary — never for what a shell might run
 * beside it. It used to test /[>;|]/, which let `ls $(touch /tmp/x)` through as
 * read-only: `ls` is allowlisted, no listed metacharacter appears, and the
 * remote shell expands the substitution and runs the inner command anyway
 * (GHSA-r8hm-vpm8-cfh6).
 *
 * Listing every dangerous construct is a losing game — `$()`, backticks,
 * `<(...)`, `${x:=...}`, `&&`, a bare newline — so this refuses every character
 * with syntactic meaning to the shell instead, and `$` wholesale rather than
 * just `$(`. The cost is that `echo $HOME` is no longer classified read-only.
 * That is the right trade for the tool whose entire promise is that it cannot
 * write: run-command still accepts it under policy.
 */
const SHELL_CONTROL_CHARS = /[;&|<>`$(){}\n\r]/;

const READ_ONLY_ALLOWLIST = new Set([
  'ls', 'cat', 'grep', 'find', 'stat', 'df', 'du', 'head', 'tail', 'wc',
  'ps', 'uname', 'uptime', 'hostname', 'id', 'who', 'whoami', 'date',
  'printenv', 'pwd', 'echo', 'printf', 'test', 'true', 'false',
  'which', 'whereis', 'file', 'readlink', 'realpath', 'basename', 'dirname',
  'seq', 'sort', 'uniq', 'cut', 'tr', 'diff', 'comm',
  'systemctl status', 'journalctl', 'docker ps', 'docker logs', 'docker inspect',
  'docker stats', 'docker images', 'free', 'top', 'htop', 'iostat', 'vmstat',
  'netstat', 'ss', 'ifconfig', 'ip addr', 'ip route', 'arp', 'dig', 'nslookup',
  'host', 'ping', 'traceroute', 'git status', 'git log',
  'git diff', 'git branch', 'git show', 'git remote',
]);
// Deliberately NOT read-only: `env`, because it is an exec wrapper. `env <cmd>`
// runs <cmd>, so allowlisting the name `env` vouched for a command the
// classifier never looked at — `env sudo rm -f /etc/passwd` classified
// `read-only` and ran on a profile whose whole contract is that it cannot
// write. It carries no shell metacharacter, so the SHELL_CONTROL_CHARS gate
// below did not catch it either. Falls through to `safe`, so run-command can
// still reach it under policy; a bare `env` that only prints the environment
// loses read-only status with it, which is the price of a name-based allowlist.
//
// Deliberately NOT read-only: `curl` and `wget` fetch arbitrary URLs (SSRF to
// cloud metadata / internal services), post local files to a remote host
// (`curl -d @/etc/passwd`), and write remote files (`curl -o`, `wget -O`) —
// none of which need a shell metacharacter to escape the classifier. They fall
// through to the `safe` class, so run-command can still use them under policy.
//
// Residual risk kept on purpose: dig/nslookup/host/ping/traceroute can leak
// small amounts of data through DNS/ICMP queries. They cannot modify the host,
// so they stay read-only; tighten them via profile policy if egress matters.

/**
 * Commands that are never allowed, whatever the role or approval policy.
 *
 * This is the policy engine's denylist — the single definition of it. The
 * engine used to keep a parallel copy as regex *strings*, which had already
 * drifted (it was missing the fork bomb and the recursive chown, and its `rm`
 * pattern was narrower). Anything here is also destructive for classification
 * purposes; see DESTRUCTIVE_DENYLIST below.
 */
/*
 * These are the patterns that stayed regexes, and every one of them is linear.
 *
 * The four that were not — `dd\s.*\bof=/dev/`, the two `curl|wget …\|\s*(sh…)`
 * forms, and `chown\s+-R\s.*\s/\s*$` — are now segment checks below. An earlier
 * comment here reasoned that ambiguity *within* a match was the only cost, and
 * that was wrong: the engine also restarts at every offset where the cheap
 * literal head matches, so a command built from `dd curl wget chown -R x `
 * repeated ran at 4x per doubling. Measured on the real chain: 64 KB took
 * 255 ms, 1 MB took 65 seconds of blocked event loop, and the stall lands in
 * classifyCommand — before the approval gate and before the allow/deny
 * decision, so no role, approval mode or readOnly flag protects against it.
 *
 * The old note said sanitizeCommand's maxChars cap kept this cheap, "but a
 * policy check should not depend on a limit set three layers away and
 * configurable to any value". Once a config file could say `commandMaxChars = 0`
 * (#123) that limit went away, and the prediction came true. The rewrite below
 * is what that sentence was asking for: the policy check is now safe on its own
 * terms, whatever maxChars says.
 *
 * The existing cost test did not catch it because its seeds are runs of spaces,
 * which never match the literal heads and so never trigger the restart.
 */
const FORBIDDEN_PATTERNS: RegExp[] = [
  /rm\s+-rf?\s+\/(\s|$)/,          // rm -rf / — the filesystem root itself
  /mkfs\./,
  />\s*\/dev\/sd/,
  /:\(\)\s*\{\s*:\|:\&\s*\}\s*;\s*:/,   // fork bomb
  />\s*\/etc\/cron/,
  />\s*\/etc\/systemd/,
  />\s*~\/.ssh\/authorized_keys/,
  /\biptables\s+-F\b/,
  /\bchmod\s+-R\s+777\s+\//,
];

/**
 * Words that are forbidden when *invoked*, which the patterns above cannot
 * express.
 *
 * These used to be `/\breboot\b/` and friends, matching the word anywhere in
 * the string. `last reboot` reads a log and was refused for containing the
 * word; so were `grep -r reboot /etc/`, `cat /var/run/reboot-required` and
 * `journalctl | grep shutdown`. On a NAS an agent checking boot history trips
 * this on its first command, which is how it was reported (#91).
 *
 * Matching an invocation rather than a mention needs to know where a command
 * word can start, and that is a tokenizer's job, not a regex's — the regex
 * forms that come close all reintroduce the `\S*` backtracking the block above
 * exists to avoid.
 */
const FORBIDDEN_INVOCATIONS = new Set(['shutdown', 'reboot', 'halt', 'poweroff', 'eval']);

/** Binaries that take the dangerous action as an argument: `systemctl reboot`. */
const ACTION_MULTIPLEXERS = new Set(['systemctl', 'init', 'telinit']);

/**
 * Binaries that run the rest of the command as another user.
 *
 * The list is explicit rather than a pattern, because a pattern cannot tell
 * `sudoedit` — which edits a file and is not elevation — from `sudo-rs`, which
 * is sudo. It has to be maintained by hand as new implementations appear; the
 * cost of missing one is that its commands classify `safe`.
 *
 * The last five were added in 2.2.5 (#132). Until 2.2.4 the check was
 * `/^\s*su\b/` and friends, and `\b` matched between `su` and the hyphen, so
 * `su-exec` and `sudo-rs` were caught — by accident of the regex, not by
 * intent. Moving to exact membership dropped them, which narrowed a security
 * control inside a security release. `gosu` and `run0` were never caught by
 * either form.
 */
const PRIVILEGE_PREFIXES = new Set([
  'sudo', 'su', 'doas', 'pkexec',
  // BusyBox/Alpine, Docker entrypoints, the Rust sudo now default on some
  // distributions, systemd's replacement, and the Solaris/illumos spelling.
  'su-exec', 'gosu', 'sudo-rs', 'run0', 'pfexec',
]);

/**
 * Binaries whose job is to run another command.
 *
 * The allowlist and the privilege check both name a binary, so a wrapper hides
 * whatever it wraps: `env sudo id` was classified by the name `env`. These are
 * stepped over when deciding whether a segment elevates, so the check sees the
 * command that will actually run.
 *
 * `env` is the one that was also allowlisted, and it has been removed from
 * READ_ONLY_ALLOWLIST above. The rest were never read-only, so before this they
 * hid elevation rather than granting it — `nohup sudo systemctl stop nginx`
 * classified `safe`, which the default bindings grant to admin and operator on
 * every tier.
 */
const EXEC_WRAPPERS = new Set([
  'env', 'nohup', 'nice', 'ionice', 'command', 'exec', 'setsid', 'stdbuf',
  'timeout', 'chrt', 'taskset', 'xargs', 'watch',
]);

/**
 * Arguments that turn an allowlisted binary into one that writes or executes.
 *
 * The allowlist vouches for a name; these are the flags that make the name a
 * lie. `find /var/www -delete` removes a directory tree and `find / -exec sudo
 * id +` runs a command as root, and both classified `read-only` — the `-exec …
 * \;` form only escaped because `;` happens to be a shell metacharacter, while
 * the `+` terminator carries none.
 */
const DISQUALIFYING_ARGS: Record<string, RegExp> = {
  find: /^-(exec|execdir|ok|okdir|delete|fprintf?|fls)$/,
};

/** A leading `NAME=value`, which a shell treats as an assignment, not a command. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** `timeout 5s`, `nice 10` — a bare argument some wrappers take before the command. */
const BARE_NUMERIC = /^\d+(\.\d+)?[smhd]?$/;

/**
 * Remove the quoting a shell would remove before looking up a command.
 *
 * `\sudo`, `'sudo'` and `"sudo"` all execute sudo — the backslash only
 * suppresses alias expansion — but a verbatim string comparison sees three
 * different words. Without this, a one-character edit walks around the check.
 */
function unquote(word: string): string {
  return word.replace(/^(['"])(.*)\1$/, '$2').replace(/\\(.)/g, '$1');
}

/**
 * Privilege-prefix flags that consume the next argument, so `sudo -u root
 * reboot` is not read as invoking `root`. Enumerable because it is one tool's
 * option set, unlike "every flag of every binary".
 */
const PREFIX_VALUE_FLAGS = new Set([
  '-u', '-g', '-p', '-C', '-h', '-r', '-t', '-U', '-c',
  '--user', '--group', '--prompt', '--close-from', '--host', '--role', '--type',
  '--other-user', '--command',
]);

/** `/sbin/reboot` and `reboot` are the same invocation. */
function stripPath(word: string): string {
  const slash = word.lastIndexOf('/');
  return slash === -1 ? word : word.slice(slash + 1);
}

/**
 * The command words a shell would actually execute — the head of every
 * `;`/`&&`/`||`/`|`/newline-separated segment, past any privilege prefix, plus
 * the arguments of a multiplexer like `systemctl`.
 *
 * Pure string work: split, trim, set lookups. No quantifiers, so nothing here
 * can backtrack.
 */
interface Segment {
  /** The binary being run, with any directory part and privilege prefix removed. */
  head: string;
  /** Everything after it, verbatim — `of=/dev/sda` must not be path-stripped. */
  args: string[];
}

function parseSegments(command: string): Segment[] {
  const segments: Segment[] = [];

  for (const raw of command.split(/[;&|\n]/)) {
    const words = raw.trim().split(/\s+/).filter(Boolean);

    let i = 0;
    while (i < words.length && PRIVILEGE_PREFIXES.has(stripPath(words[i]))) {
      i++;
      while (i < words.length && words[i].startsWith('-')) {
        const consumesValue = PREFIX_VALUE_FLAGS.has(words[i]);
        i++;
        if (consumesValue) i++;
      }
    }

    if (i < words.length) {
      segments.push({ head: stripPath(words[i]), args: words.slice(i + 1) });
    }
  }

  return segments;
}

/**
 * Whether a segment asks for elevation, reading past anything that is not yet
 * the command.
 *
 * A shell resolves the command word after assignments, and a wrapper runs what
 * follows it, so all of these execute sudo while naming something else first:
 *
 *   env sudo id            nohup sudo id         timeout 5 sudo id
 *   FOO=1 sudo id          nice -n 10 sudo id    command sudo id
 *
 * The scan walks left to right and stops at the first word that is a real
 * command. Reaching a privilege prefix before that is elevation; reaching
 * anything else is not, which is what keeps `grep sudo /var/log/auth.log` a
 * mention rather than an invocation.
 */
function segmentElevates(words: string[]): boolean {
  for (const raw of words) {
    const word = stripPath(unquote(raw));

    if (PRIVILEGE_PREFIXES.has(word)) return true;

    if (ASSIGNMENT.test(raw)) continue;
    if (EXEC_WRAPPERS.has(word)) continue;
    if (raw.startsWith('-')) continue;
    if (BARE_NUMERIC.test(raw)) continue;

    return false;
  }

  return false;
}

/**
 * Does this command elevate anywhere a shell would act on it?
 *
 * Replaces four `^`-anchored regexes that only saw a *leading* prefix. Elevation
 * behind a wrapper, behind an assignment, or after a separator all reached root
 * with the command classified `safe` or `read-only`.
 */
function elevates(command: string): boolean {
  return command
    .split(/[;&|\n]/)
    .some((segment) => segmentElevates(segment.trim().split(/\s+/).filter(Boolean)));
}

/** An allowlisted binary carrying a flag that makes it write or execute. */
function hasDisqualifyingArgs(command: string): boolean {
  return parseSegments(command).some(({ head, args }) => {
    const rule = DISQUALIFYING_ARGS[head];
    return rule !== undefined && args.some((arg) => rule.test(arg));
  });
}

function invokedWords(command: string): string[] {
  const invoked: string[] = [];

  for (const { head, args } of parseSegments(command)) {
    invoked.push(head);

    // `systemctl reboot` restarts the host. Reading a unit that happens to be
    // named after a power action is rare enough that erring towards refusal
    // here costs little.
    if (ACTION_MULTIPLEXERS.has(head)) {
      invoked.push(...args.filter((w) => !w.startsWith('-')).map(stripPath));
    }
  }

  return invoked;
}

const SHELLS = new Set(['sh', 'bash', 'zsh']);
const DOWNLOADERS = new Set(['curl', 'wget']);

/**
 * A download piped into a shell.
 *
 * Split on `|` rather than reading the whole string, so cost is linear in the
 * command's length no matter how the two halves are spaced. `||` produces an
 * empty part between them, and this deliberately still matches: `curl x || sh`
 * runs a shell when the download fails, which is not meaningfully safer than
 * running one when it succeeds.
 */
function pipesDownloadIntoShell(command: string): boolean {
  const heads = command.split('|').map((part) => parseSegments(part)[0]?.head);
  const firstDownload = heads.findIndex((h) => h !== undefined && DOWNLOADERS.has(h));
  if (firstDownload === -1) return false;
  return heads.slice(firstDownload + 1).some((h) => h !== undefined && SHELLS.has(h));
}

/** `dd … of=/dev/sda` — writing an image straight onto a block device. */
function writesToDevice(command: string): boolean {
  return parseSegments(command).some(
    ({ head, args }) => head === 'dd' && args.some((a) => a.startsWith('of=/dev/')),
  );
}

/**
 * `chown -R … /` — a recursive chown whose target is the filesystem root.
 *
 * The last non-flag argument is the target; `chown -R app:app /srv/app` is
 * ordinary and stays allowed.
 */
function chownsRoot(command: string): boolean {
  return parseSegments(command).some(({ head, args }) => {
    if (head !== 'chown' || !args.includes('-R')) return false;
    const positional = args.filter((a) => !a.startsWith('-'));
    return positional[positional.length - 1] === '/';
  });
}

/** A forbidden rule, paired with wording a refusal can quote back. */
interface ForbiddenRule {
  label: string;
  test: (command: string) => boolean;
}

const FORBIDDEN_RULES: ForbiddenRule[] = [
  ...FORBIDDEN_PATTERNS.map((re) => ({ label: String(re), test: (c: string) => re.test(c) })),
  {
    label: 'invoking a power-state command (shutdown, reboot, halt, poweroff) or eval',
    test: (command) => invokedWords(command).some((w) => FORBIDDEN_INVOCATIONS.has(w)),
  },
  {
    label: 'piping a download into a shell (curl or wget into sh, bash or zsh)',
    test: pipesDownloadIntoShell,
  },
  { label: 'dd writing to a block device (of=/dev/…)', test: writesToDevice },
  { label: 'a recursive chown of the filesystem root', test: chownsRoot },
];

/**
 * Which never-allowed rule this command trips, or null. The single entry point:
 * FORBIDDEN_PATTERNS is deliberately not exported, because half of the list
 * lives in FORBIDDEN_RULES and a caller checking only the regexes would quietly
 * permit `sudo reboot`.
 */
export function findForbiddenMatch(command: string): string | null {
  for (const rule of FORBIDDEN_RULES) {
    if (rule.test(command)) return rule.label;
  }
  return null;
}

export function isForbidden(command: string): boolean {
  return findForbiddenMatch(command) !== null;
}

/**
 * Commands that are destructive but legitimate under approval — e.g.
 * `rm -rf /tmp/build`, which must NOT be confused with `rm -rf /`.
 */
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /rm\s+-rf?\s+\//,
];

/**
 * Everything that classifies as destructive: forbidden commands included.
 *
 * Goes through isForbidden() rather than the regex list, so a command caught by
 * an invocation rule is classified destructive too — and, just as importantly,
 * reading a log that mentions `reboot` is no longer classified destructive
 * either.
 */
function isDestructive(command: string): boolean {
  return isForbidden(command) || DESTRUCTIVE_PATTERNS.some((re) => re.test(command));
}

const LEADING_PRIVILEGE_PREFIXES = [
  /^\s*sudo\b/,
  /^\s*su\b/,
  /^\s*doas\b/,
  /^\s*pkexec\b/,
];

export function extractBinary(command: string): string {
  let cmd = command.trim();
  for (const prefix of LEADING_PRIVILEGE_PREFIXES) {
    cmd = cmd.replace(prefix, '').trim();
  }
  if (cmd.startsWith('-c ')) {
    cmd = cmd.slice(3).trim();
  }
  const parts = cmd.split(/\s+/);
  return parts[0] || '';
}

export function classifyCommand(command: string): ParsedCommand {
  const trimmed = command.trim();
  const binary = extractBinary(trimmed);
  const fullCommand = trimmed;

  if (elevates(trimmed)) {
    return { binary, fullCommand, class: 'privileged' as CommandClass };
  }

  if (isDestructive(trimmed) || hasDisqualifyingArgs(trimmed)) {
    return { binary, fullCommand, class: 'destructive' as CommandClass };
  }

  const twoWordPrefix = fullCommand.split(/\s+/).slice(0, 2).join(' ');
  if (READ_ONLY_ALLOWLIST.has(binary) || READ_ONLY_ALLOWLIST.has(twoWordPrefix)) {
    if (SHELL_CONTROL_CHARS.test(trimmed)) {
      return { binary, fullCommand, class: 'safe' as CommandClass };
    }
    return { binary, fullCommand, class: 'read-only' as CommandClass };
  }

  return { binary, fullCommand, class: 'safe' as CommandClass };
}

export { READ_ONLY_ALLOWLIST, isDestructive };
