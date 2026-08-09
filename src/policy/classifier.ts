import type { CommandClass, ParsedCommand } from '../types.js';

const READ_ONLY_ALLOWLIST = new Set([
  'ls', 'cat', 'grep', 'find', 'stat', 'df', 'du', 'head', 'tail', 'wc',
  'ps', 'uname', 'uptime', 'hostname', 'id', 'who', 'whoami', 'date',
  'env', 'printenv', 'pwd', 'echo', 'printf', 'test', 'true', 'false',
  'which', 'whereis', 'file', 'readlink', 'realpath', 'basename', 'dirname',
  'seq', 'sort', 'uniq', 'cut', 'tr', 'diff', 'comm',
  'systemctl status', 'journalctl', 'docker ps', 'docker logs', 'docker inspect',
  'docker stats', 'docker images', 'free', 'top', 'htop', 'iostat', 'vmstat',
  'netstat', 'ss', 'ifconfig', 'ip addr', 'ip route', 'arp', 'dig', 'nslookup',
  'host', 'ping', 'traceroute', 'git status', 'git log',
  'git diff', 'git branch', 'git show', 'git remote',
]);
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
 * Every `\s+` here is followed by a literal. Where a `.*` or `[^|]*` comes
 * next, the quantifier before it is a single `\s`: `\s+.*` lets both halves
 * claim the same run of spaces, so a non-matching command is retried from every
 * split and the match goes quadratic. sanitizeCommand caps commands at
 * profile.maxChars (5000 by default) long before this runs, which is what keeps
 * that cheap — but a policy check should not depend on a limit set three layers
 * away and configurable to any value.
 */
const FORBIDDEN_PATTERNS: RegExp[] = [
  /rm\s+-rf?\s+\/(\s|$)/,          // rm -rf / — the filesystem root itself
  /mkfs\./,
  /dd\s.*\bof=\/dev\//,
  />\s*\/dev\/sd/,
  /\bshutdown\b/,
  /\breboot\b/,
  /\bhalt\b/,
  /\bpoweroff\b/,
  /:\(\)\s*\{\s*:\|:\&\s*\}\s*;\s*:/,   // fork bomb
  /curl\s[^|]*\|\s*(sh|bash|zsh)/,
  /wget\s[^|]*\|\s*(sh|bash|zsh)/,
  /\beval\b/,
  />\s*\/etc\/cron/,
  />\s*\/etc\/systemd/,
  />\s*~\/.ssh\/authorized_keys/,
  /\biptables\s+-F\b/,
  /\bchmod\s+-R\s+777\s+\//,
  /\bchown\s+-R\s.*\s\/\s*$/,
];

/**
 * Commands that are destructive but legitimate under approval — e.g.
 * `rm -rf /tmp/build`, which must NOT be confused with `rm -rf /`.
 */
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /rm\s+-rf?\s+\//,
];

/** Everything that classifies as destructive: forbidden commands included. */
const DESTRUCTIVE_DENYLIST: RegExp[] = [...FORBIDDEN_PATTERNS, ...DESTRUCTIVE_PATTERNS];

const PRIVILEGED_INDICATORS = [
  /^\s*sudo\b/,
  /^\s*su\b/,
  /^\s*doas\b/,
  /^\s*pkexec\b/,
];

export function extractBinary(command: string): string {
  let cmd = command.trim();
  for (const prefix of PRIVILEGED_INDICATORS) {
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

  const isPrivileged = PRIVILEGED_INDICATORS.some((re) => re.test(trimmed));

  if (isPrivileged) {
    return { binary, fullCommand, class: 'privileged' as CommandClass };
  }

  for (const pattern of DESTRUCTIVE_DENYLIST) {
    if (pattern.test(trimmed)) {
      return { binary, fullCommand, class: 'destructive' as CommandClass };
    }
  }

  const twoWordPrefix = fullCommand.split(/\s+/).slice(0, 2).join(' ');
  if (READ_ONLY_ALLOWLIST.has(binary) || READ_ONLY_ALLOWLIST.has(twoWordPrefix)) {
    if (/[>;|]/.test(trimmed)) {
      return { binary, fullCommand, class: 'safe' as CommandClass };
    }
    return { binary, fullCommand, class: 'read-only' as CommandClass };
  }

  return { binary, fullCommand, class: 'safe' as CommandClass };
}

export { READ_ONLY_ALLOWLIST, DESTRUCTIVE_DENYLIST, FORBIDDEN_PATTERNS };
