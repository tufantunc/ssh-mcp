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
  'host', 'ping', 'traceroute', 'curl', 'wget', 'git status', 'git log',
  'git diff', 'git branch', 'git show', 'git remote',
]);

const DESTRUCTIVE_DENYLIST: RegExp[] = [
  /rm\s+-rf?\s+\//,
  /mkfs\./,
  /dd\s+.*\bof=\/dev\//,
  />\s*\/dev\/sd/,
  /\bshutdown\b/,
  /\breboot\b/,
  /\bhalt\b/,
  /\bpoweroff\b/,
  /:\(\)\s*\{\s*:\|:\&\s*\}\s*;\s*:/,
  /curl\s+.*\|\s*(sh|bash|zsh)/,
  /wget\s+.*\|\s*(sh|bash|zsh)/,
  /\beval\b/,
  />\s*\/etc\/cron/,
  />\s*\/etc\/systemd/,
  />\s*~\/.ssh\/authorized_keys/,
  /\biptables\s+-F\b/,
  /\bchmod\s+-R\s+777\s+\//,
  /\bchown\s+-R\s+.*\s+\/\s*$/,
];

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

export { READ_ONLY_ALLOWLIST, DESTRUCTIVE_DENYLIST };
