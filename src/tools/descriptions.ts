import { createHash } from 'crypto';

export const TOOL_DESCRIPTIONS: Record<string, string> = {
  'list-connections': 'List all configured SSH profiles and their connection status. Use this to discover available hosts before running commands.',
  'list-sessions': 'List active sessions for a given SSH profile.',
  'open-session': 'Open a named session on a remote host. Use type="interactive" for stateful shell (CWD/env persists between commands) or type="background" for long-running processes.',
  'close-session': 'Close a named session. A background session\'s command is signalled on the host (INT, then TERM, then KILL) before its channel is dropped; an interactive session\'s shell is ended. The response says so if the command could not be signalled or had not stopped in time.',
  'read-session-output': 'Read recent output from a background session (e.g., tail -f logs).',
  'read-command': 'Execute a READ-ONLY command from an allowlist (ls, cat, grep, find, stat, df, etc.). This tool does NOT modify the system. Prefer this tool for all read operations.',
  'run-command': 'Execute an arbitrary shell command on the remote server. May modify the system. Commands classified destructive or privileged require user approval, unless the profile sets approvalPolicy to auto.',
  'privileged-command': 'Execute a command with sudo elevation. Requires user approval unless the profile sets approvalPolicy to auto. The sudo password is piped via stdin (never visible in process list).',
  'sftp-upload': 'Upload a file to the remote server via SFTP (secure file transfer, not shell-based).',
  'sftp-download': 'Download a file from the remote server via SFTP.',
  'signal-process': 'Send a signal (INT, TERM, KILL) to a remote process by PID.',
};

export function getToolHashes(): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const [name, desc] of Object.entries(TOOL_DESCRIPTIONS)) {
    hashes[name] = createHash('sha256').update(desc).digest('hex').slice(0, 16);
  }
  return hashes;
}
