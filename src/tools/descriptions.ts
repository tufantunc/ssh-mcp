import { createHash } from 'crypto';

export const TOOL_DESCRIPTIONS: Record<string, string> = {
  'list-connections': 'List all configured SSH profiles and their connection status. Use this to discover available hosts before running commands.',
  'list-sessions': 'List active sessions for a given SSH profile.',
  'open-session': 'Open a named session on a remote host. Use type="interactive" for stateful shell (CWD/env persists between commands) or type="background" for long-running processes.',
  'close-session': 'Close a named session. A background session\'s command is signalled on the host (INT, then TERM, then KILL) before its channel is dropped; an interactive session\'s shell is ended. The response says so if the command could not be signalled or had not stopped in time.',
  'read-session-output': 'Read recent output from a background session (e.g., tail -f logs).',
  'read-command': 'Execute a READ-ONLY command from an allowlist (ls, cat, grep, find, stat, df, etc.). This tool does NOT modify the system. Prefer this tool for all read operations. Single-line only: a command containing a line break is refused, so upload a multi-line script with sftp-upload and run it by path.',
  'run-command': 'Execute an arbitrary shell command on the remote server. May modify the system. Commands classified destructive or privileged go through the approval gate; approvalPolicy on the profile decides whether that is a prompt, an automatic allow, or a refusal. Single-line only: a command containing a line break is refused, so upload a multi-line script with sftp-upload and run it by path.',
  'privileged-command': 'Execute a command with sudo elevation. Goes through the approval gate; approvalPolicy on the profile decides whether that is a prompt, an automatic allow, or a refusal. The sudo password is piped via stdin (never visible in process list). Single-line only: a command containing a line break is refused, so upload a multi-line script with sftp-upload and run it by path.',
  'sftp-upload': 'Upload a file to the remote server via SFTP (secure file transfer, not shell-based). Replaces an existing file at that path unconditionally — there is no overwrite flag and no way to require a new destination.',
  'sftp-download': 'Download a file from the remote server via SFTP.',
  'sftp-list': 'List a remote directory over SFTP, with a bounded number of entries and a bounded response size. Read-only.',
  'sftp-upload-file': 'Upload a local file to the remote host over SFTP, streaming it without passing the contents through model context. The local file must be inside the transferRoot directory the operator configured; without that setting this tool refuses. Use this for binary or large files; use sftp-upload for short text you already have.',
  'sftp-download-file': 'Download a remote file to local disk over SFTP, streaming it without passing the contents through model context. The destination must be inside the transferRoot directory the operator configured; without that setting this tool refuses. Use this for binary or large files; use sftp-download when you need to read the contents.',
  'signal-process': 'Send a signal (INT, TERM, KILL) to a remote process by PID.',
};

export function getToolHashes(): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const [name, desc] of Object.entries(TOOL_DESCRIPTIONS)) {
    hashes[name] = createHash('sha256').update(desc).digest('hex').slice(0, 16);
  }
  return hashes;
}
