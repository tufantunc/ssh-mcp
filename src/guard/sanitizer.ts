import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';

/** Every character a shell would read as the end of one command and the start of another. */
const LINE_BREAKS = /[\r\n\u2028\u2029]/;
const NUL = /\u0000/;

/**
 * Validate a caller-supplied command.
 *
 * A line break is refused, not removed. The constraint itself is not negotiable
 * — a newline inside `command` would let a second command ride along past a
 * classifier that parsed only the first, which is #44 — but an earlier version
 * enforced it by replacing the break with a space, and *that* is the part worth
 * changing. The caller got no error and a different command than it asked for:
 * two lines joined, so `ls\necho x` ran `ls echo x`; or a `#` comment in a
 * `python3 -c` body pulled onto the same line, commenting out everything after
 * it. Sometimes that raises. Sometimes it runs and quietly does half the work,
 * which is the failure mode worth removing (#198).
 *
 * Trailing and leading breaks are trimmed rather than refused. A client that
 * appends a newline works today, refusing it would break that for no gain, and
 * a break at either end cannot join two commands.
 */
export function sanitizeCommand(command: unknown, maxChars: number): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }
  const cleaned = command.trim();
  if (!cleaned) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }
  if (LINE_BREAKS.test(cleaned)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Command cannot contain a line break: a second line would run past the classifier ' +
      'that only saw the first. It is refused rather than silently joined into one line, ' +
      'which is what happened before and changed what ran without saying so. ' +
      'To run a multi-line script, upload it with sftp-upload and execute it by path.',
    );
  }
  if (NUL.test(cleaned)) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot contain a null byte');
  }
  if (Number.isFinite(maxChars) && cleaned.length > maxChars) {
    throw new McpError(ErrorCode.InvalidParams, `Command is too long (max ${maxChars} characters)`);
  }
  return cleaned;
}

export function sanitizeSessionName(name: string): string {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Session name must be 1-64 chars, alphanumeric/dash/underscore only',
    );
  }
  return name;
}

export function shellSingleQuote(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}
