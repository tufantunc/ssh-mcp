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

/**
 * Every character that could make the audited string, the approval prompt and
 * the path actually used disagree with each other.
 *
 * C0 and C1 controls, the Unicode line separators, the whole Bidi_Control set
 * (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069) and the zero-width
 * formatters. A remote path is quoted back to a human in the approval prompt
 * and written into a hash-chained audit record, so a name carrying a
 * right-to-left override renders as one path and transfers another, and one
 * carrying a zero-width space renders identically to a different path.
 *
 * An earlier version stopped at the overrides and isolates, which left the
 * marks that reorder *neutral* characters — and a path is mostly neutrals:
 * slashes, dots, hyphens and digits.
 *
 * Exported because `tools/local-path.ts` asks the same question of the local
 * half. The two *functions* are split for a real reason — that one has to stat
 * and this one must not — but the character class is one threat model, and two
 * copies of it drift the first time a codepoint is added.
 */
export const PATH_CONTROL_CHARS =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

/** Longer than any path a real filesystem accepts, so this bounds nothing legitimate. */
const MAX_REMOTE_PATH_CHARS = 4096;

/** What the audit record calls a path that never passed validation. */
export const REJECTED_REMOTE_PATH = '(rejected: invalid remote path)';

/**
 * Validate a caller-supplied *remote* path for the streaming SFTP file tools.
 *
 * Pure: it touches no filesystem and reaches no host, which is what lets it run
 * before the policy decision (#207). The local half of the same question is
 * `tools/local-path.ts`, and that one cannot be pure — it has to stat — so it
 * runs after approval instead.
 *
 * Leading and trailing whitespace is **refused**, not trimmed. `sanitizeCommand`
 * trims because a shell ignores whitespace at either end of a command, so
 * trimming cannot change what runs. A path is not a command: only NUL and `/`
 * are excluded from a POSIX filename, so `"report.txt "` and `"report.txt"` are
 * two different files. Trimming here silently retargeted the transfer and
 * audited the name it did not use.
 *
 * Shell metacharacters are deliberately *not* refused. The path is interpolated
 * into a synthetic command (`sftp:upload-file <path>`) that the classifier then
 * reads, and `classifyCommand` treats anything a shell would read as a carrier
 * by taking the *higher* class — so `/tmp/x; sudo id` classifies `privileged`
 * and is refused by policy rather than slipping through at `destructive`. A
 * filename that genuinely contains a `$` is refused for the same reason, which
 * is the direction to fail in.
 */
export function sanitizeRemotePath(path: unknown): string {
  if (typeof path !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a string');
  }
  if (!path) {
    throw new McpError(ErrorCode.InvalidParams, 'Remote path cannot be empty');
  }
  if (path !== path.trim()) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Remote path cannot begin or end with whitespace: a filename may legitimately ' +
      'contain it, so trimming would transfer a different file than the one named ' +
      'and audit the name it did not use.',
    );
  }
  if (path.length > MAX_REMOTE_PATH_CHARS) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Remote path is too long (max ${MAX_REMOTE_PATH_CHARS} characters)`,
    );
  }
  if (PATH_CONTROL_CHARS.test(path)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Remote path cannot contain control, bidirectional or zero-width formatting ' +
      'characters: the approval prompt and the audit record quote this path back, ' +
      'and such a character makes what is shown differ from what is transferred.',
    );
  }
  return path;
}

/**
 * The same path, or a fixed placeholder when it is invalid — never throws.
 *
 * So that a refused call still has something to file an audit record under. The
 * audited string has to be built before `runAudited` can evaluate anything, and
 * building it from an unvalidated path would put a control character into a
 * hash-chained log; building it from nothing left a client probing the
 * validation boundary invisible to the operator, which is the failure
 * `pipeline.ts` moved sanitization inside its own try to remove. The throwing
 * check still runs, in `preCheck`, where the refusal is audited.
 */
export function remotePathForAudit(path: unknown): string {
  try {
    return sanitizeRemotePath(path);
  } catch {
    return REJECTED_REMOTE_PATH;
  }
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
