import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
// The classifier's own resolver, not a second one. See SYNTHETIC_NAMESPACE below.
import { extractBinary } from '../policy/classifier.js';

/** Every character a shell would read as the end of one command and the start of another. */
const LINE_BREAKS = /[\r\n\u2028\u2029]/;
const NUL = /\u0000/;

/**
 * Verbs this server builds for itself, which a caller may therefore not type.
 *
 * `classifyOuter` cannot tell a synthetic string from one a caller typed — both
 * arrive as text. So the moment `sftp:list` was given a class, `read-command`
 * accepted it as a command word too: measured, a `readOnly` viewer could send
 * `read-command "sftp:list /tmp sudo id"` and the classifier answered
 * `read-only`, the gate allowed it, and `exec` ran it. On main the same string
 * was `safe` and refused.
 *
 * The audit log had the same problem from the other side: a forged record was
 * identical in every field to one the tool itself produced.
 *
 * `sanitizeCommand` is the right place because it runs, by construction, only
 * for commands that did *not* come from us — `runAudited` skips it when
 * `synthetic: true`.
 *
 * Tested against `extractBinary`, the classifier's own resolver, rather than
 * against a first-token helper of this file's own. A private one was written
 * first and drifted immediately: `extractBinary` strips a leading `-c ` and the
 * leading privilege prefixes, which the helper did not, so
 * `read-command "-c sftp:download /etc/shadow"` resolved to binary
 * `sftp:download`, classified `read-only`, was allowed on a profile that denies
 * it on main, and executed. Two resolvers answering one question is the bug;
 * asking the one that decides is the fix.
 *
 * Scope of the guarantee, stated narrowly on purpose: an `sftp:*` or `session:*`
 * audit record is provably tool-generated. `signal-process` synthesises
 * `kill -TERM <pid>`, which is outside this namespace and cannot be reserved —
 * `kill` is a binary a caller may legitimately need — so a record of that shape
 * is not covered.
 */
const SYNTHETIC_NAMESPACE = /^(?:sftp|session):/;

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
  if (SYNTHETIC_NAMESPACE.test(extractBinary(cleaned))) {
    throw new McpError(
      ErrorCode.InvalidParams,
      'Command cannot begin with "sftp:" or "session:": that namespace is reserved for the ' +
      'strings this server builds for its own tools, and the classifier cannot tell a typed ' +
      'one from a generated one. Use the sftp-* and *-session tools instead.',
    );
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
 * C0 and C1 controls, the Unicode line separators, the Bidi_Control set
 * (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069), and the zero-width
 * characters that carry no meaning of their own. A remote path is quoted back to
 * a human in the approval prompt and written into a hash-chained audit record,
 * so a name carrying a right-to-left override renders as one path and transfers
 * another, and one carrying a zero-width space renders identically to a
 * different path.
 *
 * An earlier version stopped at the overrides and isolates, which left the
 * marks that reorder *neutral* characters — and a path is mostly neutrals:
 * slashes, dots, hyphens and digits.
 *
 * **U+200C and U+200D are deliberately not here**, though they sit inside the
 * range an earlier version of this class swept up. ZWNJ and ZWJ are invisible
 * but not meaningless: they are orthographically required in Persian and in the
 * Indic scripts, and structural inside an emoji sequence. Refusing them rejected
 * real filenames — measured, `/srv/mi<ZWNJ>ravad.txt` is a name a filesystem
 * accepts and a user types. The spoofing argument does not reach them either,
 * since it rests on two *different* paths rendering identically, and this
 * codebase already accepts that for homoglyphs (Cyrillic а against Latin a),
 * which no character class can catch. Refusing the joiners while accepting those
 * was inconsistent and cost legitimate input.
 *
 * Exported because `tools/local-path.ts` asks the same question of the local
 * half. The two *functions* are split for a real reason — that one has to stat
 * and this one must not — but the character class is one threat model, and two
 * copies of it drift the first time a codepoint is added.
 */
export const PATH_CONTROL_CHARS =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200b\u200e\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

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
