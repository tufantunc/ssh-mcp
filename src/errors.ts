import { writeSync } from 'fs';
import { inspect } from 'util';

/**
 * Errors caused by how the server was invoked or configured, as opposed to a
 * defect in it.
 *
 * The distinction exists because the two need to be *presented* differently.
 * `main()` used to hand every failure to `console.error('Fatal error:', error)`,
 * which prints an Error object — name, message and full stack. A missing
 * `--host` therefore reached the operator as a stack trace through
 * `buildAppConfig` and `main`, which reads as a crash. The three lines of
 * explanation we wrote for them were buried inside frames that only matter to
 * someone debugging this codebase. It is the first thing the reporter of #138
 * pasted, and none of it pointed at their actual problem.
 *
 * `reportFatal` below is the other half of that rule and lives here rather than
 * in the CLI entry point, so the reasoning is written once and a unit test can
 * reach it without importing a module that starts a server on import.
 *
 * The name says operator rather than user because in this codebase "user" is
 * the SSH account a command runs as. This is about whoever started the server.
 *
 * Scope: any throw reachable from `main()` before the transport connects should
 * be an OperatorError, and `reportFatal` is the only reader of that promise.
 * `getProfile` also throws one for a profile name that does not exist, which a
 * tool call can trigger at request time — there the message reaches the client
 * through the MCP error rather than through `reportFatal`, and the wording is
 * written for the same audience either way.
 */
export class OperatorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OperatorError';
  }
}

/**
 * No config file at the path we looked in.
 *
 * Separated from every other config failure because it is the one case that is
 * not necessarily a problem: with no config file, `--host`/`--user` take over.
 * `buildAppConfig` expressed that with a bare `catch {}`, which also swallowed
 * "the file is there and unusable" — a malformed TOML, a schema violation, a
 * permission failure — and reported all of them as "No config file found".
 *
 * That is what made #138 unfindable. A Windows operator with a valid config in
 * the right place was told the file did not exist, while the real error (a
 * permission check that cannot pass on Windows) was discarded unread.
 *
 * The type is the signal rather than the message text, so the fall-through
 * cannot be widened by an unrelated edit to the wording.
 */
export class ConfigNotFoundError extends OperatorError {
  /**
   * Kept because `loadConfig(customPath)` used to reject with Node's own
   * SystemError for a missing file, and `.code` was observable on it. Nothing
   * in this repo reads it, but a wrapper script plausibly might, and preserving
   * it costs one line.
   */
  readonly code = 'ENOENT';

  constructor(public readonly configPath: string) {
    super(
      `No config file found at ${configPath}. Create one or use --config <path>. ` +
      'See documentation for the TOML schema.',
    );
    this.name = 'ConfigNotFoundError';
  }
}

/** Exit status for an operator error, so a supervisor can tell it from a crash. */
export const EXIT_OPERATOR_ERROR = 2;
/** Exit status for anything else. */
export const EXIT_DEFECT = 1;

/**
 * How a failure reaches the operator.
 *
 * An OperatorError is about how the server was invoked or configured, so its
 * message is the whole answer. Anything else keeps the stack, because for a
 * real defect the stack is the part worth having — which also makes the stack a
 * signal: present means "this is ours, report it".
 *
 * Returns the exit status rather than calling `process.exit`, so the two halves
 * of the rule stay testable without spawning a process.
 */
export function reportFatal(
  error: unknown,
  log: (...args: unknown[]) => void = writeStderr,
): number {
  if (error instanceof OperatorError) {
    log(error.message);
    return EXIT_OPERATOR_ERROR;
  }
  log('Fatal error:', error);
  return EXIT_DEFECT;
}

/**
 * The default sink: a synchronous write to fd 2.
 *
 * Not `console.error`, because the caller calls `process.exit` on the next line.
 * Node's writes to stderr are synchronous for files, and for pipes on Linux and
 * Windows — but **asynchronous for pipes on macOS**, and under the stdio
 * transport stderr *is* a pipe owned by the MCP client. So on macOS the message
 * this whole change exists to deliver could be queued and then truncated by the
 * exit, leaving the operator with a disconnect and an exit status. CI runs on
 * Linux, where the pipe is synchronous, so no test would have caught it.
 */
function writeStderr(...args: unknown[]): void {
  let line = '';
  try {
    // Inside the try: `util.inspect` does not catch a throwing
    // `[util.inspect.custom]`, so formatting could throw while reporting a throw, which
    // escaped main()'s catch as an unhandled rejection and printed nothing at all.
    line = args.map((a) => (typeof a === 'string' ? a : inspect(a))).join(' ');
    writeSync(2, `${line}\n`);
  } catch {
    // EAGAIN on a non-blocking pipe, or a closed fd. Better a lost line than an
    // exception thrown while reporting an exception.
    console.error(line || `Fatal error: <unprintable ${typeof args[args.length - 1]}>`);
  }
}
