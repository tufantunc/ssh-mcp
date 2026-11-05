import { writeSync } from 'fs';
import { inspect } from 'util';
import { performance } from 'perf_hooks';

/**
 * Errors caused by how the server was invoked or configured, as opposed to a
 * defect in it.
 *
 * The distinction exists because the two need to be *presented* differently.
 * `main()` used to hand every failure to `console.error('Fatal error:', error)`,
 * which prints an Error object — name, message and full stack. A missing
 * `--host` therefore reached the operator as a stack trace through the startup
 * config loader (`loadAppConfig` today) and `main`, which reads as a crash. The
 * three lines of explanation we wrote for them were buried inside frames that
 * only matter to someone debugging this codebase. It is the first thing the reporter of #138
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
 * The startup loader (`loadAppConfig` today) used to express that with a bare
 * `catch {}`, which also swallowed "the file is there and unusable" — a
 * malformed TOML, a schema violation, a permission failure — and reported all
 * of them as "No config file found".
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
   * Kept because the loader (`loadConfigWithDigest` today) used to reject with
   * Node's own SystemError for a missing file, and `.code` was observable on it. Nothing
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

/**
 * Nothing is configured: no config file, and no `--host`/`--user` on the command line.
 *
 * A type rather than a bare `OperatorError` for the reason `ConfigNotFoundError` is one —
 * two layers have to agree on this state without agreeing on a string. `cli.ts` prints it
 * as a startup warning and the server keeps running; `ConnectionRegistry` throws it at
 * every tool call. Those are different audiences reached through different channels, and
 * a wording edit in one must not quietly stop matching the other.
 *
 * The path is a constructor argument rather than a `getConfigPath()` call inside the
 * message, so this file stays free of the config layer and the text is testable without
 * stubbing `os.platform()`.
 */
export class UnconfiguredError extends OperatorError {
  constructor(public readonly configPath: string) {
    super(
      'No config file found and missing required --host/--user.\n' +
      `Either create a config file at ${configPath} or pass --config <path>.\n` +
      'For quick start: --host=<host> --user=<user> (credentials via env vars).',
    );
    this.name = 'UnconfiguredError';
  }
}

/**
 * The config file is not valid TOML.
 *
 * A type of its own so a reader that must not quote the file can still say where the
 * problem is: the parser's message embeds a snippet of the source, and `line`/`column`
 * locate it without one. The message is unchanged for startup, which prints it whole.
 */
export class ConfigParseError extends OperatorError {
  constructor(message: string, readonly line?: number, readonly column?: number) {
    super(message);
    this.name = 'ConfigParseError';
  }
}

/**
 * One schema issue, by where it is and what kind it is: never the value received. The
 * path stays in segments, because some segments are keys the operator chose (role and
 * group names) and a reader that must not repeat them has to know where one ends.
 */
export interface ConfigIssue {
  path: string[];
  code: string;
}

/**
 * The config file parsed but does not match the schema.
 *
 * `issues` exists for the reason `ConfigParseError.line` does: a schema message can name
 * what it received (an unknown key, a refinement's wording), and the reload report must
 * not repeat anything from the file. Startup still prints the full message.
 */
export class ConfigSchemaError extends OperatorError {
  constructor(message: string, readonly issues: ConfigIssue[]) {
    super(message);
    this.name = 'ConfigSchemaError';
  }
}

/**
 * An error's class name, or its `typeof` when it is not an Error. For reporting a failure
 * whose message may quote something that must not be repeated, such as the config file.
 */
export function errorName(err: unknown): string {
  return err instanceof Error ? err.name : typeof err;
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
 * exit, leaving the operator with a disconnect and an exit status. Only the macOS
 * job can see that difference; cli-fatal-reporting.test.ts measures it there.
 */
const writeStderr = stderrSink();

/**
 * A sink that formats its arguments as one line and writes it with `writeAllSync`.
 * `write`, `fallback` and `now` are parameters so the failure paths are testable.
 */
export function stderrSink(
  write: SyncWrite = writeSync,
  fallback: (line: string) => void = (line) => console.error(line),
  now: () => number = monotonicMs,
): (...args: unknown[]) => void {
  return (...args) => {
    let line = '';
    try {
      // Inside the try: `util.inspect` does not catch a throwing
      // `[util.inspect.custom]`, so formatting could throw while reporting a throw, which
      // escaped main()'s catch as an unhandled rejection and printed nothing at all.
      line = args.map((a) => (typeof a === 'string' ? a : inspect(a))).join(' ');
      writeAllSync(2, `${line}\n`, write, now);
    } catch (err) {
      // A closed fd, or a reader that stopped draining. Better a lost tail than an
      // exception thrown while reporting an exception — and only a line that never
      // started goes to the fallback, which would otherwise print its head twice.
      const written = (err as { written?: number } | undefined)?.written ?? 0;
      if (written === 0) fallback(line || `Fatal error: <unprintable ${typeof args[args.length - 1]}>`);
    }
  };
}

type SyncWrite = (fd: number, buf: Buffer, offset: number) => number;

/** How long `writeAllSync` keeps retrying a pipe that takes nothing before giving up. */
export const STDERR_DRAIN_MS = 2_000;

/**
 * Milliseconds on a clock that only moves forward. The wall clock would let an NTP step
 * backwards stretch the drain window by however far it went.
 */
function monotonicMs(): number {
  // A declaration, not a const: `stderrSink()` runs at module load, above this line.
  return performance.now();
}

/**
 * Write all of `text` to `fd`, synchronously. A failure is rethrown carrying `written`,
 * the bytes that did go out.
 *
 * One `writeSync` is not one write. Once anything has touched `process.stderr` — and in
 * a running server something always has — Node puts a pipe on fd 2 into non-blocking
 * mode on macOS, and each call then takes at most what the pipe has room for: measured,
 * 65536 bytes, returned as a count rather than thrown. The single call this replaces cut
 * every message at 64KB. A full pipe answers EAGAIN until the reader drains it, so that
 * is retried — as is a write that takes nothing — for a bounded time: a reader that never
 * drains must not stop the process from exiting.
 */
export function writeAllSync(
  fd: number,
  text: string,
  write: SyncWrite = writeSync,
  now: () => number = monotonicMs,
): void {
  const buf = Buffer.from(text);
  const deadline = now() + STDERR_DRAIN_MS;
  let offset = 0;
  while (offset < buf.length) {
    let stalled: Error;
    try {
      const taken = write(fd, buf, offset);
      offset += taken;
      if (taken > 0) continue;
      stalled = Object.assign(new Error('write took no bytes'), { code: 'EAGAIN' });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EAGAIN') throw Object.assign(err as Error, { written: offset });
      stalled = err as Error;
    }
    if (now() > deadline) throw Object.assign(stalled, { written: offset });
  }
}
