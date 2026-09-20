/**
 * Reading an awk program well enough to classify what it does (#184).
 *
 * awk is the one interpreter this codebase could not fit into the `INTERPRETERS`
 * table, and two review rounds produced five attempts that were each holed by
 * the next. The two reasons are structural, and neither is fixed by adding a
 * flag to a table:
 *
 * 1. **The program is a positional operand, not a flag's value.** For `sh -c` or
 *    `python3 -c` the flag is the evidence that the interpreter was *invoked*;
 *    awk has none, so nothing in the argument list separates running awk from
 *    naming it. Keying on any word that says "awk" made `readlink -f /usr/bin/awk`
 *    and `man awk` destructive. The answer is to key on the segment's *command
 *    word* — which is what the caller does before reaching this module.
 * 2. **The four implementations disagree about which flags consume a value.**
 *    gawk consumes for `-i` and `-W`; mawk consumes for `-W` and rejects `-i`;
 *    busybox consumes for `-W`; and BWK awk — `awk` on macOS, the BSDs and
 *    Debian's `original-awk` — ignores an unknown option *without* consuming it
 *    and runs the next operand as the program. A table that skips a word awk did
 *    not skip hands this module the data file instead of the program. So only
 *    the three flags all four agree consume a value are skipped — plus the two
 *    that run no program at all — and any other flag makes the program's
 *    position unknowable, which is reported as `unreadable`.
 *
 * The rest is a small lexer. It exists because the escapes cannot be found with
 * a regex: `awk 'NR>1'` and `awk '{print $1 > $2}'` differ only in whether the
 * `>` follows an output statement, which is exactly awk's own rule and is why
 * `print (a>b)` needs its parentheses. Three of the five earlier holes were in a
 * regex trying to approximate that, and a fourth was the quadratic backtracking
 * that approximation needed.
 *
 * Single pass, no backtracking: a 211KB program of repeated `print` tokens is
 * the seed that caught the quadratic, and it is in the tests.
 */

/** What an awk program was found to do. */
export interface AwkFindings {
  /**
   * Shell commands the program hands to a shell — `system()`, `print | "cmd"`,
   * `"cmd" | getline`. Returned rather than classified here so the caller can
   * re-enter its own classifier: `awk 'BEGIN{system("sudo id")}'` is then
   * `privileged`, which is what it is, rather than a flat `destructive`.
   */
  commands: string[];
  /**
   * Commands the program pipes its *output* into — `print … | "cmd"`.
   *
   * Separate from `commands` because the direction is the payload: the shell
   * analogue `echo "sudo id" | sh` is already gated by `readsProgramFromStdin`,
   * which reads a pipe stage whose command word is an interpreter with no
   * program of its own as running whatever the previous stage printed. Pushing
   * `sh` into `commands` alone classified `awk 'BEGIN{print "sudo id" | "sh"}'`
   * as `safe`, because `sh` on its own is not dangerous — what is dangerous is
   * what awk prints into it, which this module cannot know.
   */
  pipedInto: string[];
  /** The program writes a file through output redirection. */
  writesFile: boolean;
  /**
   * The program, or where the program is, could not be read.
   *
   * "We cannot tell", not "this is root" — the same answer `hasUnreadableProgram`
   * gives for `python3 -c`, and it gates on approval rather than refusing.
   */
  unreadable: boolean;
}

/** Command words that run an awk program. `busybox awk` arrives here as `awk`. */
export const AWK_NAMES: ReadonlySet<string> = new Set(['awk', 'gawk', 'mawk', 'nawk']);

/**
 * The only flags all four implementations agree consume a following word.
 *
 * `-f` is here to be *recognised*, not to be followed: its value is a program
 * file this process cannot read, so seeing it ends the read as `unreadable`.
 */
const VALUE_FLAGS = new Set(['-F', '-v', '-f']);

/**
 * The size past which a program is refused rather than read.
 *
 * Chosen to sit above the 211KB regression seed that documents the quadratic
 * this module replaced — that shape still has to be lexed for the cost test to
 * mean anything — and far below the sizes where a linear pass is nonetheless a
 * stall: a 1MB program of `system()` calls measured 2.1s on the one thread that
 * serves every tool call. No awk one-liner comes near either number.
 */
const MAX_PROGRAM_CHARS = 256 * 1024;

/** Flags that take no value and run no program, so `awk --version` stays quiet. */
const INFO_FLAGS = new Set(['--version', '--help']);

/**
 * Redirection targets that are not a file write.
 *
 * `print > "/dev/stderr"` is an ordinary idiom for separating diagnostics from
 * output, and gating it would put a prompt on scripts that write nothing.
 */
const NON_FILE_TARGETS = new Set(['/dev/stdout', '/dev/stderr', '/dev/null', '/dev/fd/1', '/dev/fd/2']);

/** Fresh object rather than a shared constant: the arrays are ones a caller could push to. */
const unreadable = (): AwkFindings => ({ commands: [], pipedInto: [], writesFile: false, unreadable: true });

type Token =
  | { k: 'word'; v: string }
  | { k: 'num' }
  | { k: 'str'; v: string }
  | { k: 'regex' }
  | { k: 'punct'; v: string }
  | { k: 'nl' };

/** Operators that are two or three characters, longest first so `>>` beats `>`. */
const OPERATORS = [
  // No `>>=`: awk has no shift operators at all — gawk exposes shifts as the
  // `lshift()`/`rshift()` functions, so there is nothing to assign through.
  // Verified on BWK awk 20200816: `x>>=1` is a syntax error. `**=` is genuine.
  '**=',
  '|&', '&&', '||', '==', '!=', '<=', '>=', '>>', '++', '--',
  '+=', '-=', '*=', '/=', '%=', '^=', '!~', '**',
];

/**
 * Operators grouped by first character, so a punctuation token costs one lookup.
 *
 * The scan used to slice two fresh strings per punctuation character and run two
 * `Array.find`s over the whole table. Measured, that made punctuation the
 * lexer's most expensive input by 8x over identifiers and 81x over whitespace —
 * and `?:,~$` is both the cheapest program to write and the one that matched
 * nothing, so it took the slowest path on every character.
 */
const OPERATORS_BY_FIRST = new Map<string, string[]>();
for (const op of OPERATORS) {
  const bucket = OPERATORS_BY_FIRST.get(op[0]);
  if (bucket) bucket.push(op);
  else OPERATORS_BY_FIRST.set(op[0], [op]);
}

/**
 * Words after which no operand has ended, so a following `/` opens a regex.
 *
 * Reserved words only. An earlier version listed `and`, `or`, `not`, `case`,
 * `func`, `getline` and the built-in function names, and every one of those was
 * a hole: none is reserved in POSIX awk, BWK awk, mawk or busybox awk, so
 * `BEGIN{not=2; x = not / system("sudo id") / 3}` is a *division* that real awk
 * evaluates — measured on BWK awk 20200816, `not` is an ordinary variable and
 * the program prints 0.666667 after running the command. Treating the `/` as a
 * regex open swallowed the `system()` call as pattern text and the program
 * classified `safe`.
 *
 * `getline` is out for the mirror reason: it yields a value, so an operand
 * *has* ended and `getline / 2` divides.
 *
 * The failure directions are not symmetric, which is why this list is short.
 * Lexing a regex as division reads the region as code and can only over-report;
 * lexing code as a regex hides whatever is inside it. When in doubt, leave the
 * word out.
 */
const AWK_KEYWORDS = new Set([
  'print', 'printf', 'if', 'while', 'do', 'for', 'return', 'delete',
  'else', 'in', 'BEGIN', 'END', 'function', 'exit', 'next',
]);

/**
 * Whether a `/` here starts a regex rather than division.
 *
 * awk's own rule, and the same one every JavaScript lexer needs: a `/` after
 * something that can end an operand divides; anywhere else it opens a regex.
 * Getting this wrong matters in both directions — `awk '/a>b/{print}'` hides a
 * `>` inside a regex, and `awk '{print a/b}'` must not swallow the rest of the
 * program as one.
 */
function regexCanStart(previous: Token | undefined): boolean {
  if (previous === undefined) return true;
  if (previous.k === 'num' || previous.k === 'str' || previous.k === 'regex') return false;
  if (previous.k === 'word') return AWK_KEYWORDS.has(previous.v);
  if (previous.k === 'punct') return ![')', ']', '++', '--', '$'].includes(previous.v);
  return true;
}

const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z_0-9]/;
const DIGIT = /[0-9]/;

const SIMPLE_ESCAPES: Record<string, string> = {
  n: '\n'.slice(0), t: '\t', r: '\r',
  '\\': '\\', '"': '"', '/': '/',
  a: '\x07', b: '\b', f: '\f', v: '\v',
};

const OCTAL = /[0-7]/;
const HEX = /[0-9a-fA-F]/;

/**
 * Decode one escape sequence, returning its value and how many source
 * characters it consumed (not counting the backslash).
 *
 * `\ddd` and `\xhh` are the reason this is not a single-character switch. Every
 * awk decodes them, and they change the bytes that reach the shell: measured on
 * BWK awk 20200816, `awk 'BEGIN{system("\\145cho OCTAL_RAN")}'` runs `echo`
 * and `print "\\163udo"` prints `sudo`. Reading them literally meant the string
 * pushed into `commands` was not the command that runs, so `system("\\163udo id")`
 * classified `safe` — and the same spelling slipped past the never-allowed list,
 * which tests the raw text.
 *
 * `\xhh` is gawk's, and BWK awk decodes it too; mawk does not. Decoding it is
 * the over-reporting direction on the implementations that do not, which is the
 * one to fail in.
 *
 * Anything else is the character itself, which is what every implementation
 * does with an unknown escape. That keeps `FS="\\."` — an extremely common
 * idiom — from being read as something this module cannot model.
 */
function readEscape(source: string, at: number): { value: string; consumed: number } {
  const c = source[at];
  if (OCTAL.test(c)) {
    let digits = c;
    while (digits.length < 3 && OCTAL.test(source[at + digits.length] ?? '')) {
      digits += source[at + digits.length];
    }
    return { value: String.fromCharCode(parseInt(digits, 8)), consumed: digits.length };
  }
  if (c === 'x' && HEX.test(source[at + 1] ?? '')) {
    let digits = '';
    while (digits.length < 2 && HEX.test(source[at + 1 + digits.length] ?? '')) {
      digits += source[at + 1 + digits.length];
    }
    return { value: String.fromCharCode(parseInt(digits, 16)), consumed: digits.length + 1 };
  }
  return { value: SIMPLE_ESCAPES[c] ?? c, consumed: 1 };
}

/**
 * Tokenize an awk program, or return null when it cannot be read.
 *
 * An unterminated string or regex returns null rather than a best guess: the
 * remainder of the program would be lexed in the wrong mode, and a wrong mode is
 * how a `system()` call hides. Failing closed there is the whole point.
 */
function lex(source: string): Token[] | null {
  const tokens: Token[] = [];
  let i = 0;
  const n = source.length;

  while (i < n) {
    const c = source[i];

    if (c === '\n') { tokens.push({ k: 'nl' }); i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
    // A backslash-newline is a continuation: it joins the lines rather than
    // terminating the statement, so no `nl` token is emitted.
    if (c === '\\' && source[i + 1] === '\n') { i += 2; continue; }
    if (c === '#') { while (i < n && source[i] !== '\n') i++; continue; }

    if (c === '"') {
      let value = '';
      i++;
      while (i < n && source[i] !== '"') {
        if (source[i] === '\\') {
          if (i + 1 >= n) return null;
          const escape = readEscape(source, i + 1);
          value += escape.value;
          i += 1 + escape.consumed;
          continue;
        }
        // A bare newline inside a string is not legal awk, and treating it as
        // one would let the rest of the program be read as string content.
        if (source[i] === '\n') return null;
        value += source[i];
        i++;
      }
      if (i >= n) return null;
      i++;
      tokens.push({ k: 'str', v: value });
      continue;
    }

    if (c === '/' && regexCanStart(tokens[tokens.length - 1])) {
      i++;
      let inBracket = false;
      while (i < n) {
        const r = source[i];
        if (r === '\\') { i += 2; continue; }
        if (r === '\n') return null;
        // A `/` inside a bracket expression is literal — `/[/]/` is a valid
        // regex matching a slash, and ending the token there would leave the
        // rest of the program lexed as code that is really pattern text.
        if (r === '[') inBracket = true;
        else if (r === ']') inBracket = false;
        else if (r === '/' && !inBracket) break;
        i++;
      }
      if (i >= n) return null;
      i++;
      tokens.push({ k: 'regex' });
      continue;
    }

    if (DIGIT.test(c) || (c === '.' && DIGIT.test(source[i + 1] ?? ''))) {
      while (i < n && /[0-9.eExXa-fA-F+-]/.test(source[i])) {
        // `1e+5` continues, but `1+5` is two tokens and an operator.
        if ((source[i] === '+' || source[i] === '-') && !/[eE]/.test(source[i - 1] ?? '')) break;
        i++;
      }
      tokens.push({ k: 'num' });
      continue;
    }

    if (IDENT_START.test(c)) {
      const start = i;
      while (i < n && IDENT_PART.test(source[i])) i++;
      tokens.push({ k: 'word', v: source.slice(start, i) });
      continue;
    }

    const candidates = OPERATORS_BY_FIRST.get(c);
    const op = candidates?.find((o) => source.startsWith(o, i));
    if (op !== undefined) { tokens.push({ k: 'punct', v: op }); i += op.length; continue; }

    tokens.push({ k: 'punct', v: c });
    i++;
  }

  return tokens;
}

/**
 * Walk the tokens and record what the program does.
 *
 * The output-statement state is the whole reason this is a parser rather than a
 * scan: `>` is a redirection only while an unparenthesised `print`/`printf`
 * argument list is open, which is why `awk 'NR>1'` compares and
 * `awk '{print $1 > $2}'` writes.
 */
function walk(tokens: Token[]): AwkFindings {
  const commands: string[] = [];
  const pipedInto: string[] = [];
  let writesFile = false;
  let unreadable = false;

  let depth = 0;
  /** Paren depth at which an output statement is open; -1 when none is. */
  let printDepth = -1;

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];

    if (t.k === 'punct') {
      if (t.v === '(' || t.v === '[') { depth++; continue; }
      if (t.v === ')' || t.v === ']') {
        depth--;
        if (printDepth >= 0 && depth < printDepth) printDepth = -1;
        continue;
      }
      // A statement boundary closes any open output statement.
      if (t.v === '{' || t.v === '}' || t.v === ';') { printDepth = -1; continue; }

      // gawk's indirect call (`f="system"; @f("sudo id")`) and its `@load` /
      // `@include` directives. What `@` reaches is chosen at run time or lives
      // in another file, so neither is readable from here.
      if (t.v === '@') { unreadable = true; continue; }

      if (printDepth >= 0 && depth === printDepth) {
        if (t.v === '>' || t.v === '>>') {
          const target = tokens[i + 1];
          // A literal target can be recognised as a terminal; anything computed
          // is a file write whose name is not known here, which is still a file
          // write.
          if (!(target?.k === 'str' && NON_FILE_TARGETS.has(target.v))) writesFile = true;
          printDepth = -1;
          continue;
        }
        if (t.v === '|' || t.v === '|&') {
          // A single literal, with nothing concatenated onto it. awk joins
          // adjacent strings into the command it runs, so reading only the first
          // classified a *shorter* command than the one that executes — the one
          // shape in this module that could lower a class rather than raise it.
          // Measured: `print "x" | "id" "; sudo sh"` came out `safe`.
          const target = tokens[i + 1];
          const after = tokens[i + 2];
          if (target?.k === 'str' && after?.k !== 'str' && after?.k !== 'word') {
            pipedInto.push(target.v);
          } else {
            unreadable = true;
          }
          printDepth = -1;
          continue;
        }
      }

      // `"cmd" | getline` runs a command outside any output statement, so it is
      // read here rather than in the block above.
      if (t.v === '|' || t.v === '|&') {
        const after = tokens[i + 1];
        if (after?.k === 'word' && after.v === 'getline') {
          const before = tokens[i - 1];
          const earlier = tokens[i - 2];
          // Same single-literal rule as the print pipe above: `"sudo" " id" |
          // getline` runs `sudo id`, and reading only the last literal classified
          // ` id`.
          if (before?.k === 'str' && earlier?.k !== 'str' && earlier?.k !== 'word') {
            commands.push(before.v);
          } else {
            unreadable = true;
          }
        }
      }
      continue;
    }

    if (t.k === 'nl') { printDepth = -1; continue; }

    if (t.k === 'word') {
      if (t.v === 'print' || t.v === 'printf') { printDepth = depth; continue; }
      if (t.v === 'system') {
        const open = tokens[i + 1];
        if (open?.k !== 'punct' || open.v !== '(') continue;
        const arg = tokens[i + 2];
        const close = tokens[i + 3];
        // Only a single string literal is readable. `system("rm " f)` is a real
        // shell command whose text is assembled at run time, and guessing at it
        // would be worse than saying it cannot be read.
        if (arg?.k === 'str' && close?.k === 'punct' && close.v === ')') commands.push(arg.v);
        else unreadable = true;
        continue;
      }
    }
  }

  return { commands, pipedInto, writesFile, unreadable };
}

/**
 * Read an awk invocation's arguments and report what its program does.
 *
 * `args` are the words after the command word, already unquoted by the caller's
 * tokenizer. Returns null when the invocation runs no program at all — `awk`
 * alone, or `awk --version` — which is not the same as finding nothing
 * dangerous in one.
 */
export function readAwkInvocation(args: readonly string[]): AwkFindings | null {
  let i = 0;
  while (i < args.length) {
    const word = args[i];

    if (word === '--') { i++; break; }
    // A bare `-` is stdin as a data file, not a flag.
    if (word === '-' || !word.startsWith('-')) break;
    if (INFO_FLAGS.has(word)) { i++; continue; }

    const flag = word.slice(0, 2);
    if (VALUE_FLAGS.has(flag)) {
      // `-f prog.awk` puts the program in a file this process cannot read, and
      // `-f-` reads it from stdin, which is no more readable.
      if (flag === '-f') return unreadable();
      // Separate value (`-F ':'`) consumes the next word; attached (`-F:`) does not.
      i += word.length === 2 ? 2 : 1;
      continue;
    }

    // Every other flag: see the module comment. The implementations disagree
    // about whether it consumes the next word, so which operand is the program
    // is no longer knowable, and guessing is what opened two of the five holes.
    return unreadable();
  }

  const program = args[i];
  if (program === undefined) return null;

  // Bounded before lexing. The per-call cost is linear, but linear over an
  // unbounded input is still a stall on the one thread that serves every tool
  // call: with `commandMaxChars = 0` — the config spelling of unlimited — a 1MB
  // program of `system()` calls measured 2.1s. The default cap of 5000 chars
  // keeps this unreachable; an operator who lifted it gets a prompt instead of a
  // pause, which is the answer this module already gives for "we cannot read it".
  if (program.length > MAX_PROGRAM_CHARS) return unreadable();

  const tokens = lex(program);
  if (tokens === null) return unreadable();
  return walk(tokens);
}
