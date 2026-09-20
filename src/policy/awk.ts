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
 *    the three flags all four agree on are skipped, and any other flag makes the
 *    program's position unknowable, which is reported as `unreadable`.
 *
 * The rest is a small lexer. It exists because the escapes cannot be found with
 * a regex: `awk 'NR>1'` and `awk '{print $1 > $2}'` differ only in whether the
 * `>` follows an output statement, which is exactly awk's own rule and is why
 * `print (a>b)` needs its parentheses. Three of the five earlier holes were in a
 * regex trying to approximate that, and a fourth was the quadratic backtracking
 * that approximation needed.
 *
 * Single pass, no backtracking: a 192KB program of repeated `print` tokens is
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

/** Flags that take no value and run no program, so `awk --version` stays quiet. */
const INFO_FLAGS = new Set(['--version', '--help']);

/**
 * Redirection targets that are not a file write.
 *
 * `print > "/dev/stderr"` is an ordinary idiom for separating diagnostics from
 * output, and gating it would put a prompt on scripts that write nothing.
 */
const NON_FILE_TARGETS = new Set(['/dev/stdout', '/dev/stderr', '/dev/null', '/dev/fd/1', '/dev/fd/2']);

/** Fresh objects rather than shared constants: `commands` is an array a caller could push to. */
const nothing = (): AwkFindings => ({ commands: [], writesFile: false, unreadable: false });
const unreadable = (): AwkFindings => ({ commands: [], writesFile: false, unreadable: true });

type Token =
  | { k: 'word'; v: string }
  | { k: 'num' }
  | { k: 'str'; v: string }
  | { k: 'regex' }
  | { k: 'punct'; v: string }
  | { k: 'nl' };

/** Operators that are two or three characters, longest first so `>>` beats `>`. */
const OPERATORS = [
  '**=', '>>=',
  '|&', '&&', '||', '==', '!=', '<=', '>=', '>>', '++', '--',
  '+=', '-=', '*=', '/=', '%=', '^=', '!~', '**',
];

/** Words after which an operand is expected, so a `/` opens a regex. */
const AWK_KEYWORDS = new Set([
  'print', 'printf', 'if', 'while', 'do', 'for', 'return', 'delete', 'getline',
  'case', 'else', 'in', 'BEGIN', 'END', 'function', 'func', 'exit', 'next',
  'and', 'or', 'not', 'match', 'split', 'sub', 'gsub', 'gensub',
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

/**
 * Decode an awk string literal's escapes.
 *
 * Only the ones that change which bytes reach a shell matter here, and the rest
 * are passed through as themselves — awk's own behaviour for an unknown escape.
 */
function decodeEscape(char: string): string {
  switch (char) {
    case 'n': return '\n';
    case 't': return '\t';
    case 'r': return '\r';
    case '\\': return '\\';
    case '"': return '"';
    case '/': return '/';
    case 'a': return '\x07';
    case 'b': return '\b';
    case 'f': return '\f';
    case 'v': return '\v';
    default: return char;
  }
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
          value += decodeEscape(source[i + 1]);
          i += 2;
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

    const three = source.slice(i, i + 3);
    const two = source.slice(i, i + 2);
    const op = OPERATORS.find((o) => o === three) ?? OPERATORS.find((o) => o === two);
    if (op !== undefined) { tokens.push({ k: 'punct', v: op }); i += op.length; continue; }

    tokens.push({ k: 'punct', v: c });
    i++;
  }

  return tokens;
}

/** The token after `at`, skipping nothing — awk's grammar is not newline-insensitive. */
function next(tokens: Token[], at: number): Token | undefined {
  return tokens[at + 1];
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
          const target = next(tokens, i);
          // A literal target can be recognised as a terminal; anything computed
          // is a file write whose name is not known here, which is still a file
          // write.
          if (!(target?.k === 'str' && NON_FILE_TARGETS.has(target.v))) writesFile = true;
          printDepth = -1;
          continue;
        }
        if (t.v === '|' || t.v === '|&') {
          const target = next(tokens, i);
          if (target?.k === 'str') commands.push(target.v);
          else unreadable = true;
          printDepth = -1;
          continue;
        }
      }

      // `"cmd" | getline` runs a command outside any output statement, so it is
      // read here rather than in the block above.
      if (t.v === '|' || t.v === '|&') {
        const after = next(tokens, i);
        if (after?.k === 'word' && after.v === 'getline') {
          const before = tokens[i - 1];
          if (before?.k === 'str') commands.push(before.v);
          else unreadable = true;
        }
      }
      continue;
    }

    if (t.k === 'nl') { printDepth = -1; continue; }

    if (t.k === 'word') {
      if (t.v === 'print' || t.v === 'printf') { printDepth = depth; continue; }
      if (t.v === 'system') {
        const open = next(tokens, i);
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

  return { commands, writesFile, unreadable };
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

  const tokens = lex(program);
  if (tokens === null) return unreadable();
  const findings = walk(tokens);
  return findings.commands.length === 0 && !findings.writesFile && !findings.unreadable
    ? nothing()
    : findings;
}
