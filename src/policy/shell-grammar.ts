/**
 * Reads a command line the way a shell's grammar does, and returns it with that
 * grammar removed.
 *
 * The classifier decides everything from a segment's command word, and a segment is what
 * its tokeniser cuts at `; & |` and newline. The shell puts commands in other places: in
 * a subshell or a brace group, after a reserved word, in a function body or a `case` arm,
 * behind a redirection. There the "command word" is `(`, `then` or `>/dev/null`, which
 * names no binary, and the command that runs was never looked at.
 *
 * This file does not classify anything and knows no binary. It answers one question —
 * which words are commands — and hands back plain text the classifier already knows how
 * to read: `if a; then (b | c) >f; fi` becomes `a; b | c`. The classifier reads that
 * string beside its own reading of the original and keeps the higher class, so a mistake
 * here can add a command that is not really run, or miss one, but cannot take away
 * anything the classifier saw before.
 *
 * Not a shell parser: nothing is expanded and nothing is validated. Input a shell would
 * reject (an unclosed group, `case` without `esac`) returns what was read up to there.
 * It does not recurse and does not throw.
 */
export type GrammarDialect = 'posix' | 'windows';

export interface GrammarReading {
  /** The command with the shell's grammar removed, or null when it holds none. */
  flattened: string | null;
  /**
   * The same for the other ways a shell may read the line, when they differ. And where
   * the quoting is one the classifier's tokeniser does not read the same way (`$'…'`,
   * a `'` inside `"${…}"`), the line's pipelines one by one, so that a quote the
   * tokeniser thinks open in one cannot run over the next.
   */
  alternates: string[];
  /**
   * The line read with nothing left out: every operator and every parenthesis ends a
   * command, and what stands between two is a command — a `case` pattern, an array's
   * elements, the inside of `[[ … ]]` included. Which words are patterns and which
   * parentheses are subshells is exactly what the shells disagree on (`case` is a
   * program name after `time` in dash, in cmd.exe always; `[[` is one in dash), and
   * the reading above has to decide. This one does not, so nothing can hide from it;
   * the classifier uses it for what a command is by name, not for what it cannot name.
   */
  loose: string[];
  /**
   * For a line with a substitution that holds a `case` and an `esac` to end it (or the
   * `}` that ends zsh's `case x { … }`): the line
   * from that substitution to its last `)`, read with no span and no quote at all, quote
   * characters left out. A pattern's `)` ends such a substitution early for every scan
   * that counts parentheses, and inside a quoted word nothing else reads what follows;
   * which `)` is a pattern's is again what the shells disagree on. Where the substitution
   * does end is one of the parentheses after it, so nothing past the last is inside it.
   * Asked by name, like `loose`, and not read any further.
   */
  plain: string[];
  /**
   * Whether an opener of a substitution stands in the line with a `case WORD in` (or
   * zsh's `case WORD {`) anywhere behind it, in the substitution or after it: the two
   * cannot be told apart. Where such a substitution ends is what no reading here can
   * say, so the classifier does not call such a line `safe` whatever `plain` finds in it.
   */
  holdsCase: boolean;
  /** The word of every here-string on the line, as written. */
  hereStrings: string[];
  /**
   * The commands of `flattened` in order, each with what joins it to the one before,
   * whether a pipe reaches it without standing next to it (`x | { a; b; }` feeds `b`
   * too), and, for one a pipe leads to, the index of the first command of what that
   * pipe carries: in `{ a; b; } | c` both `a` and `b` feed `c`.
   */
  commands: FlatCommand[];
  /** The same for each other way of reading the line in which a pipe feeds a group. */
  otherCommands: FlatCommand[][];
  /**
   * Command text inside a substitution: `$(…)`, `<(…)` and `>(…)` — which the
   * classifier scans for too, but by counting parentheses, quoted ones included — and
   * the two it has no scan for, zsh's `=(cmd)` and the `${ cmd; }` of bash 5.3.
   */
  substitutions: string[];
  /**
   * Words with an unquoted glob or brace expansion, as written. Where one is a command
   * word the shell rewrites it before running anything, so it names no program.
   */
  expandingWords: string[];
  /** The names of the functions the line defines: a pipe to one reaches its body. */
  functionNames: string[];
}

export interface FlatCommand {
  text: string;
  join: string;
  fed: boolean;
  from: number;
}

type OpKind = ';' | '|' | 'arm' | '(' | ')' | 'redirect' | 'here-string';

interface Token {
  /** `word`, or the operator it is. */
  kind: 'word' | OpKind;
  start: number;
  end: number;
  /** A word holding an unquoted `*`, `?`, `[` or a brace expansion. */
  expands?: boolean;
}

/** How a line is read where the shells differ. */
interface Options {
  /** `$'…'` is a quoting with backslash escapes (bash, zsh, ksh), not `$` and a plain quote (dash). */
  ansi: boolean;
  /** `#` at the start of a word begins a comment (not in an interactive zsh, nor in cmd.exe). */
  comments: boolean;
  /** Inside `"${x:-…}"` a `'` is a quote (bash) and not a character (dash, POSIX). */
  quoteInBrace: boolean;
  /** `$[ … ]` and the subscript of `name[ … ]=` are one word (bash, zsh, ksh), not characters (dash). */
  subscripts: boolean;
}

interface Lexing extends Options {
  dialect: GrammarDialect;
  honorQuotes: boolean;
  /**
   * For the reading that leaves nothing out: only a span whose inside is read as a
   * command of its own (`$(…)`, backticks, `<(…)`, `${ …; }`) is one word, and only
   * when it closes. A parameter expansion, arithmetic, a subscript and a span left open
   * are characters, so an operator inside them still ends a command — they are spans to
   * some shells and not to others (dash has no `$[ … ]` and no subscripts, cmd.exe none
   * of them, and PowerShell's backtick is an escape).
   */
  loose?: boolean;
  /**
   * With `loose`: no span is one word at all. For a line with a substitution that holds
   * a `case`, where no count of parentheses says where the substitution ends.
   */
  plain?: boolean;
}

interface Lexed {
  tokens: Token[];
  sawComment: boolean;
  /** A bracket was read to its close as one word. */
  sawSubscript: boolean;
  /** Where the first substitution that holds a `case`, with an `esac` after it, starts; or -1. */
  caseFrom: number;
  openQuote: boolean;
  /** `[start, end)` of the command text inside each substitution. */
  substitutions: Array<[number, number]>;
}

const ALL_DIGITS = /^\d+$/;
/**
 * The word `case` in a substitution's text. Not only where a command starts: after
 * `time` or `builtin` it is still a statement for bash, and its pattern's `)` still
 * ends the substitution early for every scan that counts parentheses.
 */
const HOLDS_CASE = /(?:^|[\s;()|&{`])case\s/;
/** From a `case` statement's `esac` to the `)` that ends the substitution it stands in. */
const ESAC = /\besac\b/g;
/** bash's `{name}>file`: the braces name the descriptor, they are not a command word. */
const NAMED_DESCRIPTOR = /^\{[A-Za-z_][A-Za-z0-9_]*\}$/;

/** The index of the backtick that closes the one at `open`, or `command.length`. */
function closingBacktick(command: string, open: number, dialect: GrammarDialect): number {
  const n = command.length;
  for (let i = open + 1; i < n; i++) {
    if (dialect === 'posix' && command[i] === '\\') { i++; continue; }
    if (command[i] === '`') return i;
  }
  return n;
}

/**
 * Whether the `'` at `i` opens a `$'…'` string: after a `$` that is neither escaped nor
 * the second half of `$$`. Runs are counted, not single characters: in `\\$'` the
 * backslash is itself escaped, and in `$$$'` the first two are the process id.
 */
function isAnsiQuote(command: string, i: number, dialect: GrammarDialect): boolean {
  if (dialect !== 'posix') return false;
  let dollars = 0;
  let at = i - 1;
  while (at >= 0 && command[at] === '$') { dollars++; at--; }
  let backslashes = 0;
  while (at >= 0 && command[at] === '\\') { backslashes++; at--; }
  if (backslashes % 2 === 1) dollars--;
  return dollars % 2 === 1;
}

/** The index of the `'` that closes a `$'…'` string opened at `open`, where `\'` is an escape. */
function closingAnsiQuote(command: string, open: number): number {
  const n = command.length;
  for (let i = open + 1; i < n; i++) {
    if (command[i] === '\\') { i++; continue; }
    if (command[i] === "'") return i;
  }
  return n;
}

const enum Span { Paren, Substitution, Brace, DoubleQuote }
// `Substitution` is a `$(`; a `${ cmd; }` is a `Brace` whose text position is recorded.

/**
 * The index of the character that closes the span opened at `open`, or `command.length`.
 *
 * `open` is the `(` of a `$(…)`, the `{` of a `${…}` or an opening `"`. Each nests the
 * others and starts a quoting context of its own: the `"` in `"$(echo ")")"` belongs to
 * the inner command, and the `}` in `${x:-'}'}` is quoted. Getting either wrong moves
 * where every later quote is thought to open, which hides a group behind what looks like
 * a quoted word. Kept on an explicit stack: nesting is attacker-controlled depth.
 *
 * `found` is told the inside of every command substitution that is not itself inside
 * one, so that one in a double-quoted word is read like one that stands alone.
 */
function closingOf(command: string, open: number, first: Span, how: Lexing, found?: (from: number, to: number) => void): number {
  const n = command.length;
  const stack: Span[] = [first];
  /** For each open span, where its command text starts when it is a substitution, else -1. */
  const text: number[] = [first === Span.Substitution ? open + 1 : -1];
  let substitutions = first === Span.Substitution ? 1 : 0;
  const pop = (at: number): boolean => {
    stack.pop();
    const from = text.pop() as number;
    if (from !== -1 && --substitutions === 0 && found !== undefined && stack.length > 0) found(from, at);
    return stack.length === 0;
  };
  for (let i = open + 1; i < n; i++) {
    const ch = command[i];
    const top = stack[stack.length - 1];
    if (how.dialect === 'posix' && ch === '\\') { i++; continue; }
    if (ch === '`') { i = closingBacktick(command, i, how.dialect); continue; }
    if (ch === '$' && (command[i + 1] === '(' || command[i + 1] === '{')) {
      const after = command[i + 2];
      if (command[i + 1] === '(' && command[i + 2] === '(') {
        // `$(( … ))`: arithmetic. What it holds is found when a `$(` inside it is met.
        stack.push(Span.Paren);
        text.push(-1);
      } else if (command[i + 1] === '(') {
        stack.push(Span.Substitution);
        text.push(i + 2);
        substitutions++;
      } else if (after === ' ' || after === '\t' || after === '\n' || after === '|') {
        // `${ cmd; }` and `${| cmd; }`: a command substitution closed by a brace.
        stack.push(Span.Brace);
        text.push(i + 3);
        substitutions++;
      } else {
        stack.push(Span.Brace);
        text.push(-1);
      }
      i++;
      continue;
    }
    if (top === Span.DoubleQuote) {
      if (ch === '"' && pop(i)) return i;
      continue;
    }
    // Inside `"${x:-…}"`, at any depth, a single quote is a character to dash and a
    // quote to bash: `quoteInBrace` says which reading this is.
    if (how.honorQuotes && ch === "'" && !(top === Span.Brace && !how.quoteInBrace && stack.includes(Span.DoubleQuote))) {
      const close = how.ansi && isAnsiQuote(command, i, how.dialect)
        ? closingAnsiQuote(command, i)
        : command.indexOf("'", i + 1);
      if (close === -1) return n;
      i = close;
      continue;
    }
    if (how.honorQuotes && ch === '"') { stack.push(Span.DoubleQuote); text.push(-1); continue; }
    if (top === Span.Brace) {
      // A bare `{` is a character here: `${x#{}` ends at its first `}`.
      if (ch === '}' && pop(i)) return i;
    } else if (ch === '(') { stack.push(Span.Paren); text.push(-1); } else if (ch === ')' && pop(i)) return i;
  }
  return n;
}

/** A name, as the word before a subscript. */
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** The index of the `]` that closes the `[` at `open`, quoting honoured, or `command.length`. */
function closingBracket(command: string, open: number, how: Lexing): number {
  const n = command.length;
  let depth = 0;
  for (let i = open; i < n; i++) {
    const ch = command[i];
    if (how.dialect === 'posix' && ch === '\\') { i++; continue; }
    if (how.honorQuotes && (ch === "'" || ch === '"')) {
      const close = command.indexOf(ch, i + 1);
      if (close === -1) return n;
      i = close;
      continue;
    }
    if (ch === '[') depth++;
    else if (ch === ']' && --depth === 0) return i;
  }
  return n;
}

/**
 * A here-document delimiter as the shell compares it: the word with its quoting
 * removed. Inside quotes the other quote character and a backslash are kept.
 */
function heredocDelimiter(word: string): string {
  let out = '';
  let quote: string | null = null;
  for (let i = 0; i < word.length; i++) {
    const ch = word[i];
    if (quote === null) {
      if (ch === "'" || ch === '"') quote = ch;
      else if (ch === '\\' && i + 1 < word.length) out += word[++i];
      else out += ch;
    } else if (ch === quote) quote = null;
    else if (quote === '"' && ch === '\\' && (word[i + 1] === '"' || word[i + 1] === '\\' || word[i + 1] === '$' || word[i + 1] === '`')) out += word[++i];
    else out += ch;
  }
  return out;
}

/** One pass over the characters: words and operators, with quoting already decided. */
function lex(command: string, how: Lexing): Lexed {
  const { dialect, honorQuotes } = how;
  const n = command.length;
  const tokens: Token[] = [];
  let sawComment = false;
  let sawSubscript = false;
  let caseFrom = -1;
  /** Where a `case` statement can end at the latest: `esac`, or the `}` of zsh's `case x { … }`. */
  let lastEnd: number | undefined;
  let openQuote = false;
  let wordStart = -1;
  const substitutions: Array<[number, number]> = [];
  // The classifier's own scan ends a `$(…)` at a `case` pattern's `)`, and so does the
  // one here. Where a substitution holds a `case`, the text up to the `)` that follows
  // its `esac` is read as well.
  let caseAlternate = false;
  /** From here on no `esac` is followed by a `)`: looked for once, not once per substitution. */
  let noEsacFrom = n + 1;
  const substitution = (from: number, to: number) => {
    // One that never closes is a syntax error, not a command the shell runs.
    if (to >= n) return;
    substitutions.push([from, to]);
    // With nothing after it to end the statement it is a syntax error, and the shell
    // runs nothing.
    if (caseFrom === -1 && HOLDS_CASE.test(command.slice(from, to))) {
      lastEnd ??= Math.max(command.lastIndexOf('esac'), command.lastIndexOf('}'));
      if (lastEnd > from) caseFrom = from;
    }
    // Once per line: the text it adds holds every later substitution already.
    if (!caseAlternate && to < noEsacFrom && HOLDS_CASE.test(command.slice(from, to))) {
      // Up to the `)` after its `esac`. With no `esac` to end it the statement is a
      // syntax error, and there is nothing more to read.
      ESAC.lastIndex = to;
      const esac = ESAC.exec(command);
      const closing = esac === null ? -1 : command.indexOf(')', esac.index + 4);
      if (closing === -1) noEsacFrom = to;
      else {
        caseAlternate = true;
        substitutions.push([from, closing]);
      }
    }
  };
  let expands = false;
  let braceOpen = false;
  let braceSeparated = false;
  const loose = how.loose === true;
  // What the search for closing brackets may read in all. A line of `$[` or `a[` that
  // never close made each one a scan to the end of the line; past this the bracket is an
  // ordinary character, which is the reading that leaves nothing out.
  let bracketBudget = 8 * n + 64;
  // Likewise for the reading that leaves nothing out, where a span that does not close
  // is characters: each such search reads to the end of the line. Past this a span
  // opener is a character without looking.
  let openBudget = how.plain === true ? 0 : 8 * n + 64;
  /** Whether the span opened at `from` and closed at `close` is one word there. */
  const spans = (from: number, close: number): boolean => {
    if (!loose || close < n) return true;
    openBudget -= n - from;
    return false;
  };

  // Here-documents announced on this line: their bodies start after its newline.
  let heredocs: Array<{ delimiter: string; stripTabs: boolean }> = [];
  let heredocOperator: string | null = null;

  const startWord = (i: number) => { if (wordStart === -1) wordStart = i; };
  const endWord = (end: number) => {
    if (wordStart === -1) return;
    tokens.push({ kind: 'word', start: wordStart, end, expands });
    expands = false;
    braceOpen = false;
    braceSeparated = false;
    if (heredocOperator !== null) {
      heredocs.push({ delimiter: heredocDelimiter(command.slice(wordStart, end)), stripTabs: heredocOperator === '<<-' });
      heredocOperator = null;
    }
    wordStart = -1;
  };
  const op = (kind: OpKind, start: number, end: number) => {
    heredocOperator = null;
    tokens.push({ kind, start, end });
  };

  for (let i = 0; i < n; i++) {
    const ch = command[i];

    if (ch === '\n') {
      endWord(i);
      // A here-document's body is data for the command it feeds, not command lines. The
      // classifier's own reading still sees those lines as it always did; this one must
      // not find grammar in them (`> quoted mail`, `<p>`, `(an aside)` in a README).
      for (const { delimiter, stripTabs } of heredocs) {
        let lineStart = i + 1;
        for (;;) {
          let lineEnd = command.indexOf('\n', lineStart);
          if (lineEnd === -1) lineEnd = n;
          let line = command.slice(lineStart, lineEnd);
          if (stripTabs) line = line.replace(/^\t+/, '');
          i = lineEnd;
          if (line === delimiter || lineEnd === n) break;
          lineStart = lineEnd + 1;
        }
      }
      heredocs = [];
      if (i < n) op(';', i, i + 1);
      continue;
    }
    // Space and tab only. A shell does not break a word at a vertical tab or a form
    // feed, so `x<VT>#` is one word there and must not start a comment here.
    if (ch === ' ' || ch === '\t') { endWord(i); continue; }

    if (dialect === 'posix' && ch === '\\') { startWord(i); i++; continue; }
    if (honorQuotes && ch === "'") {
      const ansiQuote = how.ansi && wordStart !== -1 && isAnsiQuote(command, i, dialect);
      startWord(i);
      const close = ansiQuote ? closingAnsiQuote(command, i) : command.indexOf("'", i + 1);
      if (close === -1 || close === n) { openQuote = true; i = n; } else i = close;
      continue;
    }
    if (honorQuotes && ch === '"') {
      startWord(i);
      i = closingOf(command, i, Span.DoubleQuote, how, substitution);
      if (i === n) openQuote = true;
      continue;
    }
    if (ch === '`') {
      const close = loose && openBudget <= 0 ? n : closingBacktick(command, i, dialect);
      if (spans(i, close)) { startWord(i); i = close; continue; }
    } else if (ch === '$' && (command[i + 1] === '(' || command[i + 1] === '{')) {
      startWord(i);
      const open = i + 1;
      if (loose) {
        // The `$` is a character; what follows it is read where it stands, unless it
        // is a substitution that closes.
        const after = command[open + 1];
        const holdsCommand = command[open] === '(' ? after !== '(' : after === ' ' || after === '\t' || after === '\n' || after === '|';
        if (!holdsCommand || openBudget <= 0) continue;
        const close = closingOf(command, open, command[open] === '(' ? Span.Substitution : Span.Brace, how);
        if (spans(i, close)) i = close;
        continue;
      }
      if (command[open] === '(' && command[open + 1] === '(') {
        // `$(( … ))` is arithmetic, and the classifier's own scan leaves it alone on
        // purpose. Only what a `$(` inside it holds is a command — unless it does not
        // end in `))`, where bash falls back to a substitution holding a subshell.
        i = closingOf(command, open, Span.Paren, how, substitution);
        if (command[i - 1] !== ')') substitution(open + 1, i);
      } else if (command[open] === '(') {
        i = closingOf(command, open, Span.Substitution, how);
        substitution(open + 1, i);
      } else {
        // `${ cmd; }` and `${| cmd; }`: a command substitution, not a parameter. What
        // it holds is found when its own text is read, so nothing inside is reported.
        const after = command[open + 1];
        if (after === ' ' || after === '\t' || after === '\n' || after === '|') {
          i = closingOf(command, open, Span.Brace, how);
          substitution(open + 2, i);
        } else i = closingOf(command, open, Span.Brace, how, substitution);
      }
      continue;
    }
    if (((ch === '<' || ch === '>') && command[i + 1] === '(') || (ch === '=' && command[i + 1] === '(' && wordStart === -1)) {
      // Process substitution, and zsh's `=(cmd)`: part of a word, whose inside is a
      // command of its own.
      const open = i + 1;
      const close = loose && openBudget <= 0 ? n : closingOf(command, open, Span.Substitution, how);
      if (spans(i, close)) {
        startWord(i);
        i = close;
        substitution(open + 1, i);
        continue;
      }
    }

    if (!loose && how.subscripts && bracketBudget > 0 && ch === '[' && (command[i - 1] === '$' || (wordStart !== -1 && IDENTIFIER.test(command.slice(wordStart, i))))) {
      // bash reads `$[ … ]` and the subscript of `name[ … ]=` to the matching bracket,
      // operators and all: `a[;;]=1` is one word. Only when it does close, and for a
      // subscript only when an assignment follows — else `[` is an ordinary character.
      const close = closingBracket(command, i, how);
      bracketBudget -= close - i + 1;
      const assigns = command[close + 1] === '=' || (command[close + 1] === '+' && command[close + 2] === '=');
      if (close < n && (command[i - 1] === '$' || assigns)) {
        sawSubscript = true;
        startWord(i);
        i = close;
        continue;
      }
    }

    if (how.comments && ch === '#' && wordStart === -1) {
      sawComment = true;
      const eol = command.indexOf('\n', i);
      i = eol === -1 ? n : eol - 1;
      continue;
    }

    if (ch === ';') {
      endWord(i);
      if (command[i + 1] === ';') {
        const end = command[i + 2] === '&' ? i + 3 : i + 2;
        op('arm', i, end);
        i = end - 1;
      } else if (command[i + 1] === '&') {
        op('arm', i, i + 2);
        i++;
      } else op(';', i, i + 1);
      continue;
    }
    if (ch === '&') {
      // `&&` is two of these and `&>` is this and a redirection: the same commands either way.
      endWord(i);
      op(';', i, i + 1);
      continue;
    }
    if (ch === '|') {
      endWord(i);
      if (command[i + 1] === '|') { op(';', i, i + 2); i++; } else if (command[i + 1] === '&') { op('|', i, i + 2); i++; } else op('|', i, i + 1);
      continue;
    }
    if (ch === '<' || ch === '>') {
      // Glued to the operator, a run of digits or a `{name}` is its descriptor, not a word.
      if (wordStart !== -1) {
        const glued = command.slice(wordStart, i);
        if (ALL_DIGITS.test(glued) || NAMED_DESCRIPTOR.test(glued)) wordStart = -1;
      }
      endWord(i);
      let end = i + 1;
      let kind: OpKind = 'redirect';
      let heredoc: string | null = null;
      if (ch === '<') {
        if (command.startsWith('<<<', i)) { end = i + 3; kind = 'here-string'; } else if (command[i + 1] === '<') {
          heredoc = command[i + 2] === '-' ? '<<-' : '<<';
          end = i + heredoc.length;
        } else if (command[i + 1] === '>' || command[i + 1] === '&') end = i + 2;
      } else if (command[i + 1] === '>' || command[i + 1] === '|' || command[i + 1] === '&') end = i + 2;
      op(kind, i, end);
      heredocOperator = heredoc;
      i = end - 1;
      continue;
    }
    if (ch === '(' || ch === ')') {
      endWord(i);
      op(ch, i, i + 1);
      continue;
    }

    startWord(i);
    if (ch === '*' || ch === '?' || ch === '[') expands = true;
    else if (ch === '{') braceOpen = true;
    else if (braceOpen && (ch === ',' || (ch === '.' && command[i - 1] === '.'))) braceSeparated = true;
    else if (ch === '}' && braceSeparated) expands = true;
  }
  endWord(n);
  return { tokens, sawComment, sawSubscript, caseFrom, openQuote, substitutions };
}

/**
 * Words that are dropped where a command could start, leaving what follows them in
 * command position. Reserved words, the words that only pass a command on (`time`,
 * `coproc`, `builtin`), and zsh's precommand modifiers and `always`.
 *
 * Dropping one never hides a command: at worst the word was a program of that name, and
 * what is read instead is that program's arguments as a command.
 */
const DROPPED_HEADS = new Set([
  'if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'do', 'done', '!', 'time', 'coproc', 'builtin',
  'noglob', 'nocorrect', '-', 'always', '{', '}', 'esac', 'end',
]);
const OPENING_HEADS = new Set(['{', 'if', 'while', 'until']);
// Not zsh's `end`: its `foreach NAME (list)` opens nothing here, and `end` is an
// ordinary word everywhere else.
const CLOSING_HEADS = new Set(['}', 'fi', 'done']);
/**
 * The dropped heads after which every shell still reads `case` as a reserved word. Not
 * `time`, `builtin`, `noglob` and the like: where one of those is a program (dash has
 * no `time` keyword), `case` after it is an argument.
 */
const RESERVED_BEFORE_CASE = new Set(['{', 'if', 'then', 'elif', 'else', 'while', 'until', 'do', '!']);
/** Words that can begin the compound command a `coproc NAME` names. */
const COMPOUND_START = new Set(['{', 'if', 'while', 'until', 'for', 'select', 'case', '[[']);
/**
 * `a[0]=x` and `a+=x`: assignments the classifier does not take for a prefix. The
 * subscript is whatever stands before the `]=`: a bracket of its own (`a[b[0]]=x`), a
 * quoted or an escaped one. Taking a word for an assignment only adds a reading of what
 * follows it.
 */
const OTHER_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*(?:\[[^]*?\]\+?=|\+=)/;
/**
 * Words that hold a glob character and are not a glob: `[` and `[[`, and a few shapes a
 * PowerShell or cmd.exe line is made of. Each is exact, admits no further `*`, `?` or
 * `[`, and cannot name a program in any directory worth worrying about. A `[type]` cast
 * is not among them: as a POSIX word `[s]"udo"` is a glob for `sudo`.
 */
const NOT_A_GLOB = new RegExp(`^(?:${[
  String.raw`\[\[?`,
  // PowerShell's `?` and `%` aliases, bare or glued to a script block on `$_`.
  String.raw`[?%](?:\{(?:\$[^*?\[,]*)?)?`,
  // A static member: `[math]::Round`.
  String.raw`\[[A-Za-z_][\w.]*\]::[^*?\[]*`,
  // A hashtable or array literal.
  String.raw`@[{(][^*?\[]*`,
  // cmd.exe: `if [%1]==[] …`.
  String.raw`\[[^\]*?\[]*\]==\[[^\]*?\[]*\][^*?\[]*`,
  // An index after a group: `(…)[0]`, `[0..4]`, `[0].Name`.
  String.raw`\[-?\d+(?:\.\.-?\d+)?\](?:\.[\w.]*)?`,
].join('|')})$`);
/** A path, as the word before a glued parenthesis: zsh's `/usr/bin/(sudo)` is a glob. */
const PATH_START = /^(?:\.{0,2}|~)\//;

/** For each `(` token the index of the `)` token that closes it, else -1. */
function matchParens(tokens: Token[]): Int32Array {
  const match = new Int32Array(tokens.length).fill(-1);
  const open: number[] = [];
  for (let k = 0; k < tokens.length; k++) {
    if (tokens[k].kind === '(') open.push(k);
    else if (tokens[k].kind === ')') {
      const from = open.pop();
      if (from !== undefined) match[from] = k;
    }
  }
  return match;
}

interface Frame {
  /** A `(`, a word (`{`, `if`, `while`, a loop's `do`), or a `case` statement. */
  kind: 'paren' | 'word' | 'case';
  /** For a `case`: patterns are expected, up to the next `)`. */
  pattern: boolean;
  /** A pipe sends its output into this group or one around it. */
  fed: boolean;
}

interface Reading extends GrammarReading { openQuote: boolean; sawComment: boolean; sawSubscript: boolean; caseFrom: number }

/**
 * Where the command proper starts in `all`, at or after `from`: past the words that are
 * dropped from its head. Says nothing about what those words open or close.
 */
function afterDroppedHeads(command: string, all: Token[], from: number): number {
  let at = from;
  while (at < all.length) {
    const head = command.slice(all[at].start, all[at].end);
    if (DROPPED_HEADS.has(head)) {
      at++;
      if (head === 'time') {
        while (at < all.length && command[all[at].start] === '-') at++;
      } else if (head === 'coproc' && at + 1 < all.length
        && COMPOUND_START.has(command.slice(all[at + 1].start, all[at + 1].end))) at++;
    } else if (head === 'repeat' && all.length - at > 2) at += 2;
    else if (OTHER_ASSIGNMENT.test(head)) at++;
    else break;
  }
  return at;
}

/**
 * One pass over the tokens.
 *
 * The rule that keeps this honest: **nothing is left unread on the word of a keyword
 * the shells do not all agree on.** An earlier version skipped `[[ … ]]` up to `]]`, a
 * `for` header up to `;`, an array's elements, and `case` patterns wherever the word
 * `case` stood, and each skip was a place to put a command: `[[` is a command name in
 * dash, `foreach` is one outside zsh, and `case` is one after a redirection or after
 * `time`. Wherever a shell reads a plain command, the skip hid it.
 *
 * So every operator ends a command — `; & |`, newline, `;;`, `(` and `)` — and whatever
 * stands between two of them is read as a command. That over-reads: a `for` header is
 * "a command named `for`", `[[ -n $x` is "a command named `[[`". Such a command is
 * harmless, because its name is the keyword.
 *
 * Two things are left unread, because no shell runs them:
 *
 *  - the patterns of a `case` that stands where every shell reads it as the reserved
 *    word: first in its command, or after reserved words only, and not behind a
 *    redirection. Anywhere else `case WORD in` is a command named `case`, the `)` of its
 *    "pattern" closes whatever group is open, and the words before it are read;
 *  - what stands in parentheses after the words of a command (`x=(a b)`, `echo a (b)`):
 *    an array's elements, or a syntax error. Empty ones (`f()`) make the words function
 *    names.
 */
function readOnce(command: string, how: Lexing): Reading {
  const lexed = lex(command, how);
  const { tokens } = lexed;
  const match = matchParens(tokens);

  const text = (t: Token) => command.slice(t.start, t.end);

  const commands: string[] = [];
  const joins: string[] = [];
  /** For each command, whether a pipe reaches it without standing next to it. */
  const fedCommands: boolean[] = [];
  /** For each command a pipe leads to, where what the pipe carries begins. */
  const pipedFrom: number[] = [];
  let pipeStart = 0;
  const hereStrings = new Set<string>();
  const expanding = new Set<string>();
  const functionNames = new Set<string>();
  let structural = lexed.sawComment;
  /** Whether the word `case` stands anywhere on the line, as a word of its own. */
  const caseOnLine = tokens.some((t) => t.kind === 'word' && t.end - t.start === 4 && text(t) === 'case');

  let words: Token[] = [];
  /** A redirection came before the first word: no word after one is reserved. */
  let redirected = false;
  /** Where the command proper starts in `words`, once that is known for good. */
  let commandAt = -1;
  let join = '; ';
  let pendingJoin = '; ';
  /** Where the pipeline being read began, as an index into `commands`. */
  let pipelineStart = 0;
  /** A `for`, `select` or `foreach` header was read, behind a pipe or not: its `do` opens the body. */
  let loopHeader: { fed: boolean } | undefined;
  const frames: Frame[] = [];
  const starts: number[] = [];
  /** A `[[` was read and its `]]` not yet: `&&` and `||` split the test into commands. */
  let testOpen = false;

  const top = () => frames[frames.length - 1];
  const inPattern = () => { const frame = top(); return frame !== undefined && frame.kind === 'case' && frame.pattern; };
  const open = (kind: Frame['kind'], fedByPipe: boolean) => {
    const around = top();
    frames.push({ kind, pattern: kind === 'case', fed: fedByPipe || around?.fed === true });
    starts.push(pipelineStart);
    pipelineStart = commands.length;
  };
  const pop = () => {
    frames.pop();
    pipelineStart = starts.pop() as number;
  };
  /** A word closes the frame a word opened, and nothing else. */
  const closeWord = () => { if (top()?.kind === 'word') pop(); };
  /** A `)` closes the nearest subshell and what was left open inside it. */
  const closeParen = () => {
    let at = frames.length - 1;
    while (at >= 0 && frames[at].kind !== 'paren') at--;
    if (at < 0) return;
    while (frames.length > at) pop();
  };

  const emit = (from: Token[]) => {
    // A pipe into a group reaches every command in it, not only the first.
    fedCommands.push(top()?.fed === true && join !== ' | ');
    pipedFrom.push(join === ' | ' ? pipeStart : -1);
    for (const t of from) if (t.expands === true && !NOT_A_GLOB.test(text(t))) expanding.add(text(t));
    const closes = from.some((t) => t.end - t.start === 2 && text(t) === ']]');
    if (text(from[0]) === '[[') testOpen = !closes;
    else if (closes) testOpen = false;
    commands.push(from.map(text).join(' '));
    joins.push(join);
    join = '; ';
    loopHeader = undefined;
  };

  /** Reads `all` as a command: drops its head words, acts on what they open and close. */
  const flush = (all: Token[], behindRedirection: boolean) => {
    const word = (i: number) => text(all[i]);
    // First position of a word at or after an index, found once per word and flush.
    const firsts = new Map<string, Int32Array>();
    const indexOf = (value: string, from: number): number => {
      let next = firsts.get(value);
      if (next === undefined) {
        next = new Int32Array(all.length + 1).fill(-1);
        for (let i = all.length - 1; i >= 0; i--) next[i] = word(i) === value ? i : next[i + 1];
        firsts.set(value, next);
      }
      return from <= all.length ? next[from] : -1;
    };
    // Only the first thing a flush opens stands next to the pipe.
    let fed = join === ' | ';
    const opens = (kind: Frame['kind']) => { open(kind, fed); fed = false; };
    /** Whether every shell reads a `case` here as the reserved word. */
    let reserved = !behindRedirection;

    let at = 0;
    while (at < all.length) {
      const head = word(at);
      // `[[ -n $a && ! -d $b ]]`: inside a test the `!` negates an operand. Dropping it
      // would put the operand in command position, where a variable is "a command this
      // file cannot name". The reading that leaves nothing out still drops it.
      if (testOpen && head === '!') {
        emit(all.slice(at));
        return;
      }
      if (DROPPED_HEADS.has(head) || head === 'repeat' || OTHER_ASSIGNMENT.test(head)) {
        const next = afterDroppedHeads(command, all, at);
        if (next !== at) {
          structural = true;
          for (let i = at; i < next; i++) {
            const dropped = word(i);
            if (!RESERVED_BEFORE_CASE.has(dropped)) reserved = false;
            if (OPENING_HEADS.has(dropped)) opens('word');
            else if (dropped === 'do' && loopHeader !== undefined) {
              open('word', loopHeader.fed);
              loopHeader = undefined;
            } else if (CLOSING_HEADS.has(dropped)) closeWord();
            else if (dropped === 'esac' && top()?.kind === 'case') pop();
          }
          at = next;
          continue;
        }
      }
      // `case WORD in` and zsh's `case WORD {`, where `case` is the reserved word for
      // every shell: what follows is patterns, up to a `)`.
      if (head === 'case' && reserved && at + 2 < all.length && (word(at + 2) === 'in' || word(at + 2) === '{')) {
        structural = true;
        opens('case');
        // An empty statement: `case WORD in esac`. What follows it is commands again.
        const after = at + 3 < all.length ? word(at + 3) : '';
        if (after !== 'esac' && after !== '}') return;
        pop();
        at += 4;
        continue;
      }
      // `function NAME… {`: the body starts after the brace. `for … do`, and
      // `for … {`: likewise.
      let body = -1;
      if (head === 'function' || head === 'case') body = indexOf('{', at);
      else if (head === 'for' || head === 'select' || head === 'foreach') {
        body = indexOf('do', at);
        // PowerShell pipes into `foreach { … }`; that brace is a script block.
        if (body === -1 && (head !== 'foreach' || indexOf('in', at) !== -1)) body = indexOf('{', at);
      }
      if (head === 'function') {
        const names = body === -1 ? at + 2 : body;
        for (let i = at + 1; i < names && i < all.length; i++) functionNames.add(word(i));
      }
      if (body !== -1) {
        structural = true;
        opens('word');
        at = body + 1;
        // `function NAME {` is a brace group: a `case` first in it is the reserved word.
        if (head !== 'function') reserved = false;
        continue;
      }
      // `function NAME compound-command`: the body is whatever command follows the name.
      if (head === 'function') { structural = true; at += 2; reserved = false; continue; }

      // zsh closes a brace group without a `;`: `{ cmd }`. Elsewhere that `}` is an
      // argument, and reading it as the close only ends the command a word early.
      const brace = top()?.kind === 'word' ? indexOf('}', at + 1) : -1;
      // zsh's `if [[ … ]] { … }` and `if [[ … ]] command`: the test ends at `]]`.
      const test = head === '[[' ? indexOf(']]', at + 1) : -1;
      if (test !== -1 && test < all.length - 1 && (brace === -1 || test < brace)) {
        structural = true;
        emit(all.slice(at, test + 1));
        at = test + 1;
        reserved = false;
        continue;
      }
      if (brace !== -1) {
        structural = true;
        emit(all.slice(at, brace));
        closeWord();
        at = brace + 1;
        reserved = false;
        continue;
      }
      const header = head === 'for' || head === 'select' || head === 'foreach';
      // Behind the pipe itself, unless something this flush opened already took it.
      const behindPipe = fed;
      emit(at === 0 ? all : all.slice(at));
      if (header) loopHeader = { fed: behindPipe };
      return;
    }
  };
  const flushWords = () => {
    const all = words;
    const behind = redirected;
    words = [];
    redirected = false;
    commandAt = -1;
    if (all.length > 0) flush(all, behind);
  };

  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    if (inPattern()) {
      // Patterns: nothing here is a command, and no word opens or closes anything.
      if (t.kind === ')') {
        (top() as Frame).pattern = false;
        pendingJoin = '; ';
        pipelineStart = commands.length;
      } else if (t.kind === 'word' && (text(t) === 'esac' || text(t) === '}')) {
        // `esac` — or the `}` of zsh's `case WORD { … }` — where a pattern would start.
        const before = tokens[k - 1];
        if (before === undefined || before.kind !== 'word' || text(before) === 'in' || text(before) === '{') pop();
      }
      continue;
    }
    if (t.kind === 'word') {
      if (words.length === 0) { join = pendingJoin; pendingJoin = '; '; }
      words.push(t);
      continue;
    }
    if (t.kind === 'redirect' || t.kind === 'here-string') {
      structural = true;
      if (words.length === 0) redirected = true;
      const target = tokens[k + 1];
      if (target === undefined || target.kind !== 'word') continue;
      k++;
      if (t.kind === 'here-string') hereStrings.add(text(target));
      continue;
    }
    if (t.kind === '(') {
      structural = true;
      // Where the command proper starts: fixed once a word that is not dropped is seen.
      if (commandAt === -1 || commandAt >= words.length) commandAt = afterDroppedHeads(command, words, 0);
      const at = Math.min(commandAt, words.length);
      const rest = words.length - at;
      const head = rest > 0 ? text(words[at]) : '';
      const loop = head === 'for' || head === 'select' || head === 'foreach';
      if (match[k] !== -1 && loop && rest === 1 && head !== 'foreach') {
        // `for (( init; test; step ))`: the header ends here, and the body may follow
        // with nothing in between.
        const heads = words.slice(0, at);
        const depth = frames.length;
        const behindPipe = join === ' | ';
        words = [];
        commandAt = -1;
        if (heads.length > 0) flush(heads, redirected);
        redirected = false;
        // Behind the pipe itself, unless a head before it opened something that took it.
        open('word', behindPipe && frames.length === depth);
        k = match[k];
        continue;
      }
      if (match[k] !== -1 && loop && rest > 1 && !words.some((w) => text(w) === 'in')) {
        // zsh's `for NAME (list) body`: the list is words, not a command, and to every
        // other shell a parenthesis after a command's words is a syntax error. (cmd.exe
        // writes `for %f in (list) do …`; that one has an `in`.)
        flushWords();
        k = match[k];
        continue;
      }
      // `name=(a b)`: an array's elements, whatever stands before the name.
      const before = words[words.length - 1];
      const array = before !== undefined && before.end === t.start && command[t.start - 1] === '=';
      // In command position — nothing before it but words that are dropped — a
      // parenthesis opens a subshell. So does one that follows a keyword that takes a
      // parenthesised part: `function f (body)`, `coproc NAME (body)`, zsh's
      // `for NAME (list)`, `repeat N (body)` and `if [[ … ]] (body)`.
      const opensGroup = array ? false : rest === 0 || head === 'function' || head === 'case'
        || (head === 'repeat' && rest <= 2)
        || (rest === 1 && at > 0 && text(words[at - 1]) === 'coproc')
        || (head === '[[' && text(words[words.length - 1]) === ']]')
        // An unclosed list of zsh's `for NAME (list)`.
        || (loop && rest > 1 && !words.some((w) => text(w) === 'in'));
      if (!opensGroup && match[k] !== -1) {
        // After the words of a command, a parenthesis starts no command in any shell.
        if (match[k] === k + 1) {
          // `name()`, `name ()` and zsh's `a b()`: the words are function names, and
          // what was dropped before them is acted on once.
          for (let i = at; i < words.length; i++) functionNames.add(text(words[i]));
          const heads = words.slice(0, at);
          words = [];
          commandAt = -1;
          if (heads.length > 0) flush(heads, redirected);
          redirected = false;
        } else if (before !== undefined && before.end === t.start && !array && PATH_START.test(text(before))) {
          // `x=(a b)` is an array, and `echo a (b)` or `f(1, 2)` a syntax error. Glued
          // to a path, though, zsh reads a glob group: `/usr/bin/(sudo)`.
          before.expands = true;
        }
        k = match[k];
        continue;
      }
      flushWords();
      // `case WORD in (pattern)`: the words were the header, and this opens a pattern.
      if (inPattern()) continue;
      open('paren', pendingJoin === ' | ');
      continue;
    }
    if (t.kind === ')') {
      if (!caseOnLine && !frames.some((frame) => frame.kind === 'paren')) {
        // It closes nothing, and with no `case` anywhere on the line it is no pattern's
        // either: a syntax error to every shell, or text the classifier is reading as a
        // guess (`fix(scope): message`). It stays in the word it is written in, as the
        // classifier's own tokeniser has it.
        let start = t.start;
        let end = t.end;
        let expands = false;
        const before = words[words.length - 1];
        if (before !== undefined && before.end === t.start) {
          start = before.start;
          expands = before.expands === true;
          words.pop();
        }
        const after = tokens[k + 1];
        if (after !== undefined && after.kind === 'word' && after.start === t.end) {
          end = after.end;
          expands = expands || after.expands === true;
          k++;
        }
        if (words.length === 0) { join = pendingJoin; pendingJoin = '; '; }
        words.push({ kind: 'word', start, end, expands });
        continue;
      }
      // Not a pattern's: it closes a subshell, or stands where a `case` on the line may
      // make it one for some shell. Either way the words before it are a command.
      structural = true;
      const depth = frames.length;
      flushWords();
      // Unless those words were `case WORD in pattern`: then this is the pattern's.
      if (frames.length > depth && inPattern()) {
        (top() as Frame).pattern = false;
        pipelineStart = commands.length;
      } else closeParen();
      pendingJoin = '; ';
      continue;
    }
    flushWords();
    if (t.kind === 'arm') {
      structural = true;
      const frame = top();
      if (frame !== undefined && frame.kind === 'case') frame.pattern = true;
    }
    // A newline after a pipe continues the pipeline.
    if (t.kind === '|') {
      pendingJoin = ' | ';
      pipeStart = pipelineStart;
    } else if (!(pendingJoin === ' | ' && command[t.start] === '\n')) {
      pendingJoin = '; ';
      pipelineStart = commands.length;
    }
  }
  flushWords();

  let flattened: string | null = null;
  if (structural && commands.length > 0) {
    const parts: string[] = [commands[0]];
    for (let c = 1; c < commands.length; c++) parts.push(joins[c], commands[c]);
    flattened = parts.join('');
  }
  let looseTokens = tokens;
  if (LOOSE_DIFFERS.test(command)) {
    let own = lex(command, { ...how, loose: true });
    // A quote left open there: the quote characters are text, as for the whole line.
    if (own.openQuote && how.honorQuotes) own = lex(command, { ...how, loose: true, honorQuotes: false });
    looseTokens = own.tokens;
  }
  const loose = readLoosely(command, looseTokens);
  return {
    flattened,
    // Its pipelines one by one, for a line with a `$'…'` quote or the brace-quote reading.
    alternates: commands.length > 1 && (how.quoteInBrace || command.includes("$'")) ? pipelines(commands, joins) : [],
    loose: loose === null ? [] : [loose],
    plain: [],
    holdsCase: false,
    hereStrings: [...hereStrings],
    commands: flattened === null ? [] : commands.map((one, c) => ({ text: one, join: joins[c], fed: fedCommands[c], from: pipedFrom[c] })),
    otherCommands: [],
    substitutions: [...new Set(lexed.substitutions.map(([start, end]) => command.slice(start, end)))],
    expandingWords: [...expanding],
    functionNames: [...functionNames],
    openQuote: lexed.openQuote,
    sawComment: lexed.sawComment,
    sawSubscript: lexed.sawSubscript,
    caseFrom: lexed.caseFrom,
  };
}

/** The commands grouped into the pipelines they stand in, each as one line. */
function pipelines(commands: string[], joins: string[]): string[] {
  const out = new Set<string>();
  let current = '';
  commands.forEach((text, at) => {
    if (at > 0 && joins[at] === ' | ') current += ` | ${text}`;
    else {
      if (current !== '') out.add(current);
      current = text;
    }
  });
  if (current !== '') out.add(current);
  return [...out];
}

/** What the reading that leaves nothing out lexes differently: see `Lexing.loose`. */
const LOOSE_DIFFERS = /[[`]|\$[({]|[<>=]\(/;

/** Words that end a command wherever they stand, for the reading that leaves nothing out. */
const LOOSE_SEPARATORS = new Set(['{', '}', ']]']);

/**
 * The line with every operator, every parenthesis and every brace taken as the end of a
 * command, and no word left out but the ones dropped from a command's head. Null when
 * that is the line as it stands.
 */
function readLoosely(command: string, tokens: Token[]): string | null {
  const text = (t: Token) => command.slice(t.start, t.end);
  const out: string[] = [];
  let words: Token[] = [];
  let join = '; ';
  let pendingJoin = '; ';
  let changed = false;
  /** Parentheses open here, every one counted. */
  let depth = 0;
  /** Where in `out` the pipes of the pipeline being read stand, and whether it holds a redirection. */
  let pipes: number[] = [];
  let pipelineRedirects = false;
  let redirects = false;
  const end = () => {
    let at = afterDroppedHeads(command, words, 0);
    // `function NAME`: what follows the name is the body.
    while (at < words.length && text(words[at]) === 'function') at = afterDroppedHeads(command, words, Math.min(at + 2, words.length));
    if (at > 0) changed = true;
    if (at < words.length) {
      if (out.length === 0 || join !== ' | ') {
        pipes = [];
        pipelineRedirects = false;
      } else pipes.push(out.length);
      if (out.length > 0) out.push(join);
      pipelineRedirects = pipelineRedirects || redirects;
      out.push(words.slice(at).map(text).join(' '));
    }
    words = [];
    redirects = false;
  };
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    if (t.kind === 'word') {
      if (LOOSE_SEPARATORS.has(text(t))) {
        changed = true;
        end();
        continue;
      }
      if (words.length === 0) { join = pendingJoin; pendingJoin = '; '; }
      words.push(t);
      continue;
    }
    if (t.kind === 'redirect' || t.kind === 'here-string') {
      changed = true;
      redirects = true;
      if (tokens[k + 1]?.kind === 'word') k++;
      continue;
    }
    end();
    if (t.kind === ')') {
      if (depth > 0) depth--;
      else if (!pipelineRedirects) {
        // A `)` that closes nothing is a syntax error to a POSIX shell unless it ends a
        // `case` pattern, and there a `|` stands between alternatives: `bash|zsh)` is
        // not a pipe into a shell. cmd.exe does run a pipeline with a stray `)` after
        // it — as an argument, which the classifier's own reading has there as well. A
        // redirection is no part of a pattern, so with one the pipes stay.
        for (const at of pipes) out[at] = '; ';
      }
      pipes = [];
      pipelineRedirects = false;
    }
    if (t.kind === '|') pendingJoin = ' | ';
    else if (t.kind === '(') { changed = true; depth++; } // What a pipe leads into is still behind it.
    else {
      if (t.kind !== ';') changed = true;
      if (!(pendingJoin === ' | ' && command[t.start] === '\n')) pendingJoin = '; ';
    }
  }
  end();
  return changed && out.length > 0 ? out.join('') : null;
}

/** One reading, with the classifier tokeniser's answer to a quote left open. */
function read(command: string, dialect: GrammarDialect, options: Options): Reading {
  const reading = readOnce(command, { ...options, dialect, honorQuotes: true });
  // A quote left open is a syntax error, not one long argument. The classifier's
  // tokeniser re-reads such a string with the quote characters as ordinary text; do the
  // same, so both readings split the string in the same places.
  if (!reading.openQuote) return reading;
  // Not for the brace-quote reading: there the open quote means bash rejects the line,
  // and re-reading it with every quote off would split quoted prose into commands.
  if (options.quoteInBrace) return readOnce('', { ...options, dialect, honorQuotes: true });
  return readOnce(command, { ...options, dialect, honorQuotes: false });
}

const USUAL: Options = { ansi: true, comments: true, quoteInBrace: false, subscripts: true };

/**
 * What comes off when a flattened text is read again, and again: usually nothing.
 *
 * Text read with an open quote as plain characters can balance its quotes once part of
 * it is dropped, and a word that was not reserved behind a redirection stands first
 * once the redirection is gone. Whatever a second reading finds is added; it never
 * replaces the first, because a second reading can also lose a command (`time case x
 * in x) cmd` re-reads as a `case` statement with no end).
 *
 * Four rounds is a bound, not a count: of 147,006 fuzzed lines two found text in a
 * second round and none in a third.
 */
function further(flattened: string | null, dialect: GrammarDialect, options: Options): string[] {
  const found: string[] = [];
  let current = flattened;
  for (let round = 0; current !== null && round < 4; round++) {
    current = read(current, dialect, options).flattened;
    if (current !== null) found.push(current);
  }
  return found;
}

const CASE_HEADER_END = /\s(?:in(?=[\s()]|$)|\{)/g;
/** `$(`, a backquote, `<(`, `>(`, and zsh's `=(` where it starts a word (`x=(a b)` is an array). */
const SUBSTITUTION_OPENER = /\$\(|`|[<>]\(|(?:^|\s)=\(/;
/** Whether a `case WORD in` or `case WORD {` stands in the text: two passes, each once over it. */
function holdsCaseStatement(text: string): boolean {
  // `HOLDS_CASE` is the word `case` where a statement may start: one pattern for both tests.
  const first = text.search(HOLDS_CASE);
  if (first === -1) return false;
  let last = -1;
  for (const end of text.matchAll(CASE_HEADER_END)) last = end.index;
  return last > first;
}

export function readShellGrammar(command: string, dialect: GrammarDialect): GrammarReading {
  const { openQuote: _open, sawComment, sawSubscript, caseFrom: usualCase, ...reading } = read(command, dialect, USUAL);
  let caseFrom = usualCase;
  const alternates = new Set(reading.alternates);
  const loose = new Set(reading.loose);
  for (const one of further(reading.flattened, dialect, USUAL)) alternates.add(one);

  // The other ways a shell may read the same line. Everything they find is added to
  // what the usual reading found; none of it replaces anything.
  const also = (options: Options) => {
    const other = read(command, dialect, options);
    if (other.flattened !== null) alternates.add(other.flattened);
    for (const one of further(other.flattened, dialect, options)) alternates.add(one);
    for (const one of other.alternates) alternates.add(one);
    for (const one of other.loose) loose.add(one);
    if (other.caseFrom !== -1 && (caseFrom === -1 || other.caseFrom < caseFrom)) caseFrom = other.caseFrom;
    if (other.commands.some(({ fed }) => fed)) reading.otherCommands.push(other.commands);
    reading.hereStrings = [...new Set([...reading.hereStrings, ...other.hereStrings])];
    reading.substitutions = [...new Set([...reading.substitutions, ...other.substitutions])];
    reading.expandingWords = [...new Set([...reading.expandingWords, ...other.expandingWords])];
    reading.functionNames = [...new Set([...reading.functionNames, ...other.functionNames])];
  };
  // Four things the shells read differently, and every combination of them the line
  // can be read in:
  //  - `$'…'` is a quoting of bash, zsh and ksh; dash reads the `$` as text and the
  //    rest as an ordinary quote, which ends in a different place;
  //  - an interactive zsh and cmd.exe have no comments: there the `#` is a word and
  //    the rest of the line runs;
  //  - bash pairs single quotes inside `"${x:-…}"`; dash and POSIX take them as
  //    characters;
  //  - bash, zsh and ksh read `$[ … ]` and a subscript to the closing bracket, operators
  //    and all; dash has neither, and the operators inside end commands.
  const ansi = dialect === 'posix' && command.includes("$'") ? [true, false] : [true];
  const comments = sawComment || command.includes('#') ? [true, false] : [true];
  const quoteInBrace = command.includes('${') && command.includes("'") && command.includes('"') ? [false, true] : [false];
  const subscripts = sawSubscript ? [true, false] : [true];
  for (const a of ansi) for (const c of comments) for (const q of quoteInBrace) for (const b of subscripts) {
    if (a === USUAL.ansi && c === USUAL.comments && q === USUAL.quoteInBrace && b === USUAL.subscripts) continue;
    also({ ansi: a, comments: c, quoteInBrace: q, subscripts: b });
  }
  if (reading.flattened !== null) alternates.delete(reading.flattened);
  reading.alternates = [...alternates];
  reading.loose = [...loose];
  // See `GrammarReading.plain`. Once for the line: with no quote and no comment the
  // readings above do not differ. The quote characters are left out of the text, or the
  // classifier would pair them.
  // Where the pairing of quotes went wrong the lexer saw no substitution at all, and
  // the misalignment is what a pattern's `)` inside a quoted word produces. So the
  // question is also asked of the characters alone: an opener of a substitution, and
  // a `case` statement somewhere behind it. That takes `echo "$(date)"; case … esac`
  // too, where the statement stands outside; it cannot be told from the other.
  const opener = command.search(SUBSTITUTION_OPENER);
  if (opener !== -1 && holdsCaseStatement(command.slice(opener))) reading.holdsCase = true;
  if (caseFrom !== -1) {
    // The statement itself, `case WORD in` or zsh's `case WORD {`, and not the word
    // `case` among a command's arguments (`grep -c case f`).
    if (holdsCaseStatement(command.slice(caseFrom))) reading.holdsCase = true;
    const text = command.slice(caseFrom, command.lastIndexOf(')') + 1);
    const tokens = lex(text, { ...USUAL, comments: false, dialect, honorQuotes: false, loose: true, plain: true }).tokens;
    const plain = readLoosely(text, tokens)?.replace(/["']/g, '');
    if (plain !== undefined) reading.plain = [plain];
  }
  return reading;
}
