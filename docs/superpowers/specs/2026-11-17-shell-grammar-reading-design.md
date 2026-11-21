# Reading the shell's grammar and an interpreter's options (design)

The design behind GHSA-hmrp-r5wm-5mqf. It shipped in one release with the `split
--filter` fix (GHSA-gpfp-xjq7-64hv). This file is the design as built; the record of the
review rounds that led to it is not part of the repository.

## Problem, as measured on 2.26.0

Every table in `src/policy/classifier.ts` is keyed on a segment's command word, and a
segment is what `tokenizeSegmentsDetailed` cuts at `; & |` and newline. The shell's grammar
puts commands in other places, and there the word the tables are asked about names no
binary. Measured through `PolicyEngine`, operator on prod, default bindings: `sudo id` is
denied as `privileged`; the same command is allowed as `safe`, with no never-allowed match,
when it stands

1. inside a subshell or a brace group;
2. after a reserved word (`if`, `then`, `elif`, `else`, `while`, `until`, `do`, `!`), in a
   function body, or in a `case` arm;
3. behind a redirection that precedes the command word or is glued to it;
4. under a command word the shell rewrites before running it (a glob or a brace expansion).

`coproc`, `builtin` and `trap ACTION` pass a command on in the same way and are unread.

## What the first attempt taught (withdrawn, see the split-filter spec)

Rules were added to the tokeniser: parenthesis and `case` counters, word breaks at
redirection operators, reserved words skipped in `commandReadings`. Three reviews measured:

- classes falling below main, with never-allowed matches lost, because a `)` closing a
  substitution, a quoted `>` and a redirection between a carrier and its argument were
  each misread by a new rule;
- a quadratic loop;
- everyday commands raised to `destructive`/`privileged`.

Cause: the tokeniser's output is consumed by a dozen readers that index into `words`, and
it records neither whether a word was quoted nor how deep in a substitution a character
sits. Changing what it emits changes every reader at once, in both directions.

## Design

### 1. The grammar reading only adds commands; it never changes what exists

The tokeniser, `commandReadings` and every existing reader stay byte-for-byte as they are.
A new, separate lexer reads the command and returns the simple commands the shell would
run, each as text; `nestedCommands` pushes them, outside its speculative block, exactly as
it pushes the inside of `$(…)` today. Each is then classified by the existing code as a
command in its own right, and the result is the highest class found — the rule this file
already applies to substitutions and to the two backslash dialects.

Consequences, by construction rather than by test:

- **no class can fall below main**, and no never-allowed match can be lost: the existing
  reading still runs, unchanged, and the new one can only add;
- the never-allowed scan sees the extracted commands, because it already walks
  `nestedCommands(command, false, …)`;
- a mistake in the new lexer costs a false positive or a missed raise, never a lowering.

### 2. The lexer (`src/policy/shell-grammar.ts`, pure, no imports from the classifier)

One pass over the characters, linear, carrying the state the tokeniser lacks:

- quote and escape state, per dialect, the same rules as the tokeniser's;
- **substitution depth**: `$(…)`, backticks, `${…}`, `$((…))`, `<(…)`, `>(…)` are opaque
  spans inside a word; nothing inside one is an operator, and its closer closes only it;
- **operators as tokens, not characters in words**: `; & | && || ;; ( )`, newline, and the
  redirection operators with their optional descriptor; an operator is one only when
  unquoted and unescaped;
- a comment (`#` at a word start) ends the line.

From the tokens it builds simple commands: reserved words are recognised only unquoted and
only in command position; `case WORD in` opens patterns, each ended by its `)`; `name()`
and `function name` introduce a body; `( … )` and `{ …; }` group. A redirection and its
target are dropped from the command's words wherever they stand.

`shellGrammarCommands(command, dialect): string[]` returns, for each simple command, the
**original source text of its words joined by single spaces** — slices of the input, so
quoting is preserved exactly and nothing is re-quoted. A simple command whose text equals
a segment the existing tokeniser already produces is not returned (nothing to add; this is
also what ends the recursion). All levels are returned flat, so the reading costs one level
of `MAX_NESTING_DEPTH`, not one per nesting.

Input the lexer cannot balance (an unclosed group, `case` without `esac`) returns what was
read so far; it never throws.

### 3. Pass-on builtins

`coproc` and `builtin` are read past like the wrappers they are, and `trap ACTION
SIGNAL…` is a named carrier beside `splitFilterPrograms`: the action is classified as the
command line it is.

### 4. What the lexer returns: three readings, all additive

The shells do not agree on which words are `case` patterns, which parentheses are
subshells, where a bracket is a subscript, whether `#` starts a comment or `$'…'` is a
quoting. Every rule of the form "skip these words, they are not commands" was wrong for
some shell. So the lexer gives three readings and the classifier takes the highest class
any of them yields; none replaces another.

- **The precise reading** (`flattened`, `alternates`): the line with groups, reserved
  words and redirections removed, read once for each combination of the things the
  shells disagree on. Its commands are classified in full.
- **The reading that leaves nothing out** (`loose`): every operator and every parenthesis
  ends a command, and what stands between two is a command, a `case` pattern, an array's
  elements and the inside of `[[ … ]]` included. It is asked only what a command is by
  name (`sudo`, `reboot`), and only for text the shell certainly runs.
- **The plain reading** (`plain`): for a line with a substitution that holds a `case`,
  the text from that substitution to the line's last `)`, with no span and no quote,
  asked by name. A pattern's `)` ends such a substitution early for every count of
  parentheses.

Decided by the maintainer, as the price of these readings:

- a `case` label or an array element that names an elevating or never-allowed command is
  read as that command;
- `(( … ))` is read as commands, because `dash` runs it as a subshell;
- a glob or a brace expansion in a command word makes the line `destructive` (only `?`
  and `%` as PowerShell aliases and `[Type]::Member` are exempt);
- a PowerShell condition or block that starts with a variable is `destructive`.

### 5. A line that cannot be read to the end is not `safe`

- **A substitution and a `case` statement behind it** (`holdsCase`). Where such a
  substitution ends is what no reading can say. A line with an opener of a substitution
  (`$(`, a backquote, `<(`, `>(`, zsh's `=(` at the start of a word) and a `case WORD in`
  or `case WORD {` anywhere behind it is `destructive` at least, asked of the lexer's
  pairing and of the characters alone. That takes a statement that stands after a
  substitution and not in it, and prose that holds the word `case` and then ` in` behind
  a substitution; a statement before a substitution, or with none, keeps its class.
- **The depth cap.** Past eight levels of carriers the class is `privileged`, and so it is
  where the never-allowed scan met the cap under a text and found nothing above it.

### 6. The program behind an interpreter's options (`programsPastOptions`)

The walk from an interpreter to its program allowed only flags in between and took the
word after the program flag. Three walks stand beside it and add what they find:

- **`shellPrograms`**: `-c` is a switch, so a shell's program is its first operand
  wherever `-c` stands, `+c` included. Which words are operands depends on which options
  take a word, and that is known for bash and zsh by their names; for any other shell the
  word after an option that may take one is read both ways.
- **`modelledPrograms`**: each interpreter has an `OptionModel` of the options known to
  take **no** value. Any other option is taken to have one, attached or as the next word.
  A missing entry costs an approval prompt and hides nothing; the first version listed
  the options that take a value and left the program unread wherever it lacked one.
- **`programsAnywhere`**: vim and gdb read options after their operands too, and vim's
  `+CMD` is `-c CMD`.

Every word of a command whose operands are not data is read, as the walk beside these
does, because behind a wrapper no table lists the interpreter is not the segment's
command word. Away from the command word a cluster of flags is believed up to three
letters and a name right after another command's long option is walked without taking
unknown options to have values.

A program flag added for this walk is kept in `alsoProgramWords`, not in
`programBearingWords`: the existing walk takes the word after the first flag it knows, so
a new flag there changes which word that is on lines it reads today.

### 7. Cost

- The class of a text asks the never-allowed scan about it. It passes its own depth, and
  the scan's cache keeps how far a scan had to look, so an answer is reused for another
  number of levels where it is the same answer. Asked from depth 0 for every text, a
  nested line was scanned once per level.
- Each interpreter name starts a walk that reads past values, so a walk records the state
  it is in at each word and stops where another has been.
- Every loop over a line's words or characters is tested for growth at two sizes.

## Tests

`test/unit/policy`: `shell-grammar.test.ts` (the lexer), `shell-grammar-reading.test.ts`
(what the classifier makes of it), `interpreter-options.test.ts` (the three walks and one
test for each entry of the option tables), `round-eight-rows.test.ts` (rows from the
mutation runs), `grammar-differential.test.ts` (a corpus of realistic commands against a
snapshot of their classes before this work: nothing may fall, and every rise is listed),
and the property tests under `test/property`.

Measured on the released code: no class or never-allowed answer below 2.26.0 over the
differential corpus and over generated lines (interpreter invocations, mixed and nested
lines); of 1,810 realistic single-line commands one rises (`vim +/'foo|bar' file`).

## Release

Minor, with the `split --filter` fix. The upgrade notes list the everyday forms that now
ask for approval.
