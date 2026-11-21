import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { readShellGrammar } from '../../../src/policy/shell-grammar.js';
import { anyString, closedCommand, grammarForm, grammarSoup } from '../../property/command-arbitraries.js';
import { fcParams } from '../../property/fc-seed.js';
import { growthRatio } from './cpu-cost.js';

/**
 * The lexer alone: which words of a command line are commands, once the shell's grammar
 * is taken away. What the classifier then makes of the result is tested in
 * `shell-grammar-reading.test.ts`.
 */
const flat = (command: string, dialect: 'posix' | 'windows' = 'posix') => readShellGrammar(command, dialect).flattened;

describe('readShellGrammar: the command without its grammar', () => {
  it.each([
    ['(sudo id)', 'sudo id'],
    ['( sudo id )', 'sudo id'],
    ['{ sudo id; }', 'sudo id'],
    ['if true; then sudo id; fi', 'true; sudo id'],
    ['if a; then b; elif c; then d; else e; fi', 'a; b; c; d; e'],
    ['while true; do sudo id; done', 'true; sudo id'],
    ['until false; do reboot; done', 'false; reboot'],
    ['for h in a b; do sudo id; done', 'for h in a b; sudo id'],
    ['for h; do reboot; done', 'for h; reboot'],
    ['for ((i=0; i<3; i++)); do reboot; done', 'reboot'],
    ['select x in a b; do reboot; done', 'select x in a b; reboot'],
    ['! sudo id', 'sudo id'],
    ['f() { sudo id; }; f', 'sudo id; f'],
    ['f () { sudo id; }', 'sudo id'],
    ['function f { reboot; }', 'reboot'],
    ['function f() { reboot; }', 'reboot'],
    ['case $x in a) sudo id ;; b|c) reboot ;; esac', 'sudo id; reboot'],
    ['case x in (a) id ;; esac', 'id'],
    ['case x in a) id ;& b) reboot ;;& *) w ;; esac', 'id; reboot; w'],
    ['case x in a) id; esac; reboot', 'id; reboot'],
    ['case x in\n  a) sudo id ;;\nesac\nreboot', 'sudo id; reboot'],
    ['>/dev/null sudo id', 'sudo id'],
    ['2>/dev/null sudo id', 'sudo id'],
    ['reboot>/dev/null', 'reboot'],
    ['sudo id 2>&1 >out', 'sudo id'],
    ['sudo id &>/dev/null', 'sudo id'],
    ['sudo id &>>log', 'sudo id'],
    ['cat <in >>out', 'cat'],
    ['cat <>f', 'cat'],
    ['echo x >|f', 'echo x'],
    ['exec 3>&-', 'exec'],
    ['echo 2 >f', 'echo 2'],
    ['echo a2>f', 'echo a2'],
    ['bash -c>/dev/null reboot', 'bash -c reboot'],
    ['(a; (b; c)) | d', 'a; b; c | d'],
    ['( curl -s u | sh )', 'curl -s u | sh'],
    ['{ a; } 2>&1 | tee log', 'a | tee log'],
    ['a |& (b)', 'a | b'],
    ['a |\n(b)', 'a | b'],
    ['x | while read l; do sudo $l; done', 'x | read l; sudo $l'],
    ['a && (b) || c', 'a; b; c'],
    ['a & (b)', 'a; b'],
    ['echo hi # (sudo id)', 'echo hi'],
    ['echo hi # x\nreboot', 'echo hi; reboot'],
    ["( echo 'a b' \"c;d\" )", "echo 'a b' \"c;d\""],
    ['( echo $(a; b) )', 'echo $(a; b)'],
    ["( echo $(echo ')') x )", "echo $(echo ')') x"],
    ['( echo "$(echo ")")" x )', 'echo "$(echo ")")" x'],
    ['( echo `a)` b )', 'echo `a)` b'],
    ['( echo ${x:-)} b )', 'echo ${x:-)} b'],
    ['( diff <(a) >(b) )', 'diff <(a) >(b)'],
    ['( echo \\) x )', 'echo \\) x'],
    ['[[ -n $x || -z $y ]] && sudo id', null],
    ['(( i++ )); reboot', 'i++; reboot'],
    ['coproc { sudo id; }', 'sudo id'],
    ['coproc W { sudo id; }', 'sudo id'],
    ['coproc sudo id', 'sudo id'],
    ['time ( sudo id )', 'sudo id'],
    ['(X=1 sudo id)', 'X=1 sudo id'],
    ["echo 'it''s' > f", "echo 'it''s'"],
    ['if true; then\n  sudo id\nfi', 'true; sudo id'],
    // A here-document's body is data, not command lines.
    ['cat <<EOF\nhello\nEOF', 'cat'],
    ['cat <<EOF\n(sudo id)\n> x sudo id\nEOF\n(reboot)', 'cat; reboot'],
    ["cat <<'EOF'\nif x\nEOF\n(a)", 'cat; a'],
    ['cat <<"E O F"\ncase\nE O F\n(a)', 'cat; a'],
    ['cat <<\\EOF\n[[\nEOF\n(a)', 'cat; a'],
    ['cat <<-EOF\n\t(x)\n\tEOF\n(a)', 'cat; a'],
    ['cat <<EOF\n(x)\n\tEOF\n(a)', 'cat'],
    ['cat <<A <<B\n(x)\nA\n(y)\nB\n(a)', 'cat; a'],
    ['cat <<EOF; (b)\n(x)\nEOF', 'cat; b'],
    ['cat <<EOF\n(x)', 'cat'],
    // A `for` body may start with no separator, and with a brace instead of `do`.
    ['for ((i=0;i<1;i++)) do sudo id; done', 'sudo id'],
    ['for ((i=0;i<1;i++)) { sudo id; }', 'sudo id'],
    ['for x do sudo id; done', 'sudo id'],
    ['select x do sudo id; done', 'sudo id'],
    ['for x in a b { sudo id; }', 'sudo id'],
    // `((` is read as two subshells: bash falls back to that, and dash knows nothing else.
    ['((sudo id); true)', 'sudo id; true'],
    ['((sudo id) )', 'sudo id'],
    ['(( (a) ) ); b', 'a; b'],
    ['time -p { sudo id; }', 'sudo id'],
    ['time -p -- sudo id', 'sudo id'],
    ['coproc N case x in x) sudo id;; esac', 'case x in x; sudo id'],
    ['coproc N if a; then b; fi', 'a; b'],
    ['coproc N while a; do b; done', 'a; b'],
    ['coproc N until a; do b; done', 'a; b'],
    ['coproc N for x in 1; do b; done', 'for x in 1; b'],
    ['coproc N select x in 1; do b; done', 'select x in 1; b'],
    ['coproc N [[ -n x ]] && (b)', '[[ -n x ]]; b'],
    ['builtin exec sudo id', 'exec sudo id'],
    // `case` with no `in` before the next `;` is a command name, as it is after a redirection.
    ['case x; (a); in', 'case x; a; in'],
    ['>/dev/null case x; (sudo id); in', 'case x; sudo id; in'],
    ['2>&1 if true; (reboot)', 'true; reboot'],
    ['>f { a; }', 'a'],
    ['{fd}>/dev/null sudo id', 'sudo id'],
    ['echo {fd} >f', 'echo {fd}'],
    // Only space and tab end a word.
    ['echo \v# ; (sudo id)', 'echo \v#; sudo id'],
    ['echo \f# ; (reboot)', 'echo \f#; reboot'],
    ['echo \r# ; (reboot)', 'echo \r#; reboot'],
    // Quoting inside `${…}` and `$'…'`.
    ["echo ${x:-'}'} ; (sudo id) ; echo \\'", "echo ${x:-'}'}; sudo id; echo \\'"],
    ["echo $'\\'' ; (reboot) ; echo \\'", "echo $'\\''; reboot; echo \\'"],
    ['echo "${x:-"}"}" ; (a)', 'echo "${x:-"}"}"; a'],
    ["echo $'\\'' '(' x ; (a)", "echo $'\\'' '(' x; a"],
    ["( echo \"$(echo $'\\'' ')' )\" x )", "echo \"$(echo $'\\'' ')' )\" x"],
    ['( echo "$(echo ${x:-)})" y )', 'echo "$(echo ${x:-)})" y'],
    // An ordinary single quote keeps its backslash, in a word and inside a substitution.
    ["(echo a'\\' ; b)", "echo a'\\'; b"],
    ["( echo \"$(echo a'\\' ) x\" ; b )", "echo \"$(echo a'\\' ) x\"; b"],
    ['( ($x))', '$x'],
    ['[[ a\n(b)', '[[ a; b'],
    // `[[` stops at a separator: not every shell reserves it.
    ['[[ ; (sudo id) ; ]]', '[[; sudo id; ]]'],
    ['[[ -n x && -n y ]] && (a)', '[[ -n x; -n y ]]; a'],
    ['if [[ $a < $b ]]; then (c); fi', '[[ $a ]]; c'],
    ['(a)(b)', 'a; b'],
    // After the words of a command a parenthesis opens nothing, in any shell.
    ['echo (sudo id)', 'echo'],
    ['echo x (sudo id) y', 'echo x y'],
    ['echo ) x', null],
    ['x | case y in a|b) c ;; d|e) f ;; esac', 'x; c; f'],
    ['w; stop|restart) x', null],
    // Quoting and nesting inside a substitution, one level down.
    ['( echo $(echo \\) ) x )', 'echo $(echo \\) ) x'],
    ['( echo $(echo `a)` b) c )', 'echo $(echo `a)` b) c'],
    ['(echo $((1+2)); sudo id)', 'echo $((1+2)); sudo id'],
    ['( echo ${x:-\\})} b )', 'echo ${x:-\\})} b'],
    ['( echo ${a:-${b})} c )', 'echo ${a:-${b})} c'],
    ['( echo `a \\` )` b )', 'echo `a \\` )` b'],
    ['( echo "a\\"b)" c )', 'echo "a\\"b)" c'],
    ['( echo "`a"`" b )', 'echo "`a"`" b'],
    // Operators with no space around them.
    ['(a&sudo id)', 'a; sudo id'],
    ['x|{ sudo id; }', 'x | sudo id'],
    ['7z>log x', '7z x'],
    ['echo >; (sudo id)', 'echo; sudo id'],
    ['case x in a) y | z ;; b) w ;; esac', 'y | z; w'],
    ['(a | b)\n(c)', 'a | b; c'],
    ['case x in a) (b) ;; c) d ;; esac; e', 'b; d; e'],
    ['case x in a) { b; } ;; c) d ;; esac', 'b; d'],
    ['coproc W ( sudo id )', 'W; sudo id'],
    ['case x in esac; reboot', 'reboot'],
    ['} reboot', 'reboot'],
    ['f() reboot; f', 'reboot; f'],
    ['function f (reboot); f', 'reboot; f'],
    ['x | for i in 1; do y; done', 'x | for i in 1; y'],
    ['(sudo\tid)', 'sudo id'],
    ['(sudo\rid)', 'sudo\rid'],
    ['cat <&3', 'cat'],
    ['exec 3<&-', 'exec'],
    ['cat <<-EOF x', 'cat x'],
    ['cat <<EOF x', 'cat x'],
    ['(( (a) )); (reboot)', 'a; reboot'],
    ['((a)); (sudo id)', 'a; sudo id'],
    ['((sudo id))', 'sudo id'],
    ['(( n > 0 )) && (a)', 'n; a'],
    // Arithmetic on a variable too: dash runs `(($N))` as a command.
    ['(( $n > 5 )) && (a)', '$n; a'],
    ['if (( $# < 1 )); then (a); fi', '$#; a'],
    ['(($x); a)', '$x; a'],
    ['(( $x ) )', '$x'],
    // zsh.
    ['repeat 3 sudo id', 'sudo id'],
    ['repeat 3 { sudo id }', 'sudo id'],
    ['noglob sudo id', 'sudo id'],
    ['nocorrect sudo id', 'sudo id'],
    ['- sudo id', 'sudo id'],
    ['for x (a b) sudo id', 'for x; sudo id'],
    ['for x (a b) { sudo id }', 'for x; sudo id'],
    ['{ : } always { sudo id }', ':; sudo id'],
    ['{ echo }; }', 'echo'],
    ['echo }', null],
    ['for x in a b; { sudo id; }', 'for x in a b; sudo id'],
    ['foreach x (a b) sudo id; end; reboot', 'foreach x; sudo id; reboot'],
    ['foreach x (a)\nsudo id\nend', 'foreach x; sudo id'],
    ['(files=(*.txt); echo ${#files[@]})', 'files=; echo ${#files[@]}'],
    ['(a+=(b c) d)', 'd'],
    ['{ a; } always { sudo id; }', 'a; sudo id'],
    ['if (a) { sudo id; }', 'a; sudo id'],
    ['case x { x) sudo id ;; }', 'sudo id'],
    ['case x { x) a ;; }; reboot', 'a; reboot'],
    ['case xoo in (x|y)oo) sudo id;; esac', 'oo; sudo id'],
    ['case x in (a) b ;; (c|d)e) f ;; esac', 'b; e; f'],
    ['function f g { sudo id; }; f', 'sudo id; f'],
    ['case in in in) a ;; esac', 'a'],
    ['case x\nin a) b ;; esac', 'case x; in a; b'],
    ['a; (b) | c; d', 'a; b | c; d'],
    ['(a) |\n\n b', 'a | b'],
    // A syntax error in a shell; read as the pipe it most resembles.
    ['(a)\n| b', 'a | b'],
    ['\\if true; (b)', '\\if true; b'],
  ])('%j → %j', (command, expected) => {
    expect(flat(command)).toBe(expected);
  });

  it.each([
    'sudo id', 'a; b | c && d', "echo '(sudo id)'", 'echo "if x; then y; fi"', 'echo \\(x\\)',
    'echo \\> f', "flock '>' sudo id", 'echo $(sudo id)', 'echo ${x:-(}', 'echo $((1+2))', 'x=$(( (1+2) * 3 ))',
    'echo a{b,c}', 'echo if', 'echo {', 'echo done', 'echo }', 'x=1 if', 'kill -0 ${pid}', 'echo a#b',
    'find . -name x -exec rm {} \\;', 'find . \\( -name a -o -name b \\)',
    'diff <(sort a) <(sort b)', "docker ps --format '{{.ID}} {{.Image}}'",
    "jq '.a | select(.b > 1)' f", "psql -c 'select count(*) from t'", "rg 'sudo|su' /var/log",
    "curl -d '{\"a\":[1,2]}' http://h", "awk 'BEGIN{print 1}'", 'echo "a > b"', 'echo `a > b`',
    "'if' true", '"(" x', '\\( x', '', '   ',
  ])('reads no grammar in %j', (command) => {
    expect(flat(command)).toBeNull();
  });

  it.each([
    ['( sudo id', 'sudo id'],
    ['if true; then sudo id', 'true; sudo id'],
    ['case x in a) sudo id', 'sudo id'],
    ['case x in a', null],
    ['case x', null],
    ['{ reboot', 'reboot'],
    ['echo $(sudo id', null],
    ['echo `sudo id', null],
    ['echo ${x', null],
    [') reboot', null],
    ['echo "open; (sudo id)', 'echo "open; sudo id'],
    ["echo 'open; (sudo id)", "echo 'open; sudo id"],
    ['for', null],
    ['[[ x', null],
    ['((', null],
    ['for ((', 'for'],
    ['for ((x', 'for; x'],
    ['f()', null],
    ['>', null],
    ['<<<', null],
  ] as Array<[string, string | null]>)('reads what it can of %j and does not throw', (command, expected) => {
    expect(flat(command)).toBe(expected);
  });

  it.each([
    ['echo \\(sudo id\\)', 'echo \\'],
    ['find . \\( -name a \\)', 'find . \\'],
    ['(sudo id) \\', 'sudo id; \\'],
    ['C:\\tools\\x.exe >out', 'C:\\tools\\x.exe'],
    ['echo "a\\" > f', 'echo "a\\"'],
    // A backslash is not an escape here: these differ from the posix reading.
    ['( echo $(echo \\) x )', 'echo $(echo \\) x'],
    ['( echo ${x:-\\} b )', 'echo ${x:-\\} b'],
    ['( echo `a\\` b )', 'echo `a\\` b'],
    ['echo "a\\" "; (sudo id)"', null],
    ['echo \\; (sudo id)', 'echo \\; sudo id'],
    ["( echo $'a\\' ; b )", "echo $'a\\'; b"],
    ["( echo \"$(echo $'a\\' ) x\" ; b )", "echo \"$(echo $'a\\' ) x\"; b"],
  ] as Array<[string, string | null]>)('windows dialect: %j → %j', (command, expected) => {
    expect(flat(command, 'windows')).toBe(expected);
  });
});

describe('readShellGrammar: what reaches a command on standard input', () => {
  it.each([
    ["sh<<<'sudo id'", ["'sudo id'"]],
    ['cat <<< hi', ['hi']],
    ['<<<x sh -s', ['x']],
    ['(sh <<< a); cat <<< b', ['a', 'b']],
    ['(sh) <<< x', ['x']],
    ['while read l; do sh; done <<< "a b"', ['"a b"']],
    ["echo '<<<x'", []],
    ['cat << x', []],
    ['<<<', []],
  ])('here-strings of %j', (command, expected) => {
    expect(readShellGrammar(command, 'posix').hereStrings).toEqual(expected);
  });

  // A pipe into a group reaches every command in it; the first already has the pipe.
  it.each([
    ['x | { a; sh; }', [{ source: 'x', commands: ['sh'] }]],
    ['x | (a; b; c)', [{ source: 'x', commands: ['b', 'c'] }]],
    ['x | if a; then sh; fi', [{ source: 'x', commands: ['sh'] }]],
    ['x | while read l; do sh; done', [{ source: 'x', commands: ['sh'] }]],
    ['x | until a; do sh; done', [{ source: 'x', commands: ['sh'] }]],
    ['x | for i in 1; do sh; done', [{ source: 'x', commands: ['sh'] }]],
    ['x | select i in 1; do sh; done', [{ source: 'x', commands: ['sh'] }]],
    ['x | for ((i=0;i<1;i++)); do sh; done', [{ source: 'x', commands: ['sh'] }]],
    ['x | case y in y) a; sh ;; esac', [{ source: 'x', commands: ['a', 'sh'] }]],
    ['x | { a; { b; }; }', [{ source: 'x', commands: ['b'] }]],
    // The whole pipeline that feeds the group, not only its last stage.
    ['x | y | { a; sh; }', [{ source: 'x | y', commands: ['sh'] }]],
    ['{ x; y; } | { a; sh; }', [{ source: 'x | y', commands: ['sh'] }]],
    ['w; x | { a; sh; }', [{ source: 'x', commands: ['sh'] }]],
    ['{ w; x | { a; sh; }; }', [{ source: 'x', commands: ['sh'] }]],
    // Only the first thing opened after the pipe stands next to it.
    ['x | { while a; do sh; done; }', [{ source: 'x', commands: ['sh'] }]],
    ['x | { if a; then sh; fi; }', [{ source: 'x', commands: ['sh'] }]],
    ['x | { case y in y) sh ;; esac; }', [{ source: 'x', commands: ['sh'] }]],
    ['x | while read l; do case $l in a) : ;; esac; sh; done', [{ source: 'x', commands: [':', 'sh'] }]],
    // A pattern is not a command: a closing word in one closes nothing.
    ['x | while a; do case $l in done|b) : ;; esac; sh; done', [{ source: 'x', commands: [':', 'sh'] }]],
    ['x | { :; case y in (done) :;; esac; sh; }', [{ source: 'x', commands: [':', 'sh'] }]],
    ['x | { :; case y in (a|fi) :;; esac; sh; }', [{ source: 'x', commands: [':', 'sh'] }]],
    ['x | { :; (case y in y) :;; esac; :); sh; }', [{ source: 'x', commands: [':', ':', 'sh'] }]],
    // Not fed: after the group, before it, with no pipe, or after a loop header that
    // has no body (PowerShell's `select` is an everyday alias).
    ['x | { a; }; b', []],
    ['x; { a; b; }', []],
    ['{ a; b; } | c', []],
    ['x | { a | sh; }', []],
    ['x | if a; then b; fi; sh', [{ source: 'x', commands: ['b'] }]],
    ['x | while a; do b; done; sh', [{ source: 'x', commands: ['b'] }]],
    ['x | case y in y) a ;; esac; sh', [{ source: 'x', commands: ['a'] }]],
    ['x | select -First 3; sh', []],
    ['x | for f in a b; do c; done; sh', [{ source: 'x', commands: ['c'] }]],
    // A loop behind a brace the pipe feeds.
    ['x | { for i in 1; do :; sh; done; }', [{ source: 'x', commands: [':', 'sh'] }]],
    ['x | { for ((;;)) do :; sh; done; }', [{ source: 'x', commands: [':', 'sh'] }]],
  ])('pipes into a group in %j', (command, expected) => {
    const fed = readShellGrammar(command, 'posix').commands.filter((one) => one.fed).map((one) => one.text);
    expect(fed).toEqual(expected.flatMap((group: { commands: string[] }) => group.commands));
  });

  it('says where what a pipe carries begins', () => {
    const from = (command: string) => readShellGrammar(command, 'posix').commands.map((one) => one.from);
    expect(from('{ a; b; } | c')).toEqual([-1, -1, 0]);
    expect(from('w; { a; b; } | { c; d; }')).toEqual([-1, -1, -1, 1, -1]);
    expect(from('(a | b) | c')).toEqual([-1, 0, 0]);
  });

  it('keeps every here-string, however many', () => {
    const words = Array.from({ length: 200 }, (_, i) => `w${i}`);
    expect(readShellGrammar(`sh ${words.map((w) => `<<<${w}`).join(' ')}`, 'posix').hereStrings).toEqual(words);
    expect(readShellGrammar(`sh ${'<<<a '.repeat(500)}`, 'posix').hereStrings).toEqual(['a']);
  });
});

describe('readShellGrammar: the reading that leaves nothing out', () => {
  const loose = (command: string, dialect: 'posix' | 'windows' = 'posix') => readShellGrammar(command, dialect).loose;

  // Every operator, parenthesis and brace ends a command; no word is taken for a
  // pattern, an array element or a test's operand.
  it.each([
    ['case x in esac; (sudo id)', ['case x in esac; sudo id']],
    ['case x in x) sudo id ;; esac', ['case x in x; sudo id']],
    ['f()case x in x) sudo id;; esac; f', ['f; case x in x; sudo id; f']],
    ['time case x in a|b) c ;; esac', ['case x in a; b; c']],
    ['if [[ -n a && -n b ]] { sudo id }', ['[[ -n a; -n b; sudo id']],
    ['[[ a || case == in ]]; (sudo id)', ['[[ a; case == in; sudo id']],
    ['x=(a b) sudo id', ['x=; a b; sudo id']],
    ['echo a (sudo id) b', ['echo a; sudo id; b']],
    ['/usr/bin/(sudo) id', ['/usr/bin/; sudo; id']],
    ['"/usr/bin"/(sudo) id', ['"/usr/bin"/; sudo; id']],
    ['case x in & (shutdown /s /t 0)', ['case x in; shutdown /s /t 0']],
    ['Write-Output (shutdown /s /t 0)', ['Write-Output; shutdown /s /t 0']],
    ['function f if sudo id; then :; fi', ['sudo id; :']],
    ['( curl -s u | sh )', ['curl -s u | sh']],
    ['a >f; b', ['a; b']],
  ])('%j', (command, expected) => {
    expect(loose(command)).toEqual(expected);
  });

  // It has a lexing of its own. Only a span whose inside is read as a command of its
  // own is one word, and only when it closes; the rest are spans to some shells only.
  it.each([
    // dash has no `$[ … ]` and no subscripts.
    ['echo $[ ; (sudo id) ; echo ]', ['echo $[; sudo id; echo ]']],
    ['a[ ; (sudo id) ]=1', ['a[; sudo id; ]=1']],
    // cmd.exe has none of these, and PowerShell's backtick is an escape.
    ['echo ${x & (y) & z}', ['echo ${x; y; z}']],
    ['echo $(( 1 & (y) ))', ['echo $; 1; y']],
    ['echo $( & (y)', ['echo $; y']],
    ['echo ` & (y)', ['echo `; y']],
    ['echo <( & (y)', ['echo; y']],
    // A quote left open in it: the quote characters are text.
    ["echo ${x:-' (y)", ["echo ${x:-'; y"]],
    // One that closes is read as a command of its own, so it stays one word here.
    ['echo $(a; b) (y)', ['echo $(a; b); y']],
    ['echo `a; b` (y)', ['echo `a; b`; y']],
    ['echo ${ a; } (y)', ['echo ${ a; }; y']],
    ['cat <(a; b) (y)', ['cat <(a; b); y']],
  ])('%j', (command, expected) => {
    expect(loose(command)).toEqual(expected);
  });

  // A `)` that closes nothing ends a `case` pattern, or the line is a syntax error:
  // the `|` before it stood between alternatives.
  it.each([
    ['case x in a|b) c ;; esac', ['case x in a; b; c']],
    ['case x in a|b|c) d ;; esac', ['case x in a; b; c; d']],
    ['case x in a) b | c ;; d|e) f ;; esac', ['case x in a; b | c; d; e; f']],
    ['a | b; c|d) e', ['a | b; c; d; e']],
    // One that closes a parenthesis ends a group, and the pipe is a pipe.
    ['x=(a b) ( a | b )', ['x=; a b; a | b']],
    ['( ( a | b ) )', ['a | b']],
    // A redirection is no part of a pattern.
    ['case x in & a | >f b )', ['case x in; a | b']],
    ['case x in & a >f | b )', ['case x in; a | b']],
  ])('%j', (command, expected) => {
    expect(loose(command)).toEqual(expected);
  });

  it('reads what the other reading leaves as words', () => {
    // The list of a zsh short loop, and the operand behind a `!` inside a test.
    expect(loose('for f (a b) sudo id')).toEqual(['for f; a b; sudo id']);
    expect(loose('[[ a || ! sudo id ]]')).toEqual(['[[ a; sudo id']);
    expect(readShellGrammar('if [[ -n $a && ! -d $b ]]; then x; fi', 'posix').flattened).toBe('[[ -n $a; ! -d $b ]]; x');
    // Outside a test it is dropped as before.
    expect(readShellGrammar('if ! sudo id; then x; fi', 'posix').flattened).toBe('sudo id; x');
    expect(readShellGrammar('if [[ -n $a ]] && ! sudo id; then x; fi', 'posix').flattened).toBe('[[ -n $a ]]; sudo id; x');
  });

  it('is absent when the line is already that', () => {
    expect(loose('sudo id')).toEqual([]);
    expect(loose('a; b | c && d')).toEqual([]);
    expect(loose("echo '(sudo id)' \"{ x; }\"")).toEqual([]);
    expect(loose('find . -name x -exec rm {} \\;')).toEqual([]);
  });

  it('is given for the other ways of reading the line as well', () => {
    expect(loose('echo a # ; (sudo id)')).toEqual(['echo a #; sudo id']);
  });
});

describe('readShellGrammar: the command text inside substitutions', () => {
  it.each([
    ['echo $(sudo id)', ['sudo id']],
    // The classifier's own scan counts parentheses, quoted ones included.
    ["echo $(reboot; echo '(')", ["reboot; echo '('"]],
    ['echo "$(reboot; echo \'(\')"', ["reboot; echo '('"]],
    ["cat <(reboot; echo '(')", ["reboot; echo '('"]],
    ['tee >(sudo id)', ['sudo id']],
    // Only the outermost: what it holds is found when its own text is read.
    ['echo $(a $(b))', ['a $(b)']],
    ['echo "$(a "$(b)")" $(c)', ['a "$(b)"', 'c']],
    ['echo ${x:-$(a)}', ['a']],
    // zsh, and bash 5.3.
    ['cat =(sudo id)', ['sudo id']],
    ['diff =(a b) =(c)', ['a b', 'c']],
    ['echo ${ sudo id; }', ['sudo id; ']],
    ['echo ${| reboot; }', [' reboot; ']],
    ['echo ${\tsudo id; }', ['sudo id; ']],
    ['echo "${ sudo id; }"', ['sudo id; ']],
    ['echo ${ a ${ b; }; }', ['a ${ b; }; ']],
    // A `case` pattern ends the substitution early for every scan that counts
    // parentheses, so the rest of the line up to its last `)` is read as well.
    ['echo $(case x in x) reboot;; esac)', ['case x in x', 'case x in x) reboot;; esac']],
    ['echo $(f()case x in x) sudo id;; esac; f)', ['f()case x in x', 'f()case x in x) sudo id;; esac; f']],
    // Only up to the `)` after its `esac`, and only once on a line.
    ['echo "$(case $x in a) echo 1 ;; esac)"; echo "$HOME (x)"', ['case $x in a', 'case $x in a) echo 1 ;; esac']],
    ['echo $(case a in b) :;; esac) $(case c in d) :;; esac)', ['case a in b', 'case a in b) :;; esac', 'case c in d']],
    ['echo "$(grep -c case f)" "$(wc -l < f) (lines)"', ['grep -c case f', 'wc -l < f']],
    ['cat =(echo hi; time case x in x) sudo id ;; esac)', ['echo hi; time case x in x', 'echo hi; time case x in x) sudo id ;; esac']],
    // Arithmetic is not a substitution; a `$(` inside it is.
    ['echo $(( $x + 1 ))', []],
    ['echo "$(( $a + $b ))"', []],
    ['echo $(( $(nproc) * 2 ))', ['nproc']],
    ['echo "$(( $(date +%s) - start ))s"', ['date +%s']],
    ['echo $((sudo id); x)', ['(sudo id); x']],
    // Not at the start of a word: an array assignment, or plain text.
    ['x=(a b c)', []],
    ['echo a=(b)', []],
    ['echo ${x:-(a)}', []],
    ['echo ${x}', []],
    ["echo '=(sudo id)' '$(reboot)'", []],
    ['echo \\$(reboot)', []],
    // One that never closes is a syntax error.
    ['echo $(reboot', []],
    ['echo "$(reboot', []],
  ])('%j', (command, expected) => {
    expect(readShellGrammar(command, 'posix').substitutions).toEqual(expected);
  });
});

describe('readShellGrammar: words the shell rewrites', () => {
  // Which of them is a command word is the classifier's question; this is the list.
  it.each([
    ['/usr/bin/sud? id', ['/usr/bin/sud?']],
    ['ls *.txt /bin/[s]udo', ['*.txt', '/bin/[s]udo']],
    ['{sudo,id}', ['{sudo,id}']],
    ['/bin/{a..b} x', ['/bin/{a..b}']],
    ['env /usr/bin/sud? id', ['/usr/bin/sud?']],
    ['(sud? id)', ['sud?']],
    ['"$x"* y', ['"$x"*']],
    ['./x=1/su* id', ['./x=1/su*']],
    ['cat <<EOF\n[x]\nEOF\ns?do id', ['s?do']],
    // zsh: parentheses glued to a path group a glob.
    ['/usr/bin/(sudo) id', ['/usr/bin/']],
    ['/sbin/reboo(t)', ['/sbin/reboo']],
    ['./s(udo) id', ['./s']],
    // To a POSIX shell a bracket expression is a glob whatever follows it.
    ['[s]"udo" id', ['[s]"udo"']],
    ["[r]'eboot'", ["[r]'eboot'"]],
    ['[m]4', ['[m]4']],
    ['[R] -e x', ['[R]']],
    ['[xml] x', ['[xml]']],
    // A bracket expression is a glob whatever a cast looks like.
    ['[%s]udo id', ['[%s]udo']],
    ['[s]?do id', ['[s]?do']],
    ['[u]*/bin/sud? id', ['[u]*/bin/sud?']],
    ['?{,}udo id', ['?{,}udo']],
    // More than the old cap of them, all kept.
    [Array.from({ length: 70 }, (_, i) => `f${i}*`).join(' '), Array.from({ length: 70 }, (_, i) => `f${i}*`)],
  ])('%j', (command, expected) => {
    expect(readShellGrammar(command, 'posix').expandingWords).toEqual(expected);
  });

  it.each([
    "'sud?' id", '"sud?" id', 'sud\\? id', '[ -f x ]', '[[ -f x ]]', '{ a; }', 'echo $(s?do)', 'a{b}c x',
    'a{}b x', 'sudo id', '{a,b x', 'a,b} x', 'a..b} x', '{a.b} x', '{a.b.} x', 'echo a{b; c,d} x',
    // PowerShell and cmd.exe: the `?` alias bare and glued to its block, a hashtable,
    // a cast, a static member, an index after a group, `[%1]`.
    'Get-ChildItem | ? { $_.Name }', 'Get-Process | ?{ $_.CPU -gt 100 }', '1..3 | %{$_}',
    "@{Tags='a','b'} | ConvertTo-Json", '[math]::Round(1.5)', '[DateTime]::Now',
    '(Get-Content file.txt)[0]', '(Get-ChildItem)[0..4]', 'if [%1]==[] goto usage',
    // A parenthesis glued to a word that is no path: a call, not a glob group.
    'Write-Host("x")', '"a".Replace("x","y")', '(Get-Date).Date.AddDays(-1)', 'exit(1)', 'ls; echo see ls(1)',
    // A here-document's body is not command lines.
    'cat <<EOF\n[Unit]\n* item\n*/5 * * * * /opt/x.sh\nEOF',
    // An array's elements, and assignments to one.
    'files=(*.txt); echo ${#files[@]}', 'arr[0]=a; m[host]=web1',
    // A case pattern's alternatives are patterns, not command words.
    'case "$svc" in nginx*) echo web ;; postgres*|mysql*) echo db ;; esac',
    'case "$f" in *.jpg|*.jpeg|*.png) echo image ;; *.mp4|*.mkv) echo video ;; esac',
    'case $x in a*|b*|c*) echo m ;; esac',
    'if [x%1]==[x] echo usage', 'if [!v!]==[] echo usage',
  ])('lists none in %j', (command) => {
    expect(readShellGrammar(command, 'posix').expandingWords).toEqual([]);
  });

  it('keeps a glob after a cast that is really a file name', () => {
    expect(readShellGrammar('/bin/[s]udo id', 'posix').expandingWords).toEqual(['/bin/[s]udo']);
    expect(readShellGrammar('[s]udo id', 'posix').expandingWords).toEqual(['[s]udo']);
  });
});

describe('readShellGrammar: the other ways a shell may read the line', () => {
  it('reads `$\'…\'` as dash does, too: a `$` and an ordinary quote', () => {
    // Balanced either way, and the two readings differ. For bash the string runs on past
    // the escaped quote, so the first `(` is an operator after a word and the rest is
    // quoted text. For dash the first quote ends at the backslash, `'('` is an
    // argument, and the group runs.
    const reading = readShellGrammar("echo $'a\\' '(' ; (reboot) ; echo ')' 'b'", 'posix');
    expect(reading.flattened).toBe("echo $'a\\' ' ' 'b'");
    expect(reading.alternates).toContain("echo $'a\\' '('; reboot; echo ')' 'b'");
  });

  it('counts the `$` and the backslashes before the quote', () => {
    const ansi = (command: string) => readShellGrammar(command, 'posix').flattened;
    // `$$'` is the process id and a plain quote; `\$'` an escaped `$` and a plain quote.
    expect(ansi("(echo $$'\\' x ; reboot)")).toBe("echo $$'\\' x; reboot");
    expect(ansi("(echo \\$'\\' x ; reboot)")).toBe("echo \\$'\\' x; reboot");
    // `$$$'` is the process id and an ANSI quote; `\\$'` an escaped backslash and one.
    expect(ansi("(echo $$$'\\'' x ; reboot)")).toBe("echo $$$'\\'' x; reboot");
    expect(ansi("(echo \\\\$'\\'' x ; reboot)")).toBe("echo \\\\$'\\'' x; reboot");
  });

  it('gives the commands one by one when the quoting is one the tokeniser reads differently', () => {
    expect(readShellGrammar("echo $'a' ; (reboot)", 'posix').alternates).toEqual(["echo $'a'", 'reboot']);
    expect(readShellGrammar('echo a ; (reboot)', 'posix').alternates).toEqual([]);
  });

  it('reads a line with a comment as one without, too', () => {
    const reading = readShellGrammar('echo a # ; (sudo id)', 'posix');
    expect(reading.flattened).toBe('echo a');
    expect(reading.alternates).toEqual(['echo a #; sudo id']);
  });

  it('reads a single quote inside "${…}" as a character and as a quote', () => {
    // bash pairs the two quotes and runs `su -`; dash takes each for a character.
    const reading = readShellGrammar('echo "${x:-\'}"\'}" ; su - ; echo "${x:-\'}"\'}"', 'posix');
    expect(reading.alternates).toContain('su -');
    // Nested: the other way round.
    expect(readShellGrammar('echo "${x:-${y:-\'}}"; (su -); echo "${x:-${y:-\'}}"', 'posix').flattened)
      .toBe('echo "${x:-${y:-\'}}"; su -; echo "${x:-${y:-\'}}"');
  });

  it('adds what the other readings find to the rest as well', () => {
    expect(readShellGrammar('echo a # ; /usr/bin/sud? id', 'posix').expandingWords).toEqual(['/usr/bin/sud?']);
    expect(readShellGrammar('echo a # ; sh <<< reboot', 'posix').hereStrings).toEqual(['reboot']);
    expect(readShellGrammar('echo a # | { cat; sh; }', 'posix').otherCommands).toEqual([[
      { text: 'echo a #', join: '; ', fed: false, from: -1 },
      { text: 'cat', join: ' | ', fed: false, from: 0 },
      { text: 'sh', join: '; ', fed: true, from: -1 },
    ]]);
    expect(readShellGrammar('echo a # ; f() { sh; }', 'posix').functionNames).toEqual(['f']);
  });

  it('names the functions a line defines', () => {
    expect(readShellGrammar('f() { sh; }; x | f', 'posix').functionNames).toEqual(['f']);
    expect(readShellGrammar('function g { sh; }', 'posix').functionNames).toEqual(['g']);
    expect(readShellGrammar('function a b { sh; }', 'posix').functionNames).toEqual(['a', 'b']);
    expect(readShellGrammar('a b() { sh; }', 'posix').functionNames).toEqual(['a', 'b']);
    expect(readShellGrammar('function h if x; then y; fi', 'posix').functionNames).toEqual(['h']);
    expect(readShellGrammar('{ sh; }; x | f', 'posix').functionNames).toEqual([]);
  });
});

describe('readShellGrammar: the line with no span and no quote', () => {
  // Given only for a line with a substitution that holds a `case` and an `esac` after
  // it: no count of parentheses says where such a substitution ends, and inside a quoted
  // word nothing else reads what follows it. From the substitution to the line's last
  // `)`: where it does end is one of the parentheses in between.
  const plain = (command: string) => readShellGrammar(command, 'posix').plain;

  it.each([
    ['echo "$(x; (case a in a) :;; esac); reboot)"', ['x; case a in a; :; reboot']],
    ['echo $(case x in x) reboot;; esac)', ['case x in x; reboot']],
    // Nothing before the substitution, and nothing after the last `)`.
    ['sudo -n true; v="$(case $1 in a) echo 1 ;; esac)"; echo "a; reboot"', ['case $1 in a; echo 1']],
    // Up to the last `)`, whatever stands before it: a quoted word, a comment.
    ['v="$(case $1 in a) echo 1 ;; esac)"; echo "run (sudo make) first"', ['case $1 in a; echo 1; ; echo run; sudo make']],
    ['echo "$(case a in a) :;; esac)" # (sudo id)', ['case a in a; :;  #; sudo id']],
    // From the first such substitution on the line.
    ['echo "$(date)" "$(case a in a) :;; esac)" "$(case b in b) reboot;; esac)"', ['case a in a; :;  $; case b in b; reboot']],
  ])('%j', (command, expected) => {
    expect(plain(command)).toEqual(expected);
  });

  it.each([
    ['echo "$(date)"; (id)'],
    ['echo "$(caseless) esac"'],
    // With no `esac` after it the statement is a syntax error, and nothing runs.
    ['echo "$(grep case f)" (sudo id)'],
    ['echo esac "$(grep case f)" (sudo id)'],
    // A backtick span ends at a backtick, whatever parentheses it holds.
    ['echo `case a in a) :;; esac`; x'],
    // Inside a quoted program the substitution is found when the program is read.
    ["sh -c 'echo \"$(case a in a) :;; esac)\"'"],
    ['sudo id'],
  ])('is absent for %j', (command) => {
    expect(plain(command)).toEqual([]);
  });

  it('is found in a reading that has no comments, and is the same whichever way a backslash is read', () => {
    expect(plain('echo a # "$(x; (case a in a) :;; esac); reboot)"')).toEqual(['x; case a in a; :; reboot']);
    expect(readShellGrammar('echo "$(case a in a) :;; esac)" (id)', 'windows').plain).toEqual(plain('echo "$(case a in a) :;; esac)" (id)'));
  });
});

describe('readShellGrammar: one line of the lexer each', () => {
  // What a review found no test for. None of these changes a class today: each is the
  // lexer's own answer, which the classifier reads.
  const read = (command: string) => readShellGrammar(command, 'posix');

  it('a `$[` that never closes is a word, and the line goes on after it', () => {
    expect(read('echo $[ ; reboot').expandingWords).toEqual(['$[']);
    expect(read('echo $[ ; (reboot)').flattened).toBe('echo $[; reboot');
  });

  it('says which command each one in a pipeline is piped from', () => {
    expect(read('a | (b | c)').commands.map((one) => one.from)).toEqual([-1, 0, 1]);
  });

  it('a test alone holds no grammar, and a dropped head after one is dropped', () => {
    expect(read('[[ a ]]').flattened).toBeNull();
    expect(read('if [[ a ]] time b').flattened).toBe('[[ a ]]; b');
  });

  it('the reading that leaves nothing out drops every head, and keeps a pipe before more than one word', () => {
    expect(read('x=(function f function g sudo id)').loose).toEqual(['x=; sudo id']);
    expect(read('( a | b c )').loose).toEqual(['a | b c']);
    expect(read('(').loose).toEqual([]);
  });

  it('a reading that leaves a quote open adds nothing of its own', () => {
    expect(read('(a); echo "${x:-don\'t}"').alternates).toEqual([]);
  });

  it('reads the comment-less text again as it does the usual one', () => {
    expect(read('echo a # ; >f case x in esac; (sudo id)').alternates).toContain('echo a #; sudo id');
  });

  it('gives the commands of another reading once, and only where they differ', () => {
    expect(read('echo a # ; b').otherCommands).toEqual([]);
    expect(read('x | { :; sh; }').otherCommands).toEqual([]);
    expect(read("x | { :; echo $'a' ; sh; }").otherCommands).toHaveLength(1);
  });
});

describe('readShellGrammar: properties', () => {
  const inputs = fc.oneof(anyString, grammarSoup);
  const dialects = fc.constantFrom('posix' as const, 'windows' as const);

  it('never throws', () => {
    fc.assert(
      fc.property(inputs, dialects, (command, dialect) => {
        const reading = readShellGrammar(command, dialect);
        // Whatever comes back is text the classifier can read again.
        for (const one of [reading.flattened, ...reading.alternates, ...reading.loose, ...reading.plain, ...reading.substitutions]) {
          if (one !== null) expect(() => readShellGrammar(one, dialect)).not.toThrow();
        }
      }),
      fcParams(3000),
    );
  });

  // The flattened command is classified as a command of its own, and what comes off it
  // on a second reading is given with the first, never in its place: a second reading
  // can lose a command as well as find one.
  it('gives what a second reading of its result finds, beside the first', () => {
    fc.assert(
      fc.property(inputs, dialects, (command, dialect) => {
        const { flattened, alternates } = readShellGrammar(command, dialect);
        if (flattened === null) return;
        const again = readShellGrammar(flattened, dialect).flattened;
        if (again !== null) expect(alternates, `${flattened} -> ${again}`).toContain(again);
      }),
      fcParams(3000),
    );
  });

  it('keeps the first reading when a second one would lose a command', () => {
    // `case` is a command name after `time` for dash; with `time` gone it would read
    // as a statement with no end, and everything after it as patterns.
    expect(readShellGrammar('x=1; time case x in x) reboot ;; esac', 'posix').flattened).toBe('x=1; case x in x; reboot');
    expect(readShellGrammar('x=1; >/dev/null case x in x) rm -rf / ;; esac', 'posix').flattened).toBe('x=1; case x in x; rm -rf /');
  });

  it('reads a backslash as an escape in the posix dialect only', () => {
    expect(flat('echo \\; (sudo id)', 'posix')).toBe('echo \\;');
    expect(flat('echo \\; (sudo id)', 'windows')).toBe('echo \\; sudo id');
    expect(flat('( echo `a\\` b )', 'posix')).toBe('echo `a\\` b )');
    expect(flat('( echo `a\\` b )', 'windows')).toBe('echo `a\\` b');
  });

  it('returns every word of a command placed inside the grammar', () => {
    fc.assert(
      fc.property(grammarForm, closedCommand, (form, command) => {
        fc.pre(readShellGrammar(command, 'posix').flattened === null);
        // A comment holds no grammar: the classifier's own reading has no comments.
        fc.pre(!form(command).includes(' # '));
        // Glued to a redirection a number is its descriptor, for the shell as well.
        fc.pre(!/\d>\/dev\/null$/.test(form(command)));
        const reading = readShellGrammar(form(command), 'posix');
        // In one reading or another: every word of the command, in order, none dropped.
        const words = command.split(/\s+/).filter((w) => w !== '' && !/^(?:;|&&|\|\||\|)$/.test(w));
        const holds = (text: string) => {
          let from = 0;
          for (const word of words) {
            const at = text.indexOf(word, from);
            if (at === -1) return false;
            from = at + word.length;
          }
          return true;
        };
        const readings = [reading.flattened, ...reading.alternates, ...reading.loose, ...reading.substitutions];
        // Pipelines given one by one hold a two-command input between them.
        const all = readings.filter((text) => text !== null).join('\n');
        expect(readings.some((text) => text !== null && holds(text)) || holds(all), form(command)).toBe(true);
      }),
      fcParams(1000),
    );
  });
});

describe('readShellGrammar: cost grows with the input, not faster', () => {
  const units: Array<[string, (n: number) => string]> = [
    ['open parentheses', (n) => '('.repeat(n)],
    ['groups', (n) => '( x ) '.repeat(n)],
    ['brace groups', (n) => '{ x; } '.repeat(n)],
    ['if blocks', (n) => 'if x; then y; fi; '.repeat(n)],
    ['case blocks', (n) => 'case x in a) y ;; esac; '.repeat(n)],
    ['unclosed case', (n) => 'case x in '.repeat(n)],
    ['redirections', (n) => 'x >f '.repeat(n)],
    ['here-strings', (n) => 'x <<<y; '.repeat(n)],
    ['unclosed substitutions', (n) => '$('.repeat(n)],
    ['unclosed parameter expansions', (n) => '${'.repeat(n)],
    ['backticks', (n) => '`'.repeat(n)],
    ['single quotes', (n) => "'".repeat(n)],
    ['double quotes', (n) => '"'.repeat(n)],
    ['quote then substitutions', (n) => '"' + '$('.repeat(n)],
    ['backslashes', (n) => '\\'.repeat(n)],
    ['comments', (n) => '#x\n'.repeat(n)],
    ['function headers', (n) => 'f() '.repeat(n)],
    ['nested groups', (n) => '('.repeat(n) + 'x' + ')'.repeat(n)],
    ['nested substitutions', (n) => '$('.repeat(n) + 'x' + ')'.repeat(n)],
    ['arithmetic', (n) => '(( x )) '.repeat(n)],
    ['unbalanced double parentheses', (n) => '(('.repeat(n)],
    ['here-strings on one command', (n) => `sh ${'<<<a '.repeat(n)}`],
    ['a pipe into a long group', (n) => `x | { ${'a; '.repeat(n)}}`],
    ['here-documents', (n) => 'cat <<E\n(x)\nE\n'.repeat(n)],
    ['a here-document that never ends', (n) => `cat <<E\n${'(x)\n'.repeat(n)}`],
    ['substitutions in double quotes, nested', (n) => '"$('.repeat(n)],
    ['parameter expansions, nested', (n) => '${x:-'.repeat(n)],
    ['words after a redirection', (n) => `>f ${'if '.repeat(n)}`],
    ['loop heads with no body', (n) => 'for a { '.repeat(n)],
    ['case patterns with alternatives', (n) => `${'a|'.repeat(n)}b) x`],
    ['pattern alternatives that close frames', (n) => `while a; do ${'done|'.repeat(n)}b) x`],
    ['brackets after a dollar', (n) => '$['.repeat(n)],
    ['subscripts that never close', (n) => 'a[ '.repeat(n)],
    ['subscripts that close late', (n) => 'a[ '.repeat(n) + '] '.repeat(n)],
    ['substitutions that hold a case, and no esac before a parenthesis', (n) => '$(case x) '.repeat(n) + 'esac '.repeat(2 * n)],
    ['unclosed process substitutions', (n) => '<('.repeat(n)],
    ['a quote left open after unclosed substitutions', (n) => `${'$('.repeat(n)}'`],
  ];
  it.each(units)('%s', (_name, build) => {
    const small = build(5_000);
    const large = build(20_000);
    const ratio = growthRatio(() => readShellGrammar(small, 'posix'), () => readShellGrammar(large, 'posix'));
    expect(ratio).toBeLessThan(8);
  }, 30_000);
});

describe('readShellGrammar: a substitution that holds a case', () => {
  it.each([
    ['echo "$(case a in a) :;; esac)"', true],
    ['v=$(case $1 in a) echo 1 ;; esac); echo $v', true],
    ['echo "$(x; (case a { a) :;; }); y)"', true],
    ['case $1 in a) echo 1 ;; esac', false],
    // Behind an opener, though outside the substitution: not told apart.
    ['echo "$(date)"; case $1 in a) echo 1 ;; esac', true],
    ['case $1 in a) echo "$(date)" ;; esac', false],
    ['echo $(case x in(x) echo hi;; esac)', true],
    ['echo "$(echo case)"', false],
    ['n=$(grep -c case file.txt); echo "${n} hits"', false],
    ['out=$(mysql -N -e "select case when 1=1 then 1 else 0 end"); echo "${out}"', false],
    ['echo $(echo case esac)', false],
    ['echo "$(case $(echo a b) in a) : ;; esac; x)"', true],
  ] as Array<[string, boolean]>)('%s: %s', (command, holds) => {
    expect(readShellGrammar(command, 'posix').holdsCase).toBe(holds);
  });
});
