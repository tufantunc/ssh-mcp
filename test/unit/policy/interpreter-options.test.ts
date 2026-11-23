import { describe, it, expect } from 'vitest';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';
import { growthRatio } from './cpu-cost.js';

/**
 * The walk from an interpreter to its program allows only flags in between and takes
 * the word after the program flag. Three kinds of invocation run a program it never
 * reached, and each classified `safe`:
 *
 *  - a shell's `-c` is a switch: the program is the first operand, after every other
 *    option and after `--`, and `-o NAME` takes a word of its own;
 *  - an option that takes its value as the next word stood in the way;
 *  - vim and gdb read options after their operands, and vim's `+CMD` is `-c CMD`.
 */
describe('a shell reads its program after its options', () => {
  it.each([
    'sh -c -- reboot',
    "sh -c -- 'reboot'",
    'sh -c -e reboot',
    'sh -o errexit -c reboot',
    'sh +o errexit -c reboot',
    'sh -eo pipefail -c reboot',
    'sh -co errexit reboot',
    'bash -O extglob -c reboot',
    'bash --rcfile /dev/null -c reboot',
    'bash --init-file x -c reboot',
    'bash -euxc reboot',
    'zsh -c -- reboot',
    'env sh -c -- reboot',
    'sh -c -x -- reboot',
    "sh '' -c -- reboot",
  ])('%s', (command) => {
    expect(classifyCommand(command).class).toBe('destructive');
    expect(findForbiddenMatch(command)).not.toBeNull();
  });

  it.each([
    'sh -c -- sudo',
    'bash -o pipefail -c sudo',
    'bash -c -e sudo',
  ])('%s is an elevation', (command) => {
    expect(classifyCommand(command).class).toBe('privileged');
  });

  // What is not the program stays what it was.
  it.each([
    // `$0` and `$1` of a program that is itself harmless.
    "sh -c 'echo hi' reboot",
    "bash -c 'echo $1' _ reboot",
    // A script's own arguments.
    'bash script.sh -c reboot',
    'bash -o pipefail script.sh reboot',
    'bash -- -c reboot-notes',
    // An empty program: the shell runs nothing, and the next word is `$0`.
    "bash -c '' reboot",
    // No `-c` at all.
    'bash -o pipefail script.sh',
    'bash -x script.sh',
    // Guards: read the same before.
    "sh -c -- 'echo hi'",
    "bash -o pipefail -c 'echo hi'",
    "bash -lc 'echo hi'",
  ])('%s stays safe', (command) => {
    expect(classifyCommand(command).class).toBe('safe');
  });
});

describe('an option with a value before the program flag', () => {
  it.each([
    `python3 -W ignore -c 'import os;os.system("id")'`,
    `python3 -X dev -W ignore -c 'import os;os.system("id")'`,
    `python -W ignore -c x`,
    `perl -I lib -e 'system("id")'`,
    `ruby -I lib -e 'system("id")'`,
    `ruby -r json -e 'system("id")'`,
    `node -r ./x -e 'require("child_process").execSync("id")'`,
    `node --require ./x -p 'process.exit()'`,
    `php -d a=b -r 'system("id");'`,
    `lua -l os -e 'os.execute("id")'`,
    `osascript -l JavaScript -e 'app.doShellScript("id")'`,
    `sudo -n true; env python3 -W ignore -c x`,
  ])('%s', (command) => {
    expect(['destructive', 'privileged']).toContain(classifyCommand(command).class);
  });

  it.each([
    // The value is a script or a module: what follows is its own argument list.
    'python3 -u script.py -c config.yml',
    'python3 -m gunicorn -c conf.py app',
    'python3 -W ignore script.py -c config.yml',
    'node server.js -p 3000',
    'node -r ./x server.js -p 3000',
    'ruby -I lib script.rb -e production',
    'php -d a=b script.php -r x',
    'perl -I lib script.pl -e x',
  ])('%s stays safe', (command) => {
    expect(classifyCommand(command).class).toBe('safe');
  });
});

describe('the cost of the walk', () => {
  // Taken up after every value, the walk read the rest of the line once per option.
  it.each(['python3', 'perl', 'ruby', 'php'])('%s with a run of value options is read once', (name) => {
    const option = { python3: '-W', perl: '-I', ruby: '-r', php: '-d' }[name];
    const line = (count: number) => `${name} ${`${option} `.repeat(count)}`;
    expect(growthRatio(() => classifyCommand(line(1_000)), () => classifyCommand(line(4_000)))).toBeLessThan(8);
  }, 60_000);
});

describe('vim and gdb read options after their operands', () => {
  it.each([
    "vim f -c '!id'",
    "vim -u NONE -c '!id'",
    "vim f --cmd '!id'",
    "vim '+!id' f",
    "ex -s '+!id' +q f",
    'view f +q',
    "gdb prog -ex 'shell id'",
    "gdb -p 1 -ex 'shell id'",
    "gdb prog --eval-command='shell id'",
    "sudo -u nobody vim f -c '!id'",
  ])('%s', (command) => {
    expect(['destructive', 'privileged']).toContain(classifyCommand(command).class);
  });

  it.each([
    // A line number, a search, the last line: positions, not commands.
    'vim +10 f',
    'vim + f',
    'vim +/pattern f',
    'vim f',
    // Another program's `+` word.
    'less +F f',
    // After `--` come file names, after gdb's `--args` another program's arguments.
    'vim -- +name.txt',
    'gdb --args ./prog -ex foo',
  ])('%s stays safe', (command) => {
    expect(classifyCommand(command).class).toBe('safe');
  });
});

/**
 * One row for each line of the reader, from the mutation run of review round seven: every
 * entry of the value table, each condition of the shell's option model, the spellings of
 * a name (path, suffix, case), a wrapper in front, and which word is taken for the
 * program (the never-allowed column). The exact class, so a row cannot pass by another
 * route to a higher one.
 */
describe('one line of the reader each', () => {
  it.each([
    ["python -X dev -c x", 'destructive', false],
    ["python -Q old -c x", 'destructive', false],
    ["python --check-hash-based-pycs always -c x", 'destructive', false],
    ["python2 -W ignore -c x", 'destructive', false],
    ["python2 -X dev -c x", 'destructive', false],
    ["python2 -Q old -c x", 'destructive', false],
    ["python3 --check-hash-based-pycs always -c x", 'destructive', false],
    ["ruby -C dir -e x", 'destructive', false],
    ["ruby -E utf-8 -e x", 'destructive', false],
    ["ruby --encoding utf-8 -e x", 'destructive', false],
    ["ruby --external-encoding utf-8 -e x", 'destructive', false],
    ["ruby --internal-encoding utf-8 -e x", 'destructive', false],
    ["node --import ./x -e x", 'destructive', false],
    ["node --loader ./x -e x", 'destructive', false],
    ["node --experimental-loader ./x -e x", 'destructive', false],
    ["node -C dev -e x", 'destructive', false],
    ["node --conditions dev -e x", 'destructive', false],
    ["node --input-type module -e x", 'destructive', false],
    ["node --env-file .env -e x", 'destructive', false],
    ["node --title t -e x", 'destructive', false],
    ["php -c php.ini -r x", 'destructive', false],
    ["php -z ext.so -r x", 'destructive', false],
    ["osascript -s o -e x", 'destructive', false],
    ["bun -r ./x -e x", 'destructive', false],
    ["bun --preload ./x -e x", 'destructive', false],
    ["bun --cwd /tmp -e x", 'destructive', false],
    ["vi f -c '!id'", 'destructive', false],
    ["gvim '+!id' f", 'destructive', false],
    ["vimdiff a b -c '!id'", 'destructive', false],
    ["vim '+!id +1' f", 'destructive', false],
    ["vim -c x f -c", 'destructive', false],
    ["python3.exe -W ignore -c x", 'destructive', false],
    ["VIM f -c '!id'", 'destructive', false],
    ["gdb.exe prog -ex 'shell id'", 'destructive', false],
    ["VIM '+!id' f", 'destructive', false],
    ["flock expect vim f -c '!id'", 'destructive', false],
    ["/usr/bin/vim f -c '!id'", 'destructive', false],
    ["env python3 -W ignore -c x", 'destructive', false],
    ["nohup vim f -c '!id'", 'destructive', false],
    ["timeout 5 vim f -c '!id'", 'destructive', false],
    ["python3 -u -W ignore -c x", 'destructive', false],
    ["python3 '' -W ignore -c x", 'destructive', false],
    ["sh -c - reboot", 'destructive', true],
    ["bash --norc -c -- reboot", 'destructive', true],
    ["sh -c -x '-v; reboot'", 'destructive', true],
    ["sh -c -e 'reboot -f'", 'destructive', true],
    ["sh -o -c -- reboot", 'destructive', true],
    ["flock /tmp/l sh -c -- reboot", 'destructive', true],
    ["/bin/sh -c -- reboot", 'destructive', true],
    ["vim +reboot f", 'destructive', true],
    ["vim f -c reboot", 'destructive', true],
    ["gdb prog --eval-command=reboot", 'destructive', true],
    ["python3 -W ignore -c reboot", 'destructive', true],
    ["vim '+/pat tern' f", 'safe', false],
    ["sh -c -- '' reboot", 'safe', false],
    ["sh -- reboot", 'safe', false],
    // zsh has options that are digits, and bash reads `+c` as it reads `-c`.
    ["sh -c -9 reboot", 'destructive', true],
    ["sh +c reboot", 'destructive', true],
    ["bash -x reboot", 'safe', false],
    ["sh -c -o +o reboot", 'safe', false],
    ["vim f -c", 'safe', false],
    // vim takes a command attached to `-c`: this one is `=x`.
    ["vim f -c=x", 'destructive', false],
    ["vim f --cmdx", 'safe', false],
    ["gdb prog +x", 'safe', false],
    ["python3 script.py -W ignore -c x", 'safe', false],
    ["python3 - -W ignore -c x", 'safe', false],
    ["python3 -- -W ignore -c x", 'safe', false],
    ["echo vim f -c '!id'", 'read-only', false],
    ["grep python3 -W ignore -c x", 'read-only', false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });
});

/**
 * Round eight. The walk past an interpreter's options knows the options that take no
 * value and takes every other one to have one (attached, or the next word): a table of
 * the options with a value left the program unread wherever it lacked an entry. It reads
 * every word of a command whose operands are not data, as the walk beside it does, so a
 * wrapper no table lists hides nothing. Each line below was `safe` before.
 */
describe('options known to take no value, every word read', () => {
  it.each([
    ["unshare -m sh -c -- reboot", "destructive", true],
    ["docker exec c sh -c -- reboot", "destructive", true],
    ["kubectl exec p -- sh -c -e reboot", "destructive", true],
    ["systemd-run sh -o errexit -c reboot", "destructive", true],
    ["unknowntool bash -euxc reboot", "destructive", true],
    ["unknowntool python3 -W ignore -c CODE", "destructive", false],
    ["unshare -m vim f -c '!id'", "destructive", false],
    ["bash +c reboot", "destructive", true],
    ["bash -rcfile F -c reboot", "destructive", true],
    ["zsh -4c reboot", "destructive", true],
    ["zsh -c -oerrexit reboot", "destructive", true],
    ["ksh -R f -c reboot", "destructive", true],
    ["python3 -BW ignore -c CODE", "destructive", false],
    ["perl -wI lib -e CODE", "destructive", false],
    ["perl -e'system(q(reboot))'", "destructive", true],
    ["python3 -c\"import(os)\"", "destructive", false],
    ["perl -lane CODE", "destructive", false],
    ["node --max-old-space-size 4096 -e CODE", "destructive", false],
    ["ruby --backtrace-limit 3 -e CODE", "destructive", false],
    ["bun --port 3000 -e CODE", "destructive", false],
    ["php -B CODE", "destructive", false],
    ["php -R CODE", "destructive", false],
    ["php -E CODE", "destructive", false],
    ["php --run CODE", "destructive", false],
    ["bun --eval CODE", "destructive", false],
    ["bun -p CODE", "destructive", false],
    ["gdb --ex 'shell id'", "destructive", false],
    ["gdb -eval-command 'shell id'", "destructive", false],
    ["gdb -eval-c 'shell id'", "destructive", false],
    ["gdb -eiex 'shell id'", "destructive", false],
    ["python3.11 -c CODE", "destructive", false],
    ["python3.12 -W ignore -c CODE", "destructive", false],
    ["nvim -c '!id'", "destructive", false],
    ["nvim f '+!id'", "destructive", false],
    ["nodejs -e CODE", "destructive", false],
    ["mksh -c reboot", "destructive", true],
    ["mksh -c -- reboot", "destructive", true],
    ["fish -c reboot", "destructive", true],
    ["ksh93 -c -- reboot", "destructive", true],
    ["pypy3 -c CODE", "destructive", false],
    ["luajit -e CODE", "destructive", false],
    ["lua5.4 -l os -e CODE", "destructive", false],
    ["vim '+/x|!id' f", "destructive", false],
    ["python3 -Z val -c CODE", "destructive", false],
    ["node --unknown-flag val -e CODE", "destructive", false],
    ["deno -L debug eval CODE", "destructive", false],
    ["expect -D 1 -c CODE", "destructive", false],
    ["unknowntool perl -e'system(q(reboot))'", "destructive", true],
    ["gdb prog -ie 'shell id'", "destructive", false],
    ["gdb prog --early-init-eval-command 'shell id'", "destructive", false],
    ["fish --command=reboot", "destructive", true],
    ["fish -C reboot", "destructive", true],
    ["zsh --emulate MODE -c reboot", "destructive", true],
    ["csh -fc reboot", "destructive", true],
    ["tcsh -c reboot", "destructive", true],
    ["ruby -wlne CODE", "destructive", false],
    ["python3 -BEsc CODE", "destructive", false],
    ["unknowntool php -d a=b -r CODE", "destructive", false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });

  // Read before this round by another route (a cluster of three letters, an operand
  // with a space in it, the walk beside this one): they keep their answer.
  it.each([
    ["zsh --emulate sh -c reboot", "destructive", true],
    ["zsh -onoclobber -c reboot", "destructive", true],
    ["perl -pi.bak -e CODE f", "destructive", false],
    ["perl -pie CODE f", "destructive", false],
    ["gdb --init-eval-command='shell id'", "destructive", false],
    ["fish -c 'sudo id'", "privileged", false],
    ["csh -fc 'sudo id'", "privileged", false],
    ["unknowntool perl -lne CODE", "destructive", false],
    ["sudo -u app python3.11 -W ignore -c CODE", "privileged", false],
    ["python3 -Bc CODE", "destructive", false],
    ["ruby -ne CODE", "destructive", false],
    ["node -pe CODE", "destructive", false],
    ["php -nr CODE", "destructive", false],
    ["vim -c!id f", "destructive", false],
  ] as Array<[string, string, boolean]>)('%s is still %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });

  // A script's own arguments, another command's options that hold a program letter, and
  // a name that is a file, a branch or a package: read as they were.
  it.each([
    ["python3 -u train.py -c cfg", "safe", false],
    ["python3 -m gunicorn -c conf.py", "safe", false],
    ["python3 -Wignore script.py -c cfg", "safe", false],
    ["python3 -X dev script.py -c cfg", "safe", false],
    ["node server.js -p 3000", "safe", false],
    ["node --inspect server.js -p 3000", "safe", false],
    ["node --max-old-space-size=4096 server.js -e x", "safe", false],
    ["node --no-warnings server.js -p 3000", "safe", false],
    ["perl -w script.pl -e x", "safe", false],
    ["perl -Ilib script.pl -e x", "safe", false],
    ["ruby -Ilib script.rb -e x", "safe", false],
    ["ruby -rjson script.rb -e x", "safe", false],
    ["ruby -rtime script.rb -e x", "safe", false],
    ["php -d memory_limit=1G artisan migrate -r", "safe", false],
    ["php artisan migrate -r", "safe", false],
    ["bash script.sh -c x", "safe", false],
    ["bash --norc script.sh reboot", "safe", false],
    ["bash -l script.sh reboot", "safe", false],
    ["bash -x deploy.sh reboot", "safe", false],
    ["sh deploy.sh -c reboot", "safe", false],
    ["zsh --no-rcs script.zsh", "safe", false],
    ["find . -name perl -type f", "read-only", false],
    ["find . -name perl -newer f", "read-only", false],
    ["find / -name python3 -o -name python", "read-only", false],
    ["vim f +10", "safe", false],
    ["vim +/pattern f", "safe", false],
    ["vim -u NONE f", "safe", false],
    ["gdb --args ./prog -ex foo", "safe", false],
    ["gdb -q ./prog core", "safe", false],
    ["bun run build -e x", "safe", false],
    ["bun install", "safe", false],
    ["lua script.lua -e x", "safe", false],
    ["man perl", "safe", false],
    ["apt-get install -y python3 perl", "safe", false],
    ["kubectl get node -o wide", "safe", false],
    ["git switch view", "safe", false],
    ["pip install ruby", "safe", false],
    ["tar czf node.tgz -C /tmp node", "safe", false],
    ["useradd -s /bin/bash -c 'Full Name' bob", "safe", false],
    ["deno run script.ts -e x", "safe", false],
    ["Rscript --vanilla script.R -e x", "safe", false],
    // bash reads `-norc` as its long option and runs the script; read as a cluster of
    // letters it had a `c` in it, and `reboot` was taken for the program.
    ["bash -norc deploy.sh reboot", "safe", false],
    ["gdb prog -e file", "safe", false],
    ["gdb prog -exec file", "safe", false],
    ["gdb prog -x cmds", "safe", false],
    ["python3 -c", "safe", false],
    ["perl script.pl -lane x", "safe", false],
    ["unknowntool perl -eval-c", "safe", false],
  ] as Array<[string, string, boolean]>)('%s stays %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });

  // The walk beside this one takes the word after the first program flag it knows. A
  // flag it has not learnt leaves these as they are on 2.26.0: `-r` and `-eval-c` hand
  // over `sudo …`, which `-B` and `--eval-command=x` would hand `-r` and `''` instead.
  it.each([
    ["php -B -r 'sudo id'", 'privileged'],
    ["bun --rcfile --eval-command=x '' -eval-c sudo", 'privileged'],
  ])('a program flag only this walk reads lowers nothing: %s', (command, expected) => {
    expect(classifyCommand(command).class).toBe(expected);
  });

  // Which long options take a word is known for bash and for zsh by their names. For
  // any other shell the word after one is taken both ways.
  it.each([
    ['env sh -rcfile -BW -t --emulate reboot', 'destructive', true],
    ['sh --rcfile F -c reboot', 'destructive', true],
    ['ksh --emulate MODE -c reboot', 'destructive', true],
    ['bash -rcfile reboot -r', 'safe', false],
    ['bash --rcfile reboot -x', 'safe', false],
    ['zsh --emulate reboot -x', 'safe', false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });

  // Every word may be an interpreter's name, and each one's walk reads on past the
  // values of its options: a walk that reaches a word another has read stops there.
  it.each([
    ['vim', (n: number) => `x ${'vim '.repeat(n)}`],
    ['gdb with commands', (n: number) => `x ${'gdb -ex a '.repeat(n)}`],
    ['python3 and a value option', (n: number) => `x ${'python3 -W '.repeat(n)}`],
    ['perl and an option not known', (n: number) => `x ${'perl -Z '.repeat(n)}`],
    ['a shell and a long option', (n: number) => `x ${'sh --a '.repeat(n)}`],
    ['a shell, switched, and a long option', (n: number) => `x sh -c ${'--a sh '.repeat(n)}`],
    ['node and php in turn', (n: number) => `x ${'node --a php -Z '.repeat(n)}`],
  ] as Array<[string, (n: number) => string]>)('a line of names is walked once: %s', (_name, build) => {
    const small = build(500);
    const large = build(2_000);
    expect(growthRatio(() => classifyCommand(small), () => classifyCommand(large))).toBeLessThan(8);
  }, 60_000);
});

/**
 * The tables themselves, one line for each entry. A switch that the table lacked would
 * be taken to have a value: the script after it would be skipped as that value and the
 * script's own `-c x` read as the interpreter's. So each line below is `safe` only
 * while its option is known for what it is.
 */
describe('each option the walk knows', () => {
  const safe = (command: string) => expect(classifyCommand(command).class, command).toBe('safe');

  // [interpreter, its program flag, switches, letters whose value is attached only,
  //  letters whose value is attached or the next word, letters that end the options]
  const LETTERS: Array<[string, string, string, string, string, string]> = [
    ['python3', '-c', 'bBdEhiIOPqRsStuvVx', '', 'WXQ', 'm'],
    ['perl', '-e', 'acCdDfghlnpsStTuUvVwWX', 'FimMx', 'I', ''],
    ['ruby', '-e', 'acdhKlnpsSTUvwWy', 'Fix', 'CEIrX', ''],
    ['node', '-e', 'chiv', '', 'rC', ''],
    ['php', '-r', 'aCehHilmnqsvw', '', 'cdfFStz', ''],
    ['lua', '-e', 'iEvW', 'O', 'lj', 'b'],
    ['osascript', '-e', 'i', '', 'ls', ''],
    ['bun', '-e', 'bhiv', '', 'rF', ''],
    ['expect', '-c', 'dinNv', '', 'bDf', ''],
    ['fish', '-c', 'hilnNPv', '', 'dfop', ''],
    ['csh', '-c', 'bdefilmnqstvVxX', '', '', ''],
    ['deno', 'eval', 'hqV', '', 'L', ''],
  ];
  const each = (pick: (row: (typeof LETTERS)[number]) => string) =>
    LETTERS.flatMap((row) => [...pick(row)].map((letter): [string, string, string] => [row[0], row[1], letter]));

  it.each(each((row) => row[2]))('%s (%s): -%s is a switch', (name, flag, letter) => {
    safe(`${name} -${letter} script ${flag} x`);
  });
  it.each(each((row) => row[3]))('%s (%s): the value of -%s is attached', (name, flag, letter) => {
    safe(`${name} -${letter} script ${flag} x`);
    safe(`${name} -${letter}.v script ${flag} x`);
  });
  it.each(each((row) => row[4]))('%s (%s): the value of -%s is attached or the next word', (name, flag, letter) => {
    safe(`${name} -${letter}.v script ${flag} x`);
    expect(classifyCommand(`${name} -${letter} v ${flag} x`).class).toBe('destructive');
  });
  it.each(each((row) => row[5]))('%s (%s): -%s ends the options', (name, flag, letter) => {
    safe(`${name} -${letter} module ${flag} x`);
  });

  const LONG: Array<[string, string, string[]]> = [
    ['python3', '-c', ['--help', '--version', '--help-env', '--help-xoptions', '--help-all']],
    ['ruby', '-e', ['--copyright', '--debug', '--verbose', '--version', '--help', '--yydebug', '--jit', '--yjit', '--zjit',
      '--rjit', '--mjit', '--profile', '--enable-frozen-string-literal', '--disable-gems', '--yjit-stats']],
    ['node', '-e', [
      '--abort-on-uncaught-exception', '--allow-addons', '--allow-child-process', '--allow-inspector',
      '--allow-openssl-store', '--allow-wasi', '--allow-worker', '--build-snapshot', '--check',
      '--completion-bash', '--cpu-prof', '--disable-sigusr1', '--disable-wasm-trap-handler',
      '--disallow-code-generation-from-strings', '--enable-etw-stack-walking', '--enable-fips',
      '--enable-fips-indicator-events', '--enable-network-family-autoselection', '--enable-source-maps',
      '--entry-url', '--experimental-addon-modules', '--experimental-default-config-file',
      '--experimental-eventsource', '--experimental-import-meta-resolve', '--experimental-import-text',
      '--experimental-inspector-network-resource', '--experimental-network-inspection',
      '--experimental-print-required-tla', '--experimental-storage-inspection', '--experimental-stream-iter',
      '--experimental-strip-types', '--experimental-test-coverage', '--experimental-test-module-mocks',
      '--experimental-transform-types', '--experimental-vm-modules', '--experimental-webstorage',
      '--experimental-worker-inspection', '--expose-gc', '--force-context-aware', '--force-fips',
      '--force-node-api-uncaught-exceptions-policy', '--frozen-intrinsics', '--harmony', '--heap-prof',
      '--help', '--insecure-http-parser', '--inspect', '--inspect-brk', '--inspect-wait', '--interactive',
      '--interpreted-frames-native-stack', '--jitless', '--node-memory-debug', '--openssl-legacy-provider',
      '--openssl-shared-config', '--pending-deprecation', '--permission', '--permission-audit',
      '--preserve-symlinks', '--preserve-symlinks-main', '--prof', '--prof-process', '--report-compact',
      '--report-exclude-env', '--report-exclude-network', '--report-on-fatalerror', '--report-on-signal',
      '--report-uncaught-exception', '--require-module', '--test', '--test-force-exit', '--test-only',
      '--test-randomize', '--test-update-snapshots', '--throw-deprecation', '--tls-max-v1.2',
      '--tls-max-v1.3', '--tls-min-v1.0', '--tls-min-v1.1', '--tls-min-v1.2', '--tls-min-v1.3',
      '--trace-deprecation', '--trace-env', '--trace-env-js-stack', '--trace-env-native-stack',
      '--trace-exit', '--trace-promises', '--trace-sigint', '--trace-sync-io', '--trace-tls',
      '--trace-uncaught', '--trace-warnings', '--track-heap-objects', '--use-bundled-ca', '--use-env-proxy',
      '--use-openssl-ca', '--use-strict', '--use-system-ca', '--v8-options', '--version', '--watch',
      '--watch-preserve-output', '--zero-fill-buffers',
      '--no-warnings', '--experimental-modules', '--trace-gc', '--expose_gc', '--harmony-top-level-await',
    ]],
    ['php', '-r', ['--interactive', '--no-chdir', '--no-header', '--no-php-ini', '--info', '--syntax-check', '--modules',
      '--syntax-highlight', '--syntax-highlighting', '--strip', '--version', '--help', '--usage', '--ini']],
    ['bun', '-e', [
      '--bun', '--cpu-prof', '--cpu-prof-md', '--experimental-http2-fetch', '--experimental-http3-fetch',
      '--expose-gc', '--heap-prof', '--heap-prof-md', '--help', '--hot', '--if-present', '--parallel',
      '--prefer-latest', '--prefer-offline', '--redis-preconnect', '--revision', '--sequential', '--silent',
      '--smol', '--sql-preconnect', '--throw-deprecation', '--use-bundled-ca', '--use-openssl-ca',
      '--use-system-ca', '--version', '--watch', '--workspaces', '--zero-fill-buffers',
      '--no-install', '--inspect', '--inspect-brk', '--inspect-wait',
    ]],
    ['Rscript', '-e', ['--vanilla', '--verbose', '--anything']],
    ['deno', 'eval', ['--help', '--quiet', '--version']],
    ['fish', '-c', ['--help', '--interactive', '--login', '--no-config', '--no-execute', '--private', '--version',
      '--print-rusage-self', '--print-debug-categories']],
  ];
  it.each(LONG.flatMap(([name, flag, options]) => options.map((option): [string, string, string] => [name, option, flag])))(
    '%s: %s takes no value',
    (name, option, flag) => {
      safe(`${name} ${option} script ${flag} x`);
    },
  );

  // And the other way: an option in none of the tables is taken to have a value.
  it.each([
    'python3 -Z script -c x', 'python3 --new script -c x', 'perl -Z script -e x', 'ruby --new script -e x',
    'node --new script -e x', 'php -Z script -r x', 'lua -Z script -e x', 'bun --new script -e x',
    'osascript -Z script -e x', 'expect -Z script -c x', 'fish --new script -c x', 'csh -Z script -c x',
  ])('%s is destructive', (command) => {
    expect(classifyCommand(command).class).toBe('destructive');
  });
});

/**
 * One line for each condition of the three walks that the rows above left free: a
 * mutation run over them (162 single changes) found 73 that no test noticed.
 */
describe('one condition of the walks each', () => {
  it.each([
    ["sh -c --a x y reboot", "safe", false],
    ["sh -o -c x reboot", "safe", false],
    ["sh -c --a -x p reboot", "safe", false],
    ["sh -c -- -x reboot", "safe", false],
    ["sh -c - -x reboot", "safe", false],
    ["zsh -c --emulate reboot x", "safe", false],
    ["sh -c --norc x reboot", "destructive", true],
    ["sh -c -Oe x reboot", "destructive", true],
    ["sh -c -Te x reboot", "destructive", true],
    ["sh -c -o a x reboot", "safe", false],
    ["sh -rcfile F reboot", "destructive", true],
    ["rbash --norc x -c reboot", "safe", false],
    ["bash --zz --norc x -c reboot", "safe", false],
    ["bash --debug x -c reboot", "safe", false],
    ["bash --debugger x -c reboot", "safe", false],
    ["bash --dump-po-strings x -c reboot", "safe", false],
    ["bash --dump-strings x -c reboot", "safe", false],
    ["bash --help x -c reboot", "safe", false],
    ["bash --login x -c reboot", "safe", false],
    ["bash --noediting x -c reboot", "safe", false],
    ["bash --noprofile x -c reboot", "safe", false],
    ["bash --norc x -c reboot", "safe", false],
    ["bash --posix x -c reboot", "safe", false],
    ["bash --pretty-print x -c reboot", "safe", false],
    ["bash --restricted x -c reboot", "safe", false],
    ["bash --verbose x -c reboot", "safe", false],
    ["bash --version x -c reboot", "safe", false],
    ["pdksh -c -- reboot", "destructive", true],
    ["oksh -c -- reboot", "destructive", true],
    ["lksh -c -- reboot", "destructive", true],
    ["rksh -c -- reboot", "destructive", true],
    ["rbash -c -- reboot", "destructive", true],
    ["yash -c -- reboot", "destructive", true],
    ["posh -c -- reboot", "destructive", true],
    ["bash-5.2 -c -- reboot", "destructive", true],
    ["python3 -Z -B script -c x", "safe", false],
    ["node --eval x --eval reboot", "destructive", true],
    ["perl -e x -e reboot", "destructive", true],
    ["unknowntool perl -I lib -lne CODE", "destructive", false],
    ["unknowntool perl -type f -e CODE", "destructive", false],
    ["perl -e'reboot;' f", "destructive", true],
    ["node -r x -pe reboot", "destructive", true],
    ["python3 -W x -cexit", "destructive", false],
    ["perl -I lib -0777ne CODE", "destructive", false],
    ["perl -d:Trace script -e x", "safe", false],
    ["python3 -W x -Zc CODE", "destructive", false],
    ["gdb -args ./p -ex foo", "safe", false],
    ["vim f --args -c x", "destructive", false],
    ["vim f -c -- -c reboot", "destructive", true],
    ["gdb p -ex -- -ex reboot", "destructive", true],
    ["x -c sh -c -- reboot", "destructive", true],
    ["php -B -r sudo", "privileged", false],
    ["php --process-begin CODE", "destructive", false],
    ["php --process-code CODE", "destructive", false],
    ["php --process-end CODE", "destructive", false],
    ["bun --print CODE", "destructive", false],
    ["pypy -c CODE", "destructive", false],
    ["pypy3 -W x -c CODE", "destructive", false],
    ["jruby -e CODE", "destructive", false],
    ["gdb-multiarch p -ex x", "destructive", false],
    ["fish --init-command reboot", "destructive", true],
    ["gdb p -init-eval-command x", "destructive", false],
    ["rvim f -c x", "destructive", false],
    ["rview f -c x", "destructive", false],
    ["gview f -c x", "destructive", false],
    ["vim.tiny f -c x", "destructive", false],
    ["vim.basic f -c x", "destructive", false],
    ["vim.nox f -c x", "destructive", false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });
});

/**
 * Round eight's reviews. bash reads a long option with one dash only before its first
 * cluster; vim and gdb are walked again behind a `--` that stopped an earlier walk;
 * letters that were modelled wrongly (expect `-f`/`-b`, php `-f`/`-F`, zsh `-O`, perl
 * `-0x…`, ruby `-T`); vim's clusters; a shell behind a flag spelled like its own. And
 * what must not rise: a host or a pod named like an interpreter with a number, a name
 * that is a long option's value, switches of older node and V8, `view` as a word.
 */
describe('round eight, one line each', () => {
  it.each([
    ["bash -c -rcfile reboot", "destructive", true],
    ["bash -x -rcfile reboot", "destructive", true],
    ["bash -c -verbose errexit reboot", "destructive", true],
    ["bash -c -posix errexit reboot", "destructive", true],
    ["env -u ex -- vim f -c '!reboot'", "destructive", false],
    ["kubectl exec view -- vim f -c '!reboot'", "destructive", false],
    ["env -u gdb -- gdb p -ex 'shell id'", "destructive", false],
    ["expect -f x -c CODE", "destructive", false],
    ["expect -b x -c CODE", "destructive", false],
    ["php -F x.php -B CODE", "destructive", false],
    ["php -f x.php -r CODE", "destructive", false],
    ["zsh -c -O reboot", "destructive", true],
    ["zsh -c -JO reboot", "destructive", true],
    ["bash -c -O extglob reboot", "destructive", true],
    ["perl -0x1Fne CODE", "destructive", false],
    ["ruby -T1e CODE", "destructive", false],
    ["vim -nNesc '!reboot'", "destructive", false],
    ["vim -Nc'!reboot'", "destructive", false],
    ["unshare -c sh -c reboot", "destructive", true],
    ["redis-cli -h node1 -p 6379 ping", "safe", false],
    ["kubectl logs node-0 -p --tail=100", "safe", false],
    ["ansible-playbook site.yml -l node01 -e env=prod", "safe", false],
    ["kubectl logs deploy/python -n prod -c app", "safe", false],
    ["node --trace-gc app.js -e production", "safe", false],
    ["node --expose_gc bench.js -p 1", "safe", false],
    ["bun --inspect server.ts -p 3000", "safe", false],
    ["docker run -d --name node --restart always -e NODE_ENV=production -p 3000:3000 app", "safe", false],
    ["gh pr view 123 -c --json title", "safe", false],
    ["docker exec app perl -Ilib bin/app.pl -e prod", "safe", false],
    ["x --flag python3 -W ignore -c CODE", "destructive", false],
    ["x python3 -Z v -c CODE", "destructive", false],
    ["python3.11 -W ignore -c CODE", "destructive", false],
    ["ksh93 -c -- reboot", "destructive", true],
    ["pypy3 -W x -c CODE", "destructive", false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });

});
