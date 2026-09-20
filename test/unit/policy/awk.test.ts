import { describe, it, expect } from 'vitest';
import { classifyCommand, nestedCommands } from '../../../src/policy/classifier.js';
import { readAwkInvocation } from '../../../src/policy/awk.js';

/**
 * #184: an awk program can start a process or write a file while the command
 * classifies `safe`.
 *
 * Split out of GHSA-qvx5-rxrj-9vfh, whose fix shipped in 2.6.0 and deliberately
 * left awk out — two review rounds had produced five attempts and each was holed
 * by the next. The false-positive set below is not decoration: every entry in it
 * is a shape one of those five attempts broke, so a fix that gates them has
 * reproduced a known failure rather than found a new one.
 *
 * Asserted through `classifyCommand` rather than against the reader directly,
 * because the class is what the approval gate reads and the reader's output is
 * only an input to it.
 */

const classOf = (command: string) => classifyCommand(command).class;

describe('an awk program that starts a process', () => {
  // The class is `privileged`, not merely `destructive`: the command inside
  // `system()` is handed to `nestedCommands` and classified as itself, so the
  // audit record and the refusal name `sudo id` rather than "an awk program".
  it.each([
    `awk 'BEGIN{system("sudo id")}'`,
    `awk -F ':' 'BEGIN{system("sudo id")}'`,
    `awk -v n=1 'BEGIN{system("sudo id")}'`,
    `awk -F: -v n=1 'BEGIN{system("sudo id")}'`,
  ])('is privileged, and names the elevated binary: %s', (command) => {
    const parsed = classifyCommand(command);
    expect(parsed.class).toBe('privileged');
    expect(parsed.binary).toBe('id');
  });

  it('reads system() in every awk spelling', () => {
    for (const name of ['awk', 'gawk', 'mawk', 'nawk']) {
      expect(classOf(`${name} 'BEGIN{system("sudo id")}'`), name).toBe('privileged');
    }
  });

  it('hands the inner command to the classifier, verbatim', () => {
    // Asserted on `nestedCommands` rather than on the class, because the class
    // collapses this. Measured: with the awk reader disabled outright, both
    // `.class` assertions this replaced still passed — the first because the raw
    // text matches the `rm -rf` pattern with no awk reading at all, the second
    // because `safe` is the default for anything unrecognised.
    expect(nestedCommands(`awk 'BEGIN{system("rm -rf /var/lib/thing")}'`))
      .toEqual(['rm -rf /var/lib/thing']);
    expect(nestedCommands(`awk 'BEGIN{system("ls")}'`)).toEqual(['ls']);
    expect(classOf(`awk 'BEGIN{system("rm -rf /var/lib/thing")}'`)).toBe('destructive');
  });

  it('is not switched off by an explicitly empty flag value', () => {
    // Through `classifyCommand`, not the reader: the defect was in the
    // *tokenizer*, which dropped a quoted empty word, so the reader saw three
    // words instead of four and consumed the program as `-F`'s value. It then
    // reported "this invocation runs no program" and the whole gate went silent
    // for a five-character edit. Real awk warns about the empty FS and runs the
    // program anyway — measured, including the file write.
    expect(classOf(`awk -F '' 'BEGIN{system("sudo id")}'`)).toBe('privileged');
    expect(classOf(`awk -F "" 'BEGIN{system("sudo id")}'`)).toBe('privileged');
    // With a data file after it, so a bail-out on "no operand left" would not
    // have been enough: the filename would have been read as the program.
    expect(classOf(`awk -F '' 'BEGIN{system("sudo id")}' /etc/passwd`)).toBe('privileged');
    expect(classOf(`awk -F '' '{print "p" > "/etc/cron.d/x"}'`)).toBe('destructive');
    expect(classOf(`awk -v '' 'BEGIN{system("sudo id")}'`)).toBe('privileged');
  });

  it('reads a path-qualified awk', () => {
    expect(classOf(`/usr/bin/awk 'BEGIN{system("sudo id")}'`)).toBe('privileged');
    expect(classOf(`/bin/gawk 'BEGIN{print "x" > "/etc/passwd"}'`)).toBe('destructive');
  });

  it("reads gawk's coprocess operator, not only the plain pipe", () => {
    expect(classOf(`awk 'BEGIN{print "x" |& "sudo tee /etc/passwd"}'`)).toBe('privileged');
    expect(classOf(`awk 'BEGIN{"sudo id" |& getline r; print r}'`)).toBe('privileged');
  });

  it('decodes octal and hex escapes, which change the bytes the shell gets', () => {
    // Every awk decodes these. Reading them literally meant the string handed to
    // the classifier was not the command that runs — measured on BWK awk
    // 20200816, `system("\\163udo id")` runs `sudo id` — and the raw text also
    // slips past the never-allowed list, which matches on the text as sent.
    expect(classOf(`awk 'BEGIN{system("\\163udo id")}'`)).toBe('privileged');
    expect(classOf(`awk 'BEGIN{system("\\x73udo id")}'`)).toBe('privileged');
    // `privileged`, not `destructive`: once the escape is decoded the target is
    // `sudo sh`, and the classifier reads it as itself.
    expect(classOf(`awk 'BEGIN{print "x" | "\\163udo sh"}'`)).toBe('privileged');
    expect(classOf(`awk 'BEGIN{system("\\162m -rf \\057")}'`)).toBe('destructive');
    expect(nestedCommands(`awk 'BEGIN{system("\\163udo id")}'`)).toEqual(['sudo id']);
  });

  it('is not fooled by an escaped quote re-pairing the string delimiters', () => {
    expect(classOf(`awk 'BEGIN{s="\\""; system("sudo id"); t="\\""}'`)).toBe('privileged');
    expect(classOf(`awk '"" || system("sudo id") || ""'`)).toBe('privileged');
  });

  it('reads a command piped out of print, and one piped into getline', () => {
    expect(classOf(`awk 'BEGIN{print "x" | "sudo tee /etc/passwd"}'`)).toBe('privileged');
    expect(classOf(`awk 'BEGIN{"sudo id" | getline r; print r}'`)).toBe('privileged');
  });

  it('refuses to guess at a command it cannot read in full', () => {
    // Assembled at run time. Reading the literal half and classifying that would
    // describe a command that never runs.
    expect(classOf(`awk -v f=/etc 'BEGIN{system("rm -rf " f)}'`)).toBe('destructive');
    expect(classOf(`awk -v c=id 'BEGIN{c | getline r; print r}'`)).toBe('destructive');
    expect(classOf(`awk -v c=id 'BEGIN{print "x" | c}'`)).toBe('destructive');
  });

  it('refuses a concatenated command rather than classifying half of it', () => {
    // awk joins adjacent literals into the command it runs, so reading only one
    // of them classifies a *shorter* command than the one that executes — the
    // single shape in this module that could lower a class rather than raise it.
    // Measured on BWK awk: `"ech" "o CONCAT" | getline` runs `echo CONCAT`.
    expect(classOf(`awk 'BEGIN{"sudo" " id" | getline v}'`)).toBe('destructive');
    expect(classOf(`awk 'BEGIN{print "x" | "id" "; sudo sh"}'`)).toBe('destructive');
  });

  it('gates a program that pipes its output into an interpreter', () => {
    // The awk spelling of `echo "sudo id" | sh`, which this repo already gates
    // through `readsProgramFromStdin`. Classifying the target alone says `sh`,
    // which is not dangerous; what is dangerous is what awk prints into it, and
    // that is assembled at run time.
    for (const shell of ['sh', '/bin/sh', 'bash']) {
      expect(classOf(`awk 'BEGIN{print "sudo id" | "${shell}"}'`), shell).toBe('destructive');
    }
    // A pipe target that is not an interpreter is still classified as itself.
    expect(classOf(`awk 'BEGIN{print "x" | "sudo tee /etc/passwd"}'`)).toBe('privileged');
  });

  it('treats a word that is not reserved as a variable, so the / after it divides', () => {
    // `and`, `or`, `not` and `case` are ordinary identifiers in POSIX awk, BWK
    // awk, mawk and busybox awk — verified locally: `BEGIN{not=4; print not/2}`
    // prints 2. Listing them as keywords made the lexer open a regex where awk
    // divides, and the regex swallowed everything up to the next `/`.
    for (const word of ['not', 'or', 'and', 'case']) {
      expect(classOf(`awk 'BEGIN{${word}=2; x = ${word} / system("sudo id") / 3}'`), word)
        .toBe('privileged');
    }
    // `getline` is the mirror case: it is reserved, but it yields a value, so an
    // operand has ended and the `/` divides.
    expect(classOf(`awk 'BEGIN{x = getline / system("sudo id") / 2}'`)).toBe('privileged');
    expect(classOf(`awk 'BEGIN{f="/root/.ssh/authorized_keys"; not=4; print not / 2 > f}'`))
      .toBe('destructive');
  });
});

describe("an awk program that writes a file", () => {
  it('gates output redirection, which needs no system() at all', () => {
    expect(classOf(`awk 'BEGIN{print "ssh-rsa AAAA" > "/root/.ssh/authorized_keys"}'`))
      .toBe('destructive');
    expect(classOf(`awk 'BEGIN{print "x" >> "/root/.ssh/authorized_keys"}'`))
      .toBe('destructive');
  });

  it('keeps an output statement open across a backslash-newline continuation', () => {
    // The continuation joins the lines, so the `>` still belongs to the print.
    // Without it the newline closes the statement and a genuine file write reads
    // as a comparison — measured: destructive becomes safe.
    expect(classOf("awk '{print $1 \\\n > \"/tmp/f\"}'")).toBe('destructive');
  });

  it('gates a redirection whose target is computed', () => {
    expect(classOf(`awk '{print $1 > $2}'`)).toBe('destructive');
  });

  it('gates a redirection from printf, with or without parentheses', () => {
    expect(classOf(`awk 'BEGIN{printf "%s\\n", "x" > "/etc/hosts"}'`)).toBe('destructive');
    expect(classOf(`awk 'BEGIN{printf("%s\\n", "x") > "/etc/hosts"}'`)).toBe('destructive');
  });

  it('leaves the standard streams alone, which scripts write to routinely', () => {
    for (const target of ['/dev/stderr', '/dev/stdout', '/dev/null', '/dev/fd/1', '/dev/fd/2']) {
      expect(classOf(`awk 'BEGIN{print "note" > "${target}"}'`), target).toBe('safe');
    }
  });
});

describe('an awk invocation this process cannot read', () => {
  it('gates a program that lives in a file', () => {
    expect(classOf('awk -f /tmp/evil.awk data.txt')).toBe('destructive');
    expect(classOf('awk -f- data.txt')).toBe('destructive');
  });

  it("gates gawk's indirect call and its directives", () => {
    // `@f(...)` chooses the function at run time, so the name is not in the text.
    expect(classOf(`gawk 'BEGIN{f="system"; @f("sudo id")}'`)).toBe('destructive');
    expect(classOf(`gawk '@include "evil"; BEGIN{print}'`)).toBe('destructive');
  });

  it('gates a flag the four implementations disagree about', () => {
    // gawk consumes a value for -i and -W, mawk rejects -i, and BWK awk ignores
    // an unknown option WITHOUT consuming it and runs the next operand. Any
    // table that guesses hands the reader the data file instead of the program.
    for (const flag of ['-W interactive', '-i inplace', '--source', '-E', '--re-interval', '-W']) {
      expect(classOf(`awk ${flag} '{print $1}' data.txt`), flag).toBe('destructive');
    }
  });

  it('refuses a program too large to be worth reading', () => {
    // Linear is not the same as bounded: with `commandMaxChars = 0` — the config
    // spelling of unlimited — a 1MB program of `system()` calls measured 2.1s on
    // the thread that serves every other tool call. Above the bound it is the
    // module's existing "we cannot read this" answer, which costs nothing.
    const huge = `awk '{${'print $1;'.repeat(40_000)}}'`;
    expect(huge.length).toBeGreaterThan(256 * 1024);
    const started = process.hrtime.bigint();
    expect(classOf(huge)).toBe('destructive');
    expect(Number(process.hrtime.bigint() - started) / 1e6).toBeLessThan(3000);
  });

  it('gates a program whose string or regex never closes', () => {
    // Lexing the rest in the wrong mode is how a system() call hides, so an
    // unterminated literal fails closed rather than being guessed past.
    expect(classOf(`awk '{print "unterminated}'`)).toBe('destructive');
    expect(classOf(`awk '/unterminated{print}'`)).toBe('destructive');
  });

  it('says nothing about an invocation that runs no program', () => {
    expect(classOf('awk --version')).toBe('safe');
    expect(classOf('awk --help')).toBe('safe');
    expect(classOf('awk')).toBe('safe');
  });
});

/**
 * The set #184 names as having broken the five abandoned attempts, plus the
 * adjacent shapes the same parser has to get right. They are the reason this is
 * a parser and not a pattern.
 */
describe('ordinary awk stays out of the gate', () => {
  it.each([
    `awk '{print $1}'`,
    `awk -F: '{print $1}'`,
    `awk -F ':' '{print $1}'`,
    `awk 'NR>1'`,
    `awk '$1 == "root"'`,
    `awk '{sum+=$1} END{print sum}'`,
    `awk '{print $1 "@" $2}'`,
    `awk '/a>b/ {print}'`,
    `awk '{print (a>b)}'`,
    `awk '{print a/b}'`,
    `awk '{ if ($3 > 100) print $1 }'`,
    `awk 'BEGIN{FS=":"} {print $1}' /etc/passwd`,
    `awk '{n = split($0, parts, "/"); print parts[n]}'`,
    `awk '# a comment with > and "quotes"\n{print $1}'`,
    `awk -v threshold=5 '$2 > threshold {print $1}'`,
    // Division after punctuation, which `regexCanStart` has to read as division
    // and not as a regex open. Untested before, and every one of these flips to
    // destructive if the exclusion list is replaced with `return true`.
    `awk '{print (a)/2}'`,
    `awk '{print a[1]/2}'`,
    `awk '{print $1/2}'`,
    `awk '{if (!/x/) print}'`,
    `awk '/[/]/{print}'`,
    `awk '{gsub(/[/]/,"-"); print}'`,
    // A multi-line program: the newline is what closes the output statement, so
    // without it the second line's `> 3` reads as a redirection of the first
    // line's print. (`print $2 > 3` on its own really does write a file named
    // `3` — verified — which is why the second line here has no `print`.)
    `awk '{print $1\n$2 > 3}'`,
    // Backslashes, which a second round of unquoting used to delete.
    `awk '{print "\\\\"}'`,
    `awk 'BEGIN{FS="\\\\."} {print $1}'`,
  ])('%s', (command) => {
    expect(classOf(command)).toBe('safe');
  });

  it('does not fire on a command that merely names awk', () => {
    // Keying on any word that says "awk" rather than on the word that runs is
    // what made both of these destructive in an earlier attempt.
    expect(classOf('readlink -f /usr/bin/awk')).toBe('read-only');
    expect(classOf('man awk')).toBe('safe');
    expect(classOf('which awk')).toBe('read-only');
    expect(classOf('grep -r awk /etc')).toBe('read-only');
  });

  it('reads awk behind a pipe and behind a wrapper', () => {
    expect(classOf(`df -h | awk '{print $5}'`)).toBe('safe');
    expect(classOf(`ps aux | awk '{print $2}' | head`)).toBe('safe');
    // The evidence of invocation still has to hold once a wrapper is in front.
    expect(classOf(`df -h | awk 'BEGIN{system("sudo id")}'`)).toBe('privileged');
    expect(classOf(`busybox awk 'BEGIN{system("sudo id")}'`)).toBe('privileged');
  });
});

describe('cost', () => {
  const costMs = (program: string) => {
    const started = process.hrtime.bigint();
    expect(classOf(program), program.slice(0, 24)).toBe('safe');
    return Number(process.hrtime.bigint() - started) / 1e6;
  };

  /**
   * Seeded with repeated `print` tokens rather than repeated spaces.
   *
   * An earlier attempt replaced a bounded `[^;{}>]{0,200}` with an unbounded
   * `[^;{}]*>` and went quadratic: 192KB cost 8.7s inside the policy gate, on
   * the single thread that also serves every other tool call. A whitespace seed
   * missed it, because the backtracking needed tokens to backtrack over.
   */
  it('classifies a 211KB program of repeated print statements promptly', () => {
    const program = `awk '{${'print $1;'.repeat(24_000)}}'`;
    expect(program.length).toBeGreaterThan(192 * 1024);
    // An absolute bound measures the runner, so it is only a smoke check here —
    // the growth assertion below is what carries the "linear" claim. Three
    // seconds matches the neighbouring budgets in classifier.test.ts, which were
    // widened after CI failed at 3677ms against a 1000ms bound under coverage
    // instrumentation.
    expect(costMs(program)).toBeLessThan(3000);
  });

  /**
   * A ratio rather than a wall-clock bound, matching classifier.test.ts:290.
   *
   * "Stays linear" is a claim about growth, and only a growth measurement can
   * check it: the previous version of this test timed one input size and called
   * that linearity. Quadrupling the input should roughly quadruple the cost; the
   * quadratic shape this guards against grew sixteen-fold.
   */
  it.each([
    ['repeated print statements', (n: number) => `awk '{${'print $1;'.repeat(Math.ceil(n / 9))}}'`],
    ['one long argument list', (n: number) => `awk '{print ${'$1 "x" '.repeat(Math.ceil(n / 8))}}'`],
    ['many string literals', (n: number) => `awk '{print ${'"aaaaaaaa" '.repeat(Math.ceil(n / 11))}}'`],
    ['punctuation that matches no operator', (n: number) => `awk '{x = ${'?:,~'.repeat(Math.ceil(n / 4))} 1}'`],
  ])('stays linear on %s', (_label, build) => {
    // 50KB and 200KB, both under the 256KB refusal bound so the lexer actually
    // runs. Max(…, 0.01) because a fast small case can measure as zero.
    const small = Math.max(costMs(build(50_000)), 0.01);
    const large = costMs(build(200_000));
    expect(large / small, `4x the input cost ${(large / small).toFixed(1)}x the time`)
      .toBeLessThan(8);
  });
});

/**
 * The reader on its own, for the cases the classifier flattens.
 *
 * `classifyCommand` collapses "found a command" and "could not read it" into one
 * class, so these distinguish them — and the distinction is what decides whether
 * an operator sees `sudo id` or "we cannot tell" in the audit record.
 */
describe('readAwkInvocation', () => {
  it('reports nothing for a program that does nothing dangerous', () => {
    expect(readAwkInvocation(['{print $1}'])).toEqual({
      commands: [], pipedInto: [], writesFile: false, unreadable: false,
    });
  });

  it('returns null when no program is present', () => {
    expect(readAwkInvocation([])).toBeNull();
    expect(readAwkInvocation(['--version'])).toBeNull();
  });

  it.each([
    ['\\t', '\t'], ['\\n', '\n'], ['\\\\', '\\'], ['\\"', '"'],
    ['\\061', '1'], ['\\x41', 'A'], ['\\q', 'q'],
  ])('decodes %s in a system() argument', (escape, decoded) => {
    // The bytes that reach the shell are what the classifier re-reads. `\n`
    // matters most: the multi-line-command refusal only sees a real newline.
    expect(readAwkInvocation([`BEGIN{system("a${escape}b")}`])?.commands)
      .toEqual([`a${decoded}b`]);
  });

  it('separates "found a command" from "could not read one"', () => {
    // `.class` collapses these, and which one an operator is told is the
    // difference between a named command and "we cannot tell".
    expect(readAwkInvocation(['{print $1 > $2}'])).toEqual({
      commands: [], pipedInto: [], writesFile: true, unreadable: false,
    });
    expect(readAwkInvocation(['BEGIN{system(x)}'])).toEqual({
      commands: [], pipedInto: [], writesFile: false, unreadable: true,
    });
    expect(readAwkInvocation([`BEGIN{print "x" | "sh"}`])).toEqual({
      commands: [], pipedInto: ['sh'], writesFile: false, unreadable: false,
    });
  });

  it('separates the flags that are skipped from the flag that is not', () => {
    expect(readAwkInvocation(['-F', ':', '{print $1}'])?.unreadable).toBe(false);
    expect(readAwkInvocation(['-F:', '{print $1}'])?.unreadable).toBe(false);
    expect(readAwkInvocation(['-v', 'n=1', '{print $1}'])?.unreadable).toBe(false);
    expect(readAwkInvocation(['-vn=1', '{print $1}'])?.unreadable).toBe(false);
    expect(readAwkInvocation(['-f', 'prog.awk'])?.unreadable).toBe(true);
  });

  it('treats a bare - and -- as operands rather than flags', () => {
    // `awk -- '{...}'` ends the options; a bare `-` is stdin as a data file.
    expect(readAwkInvocation(['--', 'BEGIN{system("sudo id")}'])?.commands).toEqual(['sudo id']);
    // With the `-` first, the branch that recognises it runs — and a bare `-`
    // is an operand, so it becomes the program and the real program becomes a
    // data file. That is what awk does too: `awk - 'BEGIN{print "RAN"}'` is a
    // syntax error, not a run. Nothing is found, and nothing should be.
    expect(readAwkInvocation(['-', 'BEGIN{system("sudo id")}'])?.commands).toEqual([]);
  });

  it('keeps an explicitly empty flag value from eating the program', () => {
    // The tokenizer used to drop a quoted empty word, so this arrived one word
    // short and the program was consumed as `-F`'s value: the reader reported
    // "no program" and the whole gate went silent. Real awk warns about the
    // empty FS and runs the program anyway — measured, including the file write.
    expect(readAwkInvocation(['-F', '', 'BEGIN{system("sudo id")}'])?.commands)
      .toEqual(['sudo id']);
  });

  it('does not read a data file as the program', () => {
    // The second operand is data. Reading it as a program would classify the
    // *contents* of a filename, which is how one attempt gated `awk '{print}' report.awk`.
    expect(readAwkInvocation(['{print $1}', 'BEGIN{system("sudo id")}'])?.commands).toEqual([]);
  });
});
