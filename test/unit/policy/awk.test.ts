import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../../../src/policy/classifier.js';
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

  it('classifies a non-elevated system() by what it actually runs', () => {
    expect(classOf(`awk 'BEGIN{system("rm -rf /var/lib/thing")}'`)).toBe('destructive');
    expect(classOf(`awk 'BEGIN{system("ls")}'`)).toBe('safe');
  });

  it('reads a command piped out of print, and one piped into getline', () => {
    expect(classOf(`awk 'BEGIN{print "x" | "sudo tee /etc/passwd"}'`)).toBe('privileged');
    expect(classOf(`awk 'BEGIN{"sudo id" | getline r; print r}'`)).toBe('privileged');
  });

  it('refuses to guess at a system() argument it cannot read', () => {
    // Assembled at run time. Reading the literal half and classifying that would
    // describe a command that never runs.
    expect(classOf(`awk -v f=/etc 'BEGIN{system("rm -rf " f)}'`)).toBe('destructive');
  });
});

describe("an awk program that writes a file", () => {
  it('gates output redirection, which needs no system() at all', () => {
    expect(classOf(`awk 'BEGIN{print "ssh-rsa AAAA" > "/root/.ssh/authorized_keys"}'`))
      .toBe('destructive');
    expect(classOf(`awk 'BEGIN{print "x" >> "/root/.ssh/authorized_keys"}'`))
      .toBe('destructive');
  });

  it('gates a redirection whose target is computed', () => {
    expect(classOf(`awk '{print $1 > $2}'`)).toBe('destructive');
  });

  it('gates a redirection from printf, with or without parentheses', () => {
    expect(classOf(`awk 'BEGIN{printf "%s\\n", "x" > "/etc/hosts"}'`)).toBe('destructive');
    expect(classOf(`awk 'BEGIN{printf("%s\\n", "x") > "/etc/hosts"}'`)).toBe('destructive');
  });

  it('leaves the standard streams alone, which scripts write to routinely', () => {
    for (const target of ['/dev/stderr', '/dev/stdout', '/dev/null']) {
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
 * Every entry here is a shape one of the five abandoned attempts classified
 * wrongly. They are the reason this is a parser and not a pattern.
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
  /**
   * Seeded with repeated `print` tokens rather than repeated spaces.
   *
   * An earlier attempt replaced a bounded `[^;{}>]{0,200}` with an unbounded
   * `[^;{}]*>` and went quadratic: 192KB cost 8.7s inside the policy gate, on
   * the single thread that also serves every other tool call. A whitespace seed
   * missed it, because the backtracking needed tokens to backtrack over.
   */
  it('stays linear on a program built from repeated print statements', () => {
    const program = `awk '{${'print $1;'.repeat(24_000)}}'`;
    expect(program.length).toBeGreaterThan(192 * 1024);

    const started = process.hrtime.bigint();
    expect(classOf(program)).toBe('safe');
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    // Measured at ~75ms on the development machine; the quadratic shape this
    // guards against was 8.7s, so the bound is generous without being useless.
    expect(elapsedMs, `classifying 192KB of awk took ${elapsedMs.toFixed(0)}ms`)
      .toBeLessThan(1500);
  });

  it('stays linear on a long argument list, a long regex and many strings', () => {
    const shapes = [
      `awk '{print ${'$1 "x" '.repeat(24_000)}}'`,
      `awk '/${'a'.repeat(190_000)}/{print}'`,
      `awk '{print ${'"aaaaaaaa" '.repeat(20_000)}}'`,
    ];
    for (const program of shapes) {
      const started = process.hrtime.bigint();
      classOf(program);
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
      expect(elapsedMs, `${program.slice(0, 20)}… took ${elapsedMs.toFixed(0)}ms`)
        .toBeLessThan(1500);
    }
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
      commands: [], writesFile: false, unreadable: false,
    });
  });

  it('returns null when no program is present', () => {
    expect(readAwkInvocation([])).toBeNull();
    expect(readAwkInvocation(['--version'])).toBeNull();
  });

  it('decodes the escapes in a system() argument', () => {
    // The bytes that reach the shell are what the classifier re-reads, so an
    // undecoded `\t` would be classified as a backslash and a `t`.
    expect(readAwkInvocation([`BEGIN{system("echo\\tone")}`])?.commands).toEqual(['echo\tone']);
  });

  it('separates the flags that are skipped from the flag that is not', () => {
    expect(readAwkInvocation(['-F', ':', '{print $1}'])?.unreadable).toBe(false);
    expect(readAwkInvocation(['-F:', '{print $1}'])?.unreadable).toBe(false);
    expect(readAwkInvocation(['-v', 'n=1', '{print $1}'])?.unreadable).toBe(false);
    expect(readAwkInvocation(['-vn=1', '{print $1}'])?.unreadable).toBe(false);
    expect(readAwkInvocation(['-f', 'prog.awk'])?.unreadable).toBe(true);
  });

  it('treats a bare - and -- as operands rather than flags', () => {
    // `awk -- '{...}'` ends the options; `awk '{...}' -` reads stdin as data.
    expect(readAwkInvocation(['--', 'BEGIN{system("sudo id")}'])?.commands).toEqual(['sudo id']);
    expect(readAwkInvocation(['BEGIN{system("sudo id")}', '-'])?.commands).toEqual(['sudo id']);
  });

  it('does not read a data file as the program', () => {
    // The second operand is data. Reading it as a program would classify the
    // *contents* of a filename, which is how one attempt gated `awk '{print}' report.awk`.
    expect(readAwkInvocation(['{print $1}', 'BEGIN{system("sudo id")}'])?.commands).toEqual([]);
  });
});
