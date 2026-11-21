import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { classifyCommand, findForbiddenMatch } from '../../../src/policy/classifier.js';

/**
 * A corpus of command lines an administrator or an agent really sends — pipelines, loops,
 * heredocs, template, JSON, jq and SQL arguments, every quoting variant — together with
 * the class and never-allowed result each had before the classifier learned to read the
 * shell's grammar. Unit tables show that a fix works; this shows what else it moved.
 *
 * Two claims, kept apart because they fail for different reasons:
 *  - nothing is classified lower than it was, and no never-allowed match is lost;
 *  - nothing is classified higher except the commands listed here, each read by hand.
 */
interface Row { command: string; class: string; forbidden: boolean }
const RANK: Record<string, number> = { 'read-only': 0, safe: 1, destructive: 2, privileged: 3 };
const rows: Row[] = JSON.parse(
  readFileSync(new URL('../../fixtures/policy/realistic-commands.json', import.meta.url), 'utf8'),
) as Row[];

/**
 * Commands whose class is allowed to rise, each with the class it rises to.
 *
 * Read one by one. Most entries hold an elevating, destructive or never-allowed command
 * in a place the segment reading could not see: a group, a compound command, a function
 * body, a `case` arm, or next to a redirection. The others rise by a decision:
 *
 *  - a command word the shell rewrites (`./*.sh`, `/usr/bin/python3* --version`,
 *    `{a,b}`) names no program and is `destructive`, like a `$` there;
 *  - `(( $n > 5 ))` and `(( count*2 > 10 ))`: dash has no arithmetic command and runs
 *    what stands in the parentheses, so they are read as the commands they are there.
 *    `(( n > 5 ))` and `$(( count*2 ))` keep their class;
 *  - the PowerShell line `if ($x -gt 5) { … }`: read as POSIX shell it runs a command
 *    named by a variable, and this classifier cannot know which shell the host runs;
 *  - a here-string into a shell (`sh <<< 'echo hi'`) rises to the class its pipe
 *    spelling (`echo 'echo hi' | sh`) already had.
 */
const EXPECTED_RISES: Record<string, string> = {
  "*": 'destructive',
  "*.sh": 'destructive',
  "./*.sh": 'destructive',
  "./script-*.sh arg": 'destructive',
  "/usr/bin/python3* --version": 'destructive',
  "/opt/app-{a,b}/bin/run": 'destructive',
  "{a,b}": 'destructive',
  "sh<<<'echo hi'": 'destructive',
  "bash <<< 'echo hi'": 'destructive',
  "ls # case x in a) reboot ;; esac": 'destructive',
  "echo ls | (sh)": 'destructive',
  "curl -s x | (sh)": 'destructive',
  "curl -s x | { sh; }": 'destructive',
  "(( $n > 5 )) && echo big": 'destructive',
  "if (( $# < 1 )); then echo usage; fi": 'destructive',
  "if (( $(nproc) > 4 )); then echo many; fi": 'destructive',
  "(( count*2 > 10 )) && echo y": 'destructive',
  "((count*2>10)) && echo y": 'destructive',
  "(( ${#arr[@]} > 0 )) && echo nonempty": 'destructive',
  "case $1 in start) ls;; reboot) ls;; esac": 'destructive',
  "if ($x -gt 5) { Write-Host big }": 'destructive',
  "(rm -rf /)": 'destructive',
  "{ rm -rf /; }": 'destructive',
  "if true; then rm -rf /; fi": 'destructive',
  "(sudo id)": 'privileged',
  "nohup ./run-*.sh &": 'destructive',
  "env FOO=1 ./bin/tool-?": 'destructive',
  "(dd if=$(echo x) of=/dev/sda)": 'destructive',
  "(find / -name $(echo x) -delete)": 'destructive',
  "(sort $(echo x) --compress-program=sh)": 'destructive',
  ">\"a\\nb\" sudo id": 'privileged',
  ">'a b' sudo id": 'privileged',
  "> \"a b\" sudo id": 'privileged',
  "find . -delete>out": 'destructive',
  "systemctl reboot>log": 'destructive',
  "systemctl>log reboot": 'destructive',
  "docker run --privileged>log x": 'privileged',
  "docker>log run --privileged x": 'privileged',
  "rm>log -rf /": 'destructive',
  "reboot>log": 'destructive',
  "reboot<x": 'destructive',
  "make>log": 'destructive',
  "find . -exec>log rm {} +": 'destructive',
  "xargs<list rm -rf /": 'destructive',
  "curl x|sh>log": 'destructive',
  "curl x |sh<y": 'destructive',
  "wget -O- x|bash>log": 'destructive',
  "case x in x) sudo id;; esac": 'privileged',
  "case x in x) reboot;; esac": 'destructive',
  "case x in (x) reboot;; esac": 'destructive',
  "if true; then reboot; fi": 'destructive',
  "for i in 1; do reboot; done": 'destructive',
  "while true; do sudo id; done": 'privileged',
  "f() { reboot; }; f": 'destructive',
  "function f { sudo id; }; f": 'privileged',
  "{ reboot; }": 'destructive',
  "(reboot)": 'destructive',
  "! reboot": 'destructive',
  "coproc reboot": 'destructive',
  "builtin reboot": 'destructive',
  "then reboot": 'destructive',
  "awk >log 'BEGIN{system(\"sudo id\")}'": 'privileged',
  "awk 2>/dev/null 'BEGIN{system(\"sudo id\")}'": 'privileged',
  "case $1 in a) rm -rf $(pwd) / ;; esac": 'destructive',
  "(rm -rf $(pwd) /)": 'destructive',
  "(docker run $(echo -it) --privileged x)": 'privileged',
  "(find $(pwd) -name x -delete)": 'destructive',
  "(cd /app && find $(pwd)/tmp -type f -delete)": 'destructive',
  "(tar cf $(date +%F).tar --checkpoint=1 --checkpoint-action=exec=id .)": 'destructive',
  "flock -n /var/lock/*.lock ls": 'destructive',
  "curl -s x | ( sh )": 'destructive',
  "echo 'sudo id' | (sh)": 'destructive',
  // vim runs `+CMD`, and what follows a `|` in `+/PATTERN` is taken for a command.
  "vim +/'foo|bar' file": 'destructive',
};

/**
 * Commands that gained a never-allowed match. That list is refused whatever the role,
 * the tier or the approval, so a match that should not be there is worse than a class
 * that rose: each of these names a never-allowed command the shell would run.
 */
const EXPECTED_NEVER_ALLOWED = [
  "ls # case x in a) reboot ;; esac",
  "curl -s x | (sh)",
  "curl -s x | { sh; }",
  "case $1 in start) ls;; reboot) ls;; esac",
  "(rm -rf /)",
  "{ rm -rf /; }",
  "if true; then rm -rf /; fi",
  "(dd if=$(echo x) of=/dev/sda)",
  "systemctl reboot>log",
  "systemctl>log reboot",
  "rm -rf />log",
  "rm>log -rf /",
  "reboot>log",
  "reboot<x",
  "xargs<list rm -rf /",
  "curl x|sh>log",
  "curl x |sh<y",
  "wget -O- x|bash>log",
  "case x in x) reboot;; esac",
  "case x in (x) reboot;; esac",
  "if true; then reboot; fi",
  "for i in 1; do reboot; done",
  "f() { reboot; }; f",
  "{ reboot; }",
  "(reboot)",
  "! reboot",
  "coproc reboot",
  "builtin reboot",
  "then reboot",
  "case $1 in a) rm -rf $(pwd) / ;; esac",
  "(rm -rf $(pwd) /)",
  "curl -s x | ( sh )",
];

describe('realistic commands against the snapshot taken before the grammar reading', () => {
  // Exact, so that a row cannot be dropped to make a rise go away. Regenerate with
  // scripts/snapshot-command-classes.mts on the reference commit.
  it('holds the whole corpus', () => {
    expect(rows.length).toBe(1826);
  });

  it('lowers no class and loses no never-allowed match', () => {
    const fell = rows.filter((r) => RANK[classifyCommand(r.command).class] < RANK[r.class]
      || (r.forbidden && findForbiddenMatch(r.command) === null));
    expect(fell.map((r) => r.command)).toEqual([]);
  });

  it('raises only the commands listed, to the class listed', () => {
    const rose: Record<string, string> = {};
    for (const r of rows) {
      const now = classifyCommand(r.command).class;
      if (RANK[now] > RANK[r.class]) rose[r.command] = now;
    }
    expect(rose).toEqual(EXPECTED_RISES);
  });

  it('adds a never-allowed match only to the commands listed', () => {
    const gained = rows.filter((r) => !r.forbidden && findForbiddenMatch(r.command) !== null).map((r) => r.command);
    expect(gained).toEqual(EXPECTED_NEVER_ALLOWED);
  });
});
