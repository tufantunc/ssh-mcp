import { describe, it, expect } from 'vitest';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import {
  classifyCommand, READ_ONLY_ALLOWLIST, READERS, nestedCommands, findForbiddenMatch,
} from '../../../src/policy/classifier.js';
import type { Profile } from '../../../src/types.js';

/**
 * GHSA-qmx6-47vm-3vf7: a binary the classifier does not recognise laundered an
 * elevated command into `safe`, the class that raises no prompt.
 *
 * The fix does not scan text for `sudo`. An earlier design did, and it asserted
 * elevations the existing readers deliberately refuse to assert — awk's runtime
 * concatenation and `$S` both cap at `destructive` on purpose — and it beat the
 * nested classification that names the elevated binary correctly. Instead, the
 * operands of a segment no more specific reader claimed become nested commands,
 * and the existing anchored check finds the elevation on a command it leads.
 */
const operatorProd = {
  name: 'prod-web', host: 'h', port: 22, user: 'deploy', auth: 'agent', tty: false,
  timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'prod',
  role: 'operator', readOnly: false, approvalPolicy: 'ask-destructive', cert: false,
  announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
  sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
  transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
} as unknown as Profile;

const engine = new PolicyEngine(DEFAULT_RULES);
const decide = (command: string) => engine.evaluate(command, operatorProd, 'run-command');

describe('an unrecognised binary cannot hide a command in its operands', () => {
  it.each([
    ['osascript', `osascript -e 'do shell script "sudo id"'`],
    ['an unknown binary', `whatever-tool -e 'sudo id'`],
    ['an unknown binary, no flag', `whatever-tool 'sudo id'`],
  ])('refuses elevation carried by %s', (_label, command) => {
    expect(decide(command).commandClass, command).toBe('privileged');
    expect(decide(command).decision, command).toBe('deny');
  });

  it('names the binary that would run as root, not the carrier', () => {
    // The reason this is a nested classification rather than a text scan: the
    // existing anchored check runs on a command the elevation actually leads, so
    // it can say which binary root would execute. A text scan can only name the
    // outer word, and four awk tests caught exactly that.
    expect(classifyCommand(`osascript -e 'do shell script "sudo id"'`).binary).toBe('id');
  });

  it('finds elevation reached only through a substitution', () => {
    expect(decide(`whatever-tool -e "$(printf 'sudo id')"`).commandClass).toBe('privileged');
  });

  it('leaves the deliberate caps alone', () => {
    // Both are documented decisions this fix must not override: awk assembles the
    // command at run time, and `$S` cannot be resolved, so neither is a confirmed
    // elevation. `destructive` asks for approval; `privileged` would refuse.
    expect(classifyCommand(`awk 'BEGIN{"sudo" " id" | getline v}'`).class).toBe('destructive');
    expect(classifyCommand('S=sudo; $S id').class).toBe('destructive');
  });

  it('leaves the commands an operator runs all day alone', () => {
    for (const [command, expected] of [
      ['kubectl get pods', 'safe'],
      ['make deploy', 'safe'],
      ['docker run -e FOO=bar img', 'safe'],
      ['terraform apply', 'safe'],
      ["grep 'sudo' /var/log/auth.log", 'read-only'],
      ['find / -name perl', 'read-only'],
      ['echo "sudo id"', 'read-only'],
    ] as const) {
      expect(classifyCommand(command).class, command).toBe(expected);
    }
  });

  it('sees both halves of an operand that carries a separator', () => {
    // One word to the tokeniser, two commands to a shell. Pushing it as a nested
    // command is what makes the second half visible at all.
    expect(classifyCommand(`whatever-tool 'echo a; sudo id'`).class).toBe('privileged');
  });

  it('stays cheap on many long multi-word operands', () => {
    // The recursion is wider now: every multi-word operand of an unrecognised
    // binary is classified. The bound is a growth ratio rather than a wall clock —
    // CI runs under coverage, and an absolute bound here once failed at 3677ms.
    const operand = (n: number) => `'${'word '.repeat(n)}'`;
    const small = `whatever-tool ${Array.from({ length: 10 }, () => operand(10)).join(' ')}`;
    const large = `whatever-tool ${Array.from({ length: 100 }, () => operand(100)).join(' ')}`;
    const time = (c: string) => { const t = performance.now(); classifyCommand(c); return performance.now() - t; };
    time(small);
    const a = time(small);
    const b = time(large);
    // 100x the operands at 10x the length is 1000x the input; anything near linear
    // is fine and anything quadratic is not.
    expect(b).toBeLessThan(Math.max(a * 3000, 100));
  });

  it('costs an operand whose first word is an elevation name', () => {
    // The accepted cost, pinned so it is a decision rather than a surprise: an
    // operand that begins with `sudo ` has the shape of a command, which is why it
    // is caught. The elevation name has to lead — these two are unaffected.
    expect(classifyCommand('git commit -m "sudo fix"').class).toBe('privileged');
    expect(classifyCommand('git commit -m "fix the sudo thing"').class).toBe('safe');
    expect(classifyCommand('curl -H "X: sudo y" http://h').class).toBe('safe');
  });
});

describe('the two questions the read-only allowlist used to answer', () => {
  it('keeps the carrier scan running for a reader that is not exempt', () => {
    // The regression #217's review found: one Set read by two mechanisms, so
    // adding a name for its class silently switched the carrier scan off for it.
    // This is the behaviour the table protects.
    expect(classifyCommand(`sftp:list /tmp sh -c 'sudo id'`).class).toBe('privileged');
  });

  it('makes every reader answer both questions', () => {
    // The point of the table. A name cannot be added for its class without
    // stating whether its operands can hide a command — TypeScript requires the
    // field, and this asserts nobody has defaulted it away.
    //
    // Asserts the VALUES, not just their type. `expect(typeof entry.readOnly)
    // .toBe('boolean')` is true whether `readOnly` is `true` or `false`, so
    // flipping `find.operandsAreData`, `stat.readOnly` or
    // `journalctl.operandsAreData` to `false` passed it — measured. Every entry
    // is `{ readOnly: true, operandsAreData: true }` today, so that is the
    // literal shape each one must equal.
    for (const [name, entry] of Object.entries(READERS)) {
      expect(entry, name).toEqual({ readOnly: true, operandsAreData: true });
    }
    expect(Object.keys(READERS).length).toBe(68);
  });

  it('derives the class allowlist from the table rather than repeating it', () => {
    // If these ever diverge, one of the two questions has been answered twice.
    expect(READ_ONLY_ALLOWLIST.size)
      .toBe(Object.values(READERS).filter((e) => e.readOnly).length);
  });
});

/** PowerShell emits UTF-16LE base64 for -EncodedCommand. */
const encode = (s: string) => Buffer.from(s, 'utf16le').toString('base64');

describe('interpreters that take a program on the command line', () => {
  it.each([
    ['osascript', `osascript -e 'do shell script "systemctl stop nginx"'`],
    ['lua', `lua -e 'os.execute("systemctl stop nginx")'`],
    ['Rscript', `Rscript -e 'system("systemctl stop nginx")'`],
    ['bun', `bun -e 'require("child_process").execSync("systemctl stop nginx")'`],
    ['deno eval', `deno eval 'new Deno.Command("systemctl").outputSync()'`],
    ['pwsh -Command', `pwsh -Command 'Stop-Service nginx'`],
  ])('treats a program handed to %s as unreadable', (_label, command) => {
    // No elevation in these payloads, so Task 1's scan does not reach them. This
    // is the half that needs the name.
    expect(classifyCommand(command).class, command).toBe('destructive');
  });

  it('tclsh has no -c flag — real tclsh reads a program from a file or from stdin', () => {
    // Real tclsh takes a script FILE as its positional argument, or reads one
    // from stdin; it has no `-c` that hands it a program inline the way
    // sh/bash/python/pwsh do. `tclsh -c 'exec systemctl stop nginx'` is a
    // fictional invocation shape — real tclsh treats `-c` as an unrecognised
    // option, not a program flag — so `tclsh` here reads as a plain,
    // unrecognised interpreter invocation with no program on its command
    // line, same as `tclsh script.tcl` would.
    expect(classifyCommand(`tclsh -c 'exec systemctl stop nginx'`).class).toBe('safe');
  });

  it('the genuine tclsh carrier is the pipe: reads a program from stdin', () => {
    expect(classifyCommand(`echo 'exec sudo id' | tclsh`).class).toBe('destructive');
  });

  it('reads a carrier through a path and through quotes', () => {
    expect(classifyCommand(`/usr/bin/osascript -e 'do shell script "id"'`).class).toBe('destructive');
    expect(classifyCommand(`"osascript" -e 'do shell script "id"'`).class).toBe('destructive');
  });

  it('decodes -EncodedCommand so elevation inside it is elevation', () => {
    expect(classifyCommand(`pwsh -EncodedCommand ${encode('sudo id')}`).class).toBe('privileged');
  });

  it('decodes the -e abbreviation of -EncodedCommand the same way', () => {
    // pwsh/powershell accept -e as an abbreviation of -EncodedCommand. The brief's
    // original gate — words.includes('-EncodedCommand') — never fires for this
    // spelling, so it silently stayed at destructive instead of privileged. The
    // gate must key off the flag programAfterFlag actually matched, not a scan
    // for the long spelling.
    expect(classifyCommand(`pwsh -e ${encode('sudo id')}`).class).toBe('privileged');
  });

  it('still refuses an encoded payload that does not elevate', () => {
    // readable: false means the presence of a program is enough.
    expect(classifyCommand(`pwsh -EncodedCommand ${encode('Get-Process')}`).class).toBe('destructive');
  });

  it('does not throw on base64 that decodes to nothing useful', () => {
    // Buffer.from(x, 'base64') never throws — it drops invalid characters — so the
    // failure mode is a wrong answer, not an exception. Both must be safe.
    //
    // The empty case is quoted (`''`) rather than a bare empty string: an unquoted
    // empty operand leaves no token at all after `-EncodedCommand`, which is a
    // different, pre-existing shape — "the flag has no argument" — that this file
    // already answers `safe` for every interpreter in the table (`python3 -c` with
    // nothing after it is `safe` too). A quoted empty word does survive
    // tokenization and is the case this test means to exercise: an operand that is
    // present but decodes to nothing useful.
    for (const junk of ['!!!!not base64!!!!', "''", 'QQ', 'a'.repeat(4001)]) {
      expect(() => classifyCommand(`pwsh -EncodedCommand ${junk}`)).not.toThrow();
      expect(classifyCommand(`pwsh -EncodedCommand ${junk}`).class).toBe('destructive');
    }
  });

  it('stays cheap on a large encoded operand', () => {
    // Decoding is attacker-controlled work done before the policy decision. The
    // bound is a growth ratio, not a wall clock: this repo's CI runs under
    // coverage and an absolute bound once failed at 3677ms.
    //
    // Both sizes are kept under MAX_ENCODED_CHARS (64 KiB of base64) on purpose. The
    // guard now reads a bounded prefix instead of refusing outright past the limit
    // (fix round 1: a refusal was a downgrade path, not merely untested), so an input
    // that crosses the limit is clamped to the same decode cost regardless of how much
    // further it grows — that would make this test measure the clamp, not the decode.
    // Below the limit, every extra character is still decoded, so the ratio this test
    // checks is the one decoding itself is responsible for.
    const small = encode('Get-Process '.repeat(18));
    const large = encode('Get-Process '.repeat(1_800));
    const time = (c: string) => { const t = performance.now(); classifyCommand(c); return performance.now() - t; };
    time(`pwsh -EncodedCommand ${small}`); // warm
    const ratioSmall = time(`pwsh -EncodedCommand ${small}`);
    const ratioLarge = time(`pwsh -EncodedCommand ${large}`);
    expect(ratioLarge).toBeLessThan(Math.max(ratioSmall * 200, 50));
  });
});

describe('fix round 1: the catch-all must not switch off for the binaries it now recognises', () => {
  // Task 1's block only ran when the segment's head was NOT in INTERPRETERS. Adding
  // pwsh, osascript, deno etc. to the table excluded them from that catch-all, and the
  // interpreter loop that is supposed to cover them instead calls `programAfterFlag`,
  // which gives up the moment a non-flag word (an option's own value, or an option that
  // takes no program-bearing meaning) sits between the binary and its program-bearing
  // word. These are ordinary spellings, not contrived ones.
  it.each([
    ['an option that takes a value', `pwsh -ExecutionPolicy Bypass -Command 'sudo id'`],
    ['another option that takes a value', `pwsh -WindowStyle Hidden -Command 'sudo id'`],
    ['osascript -l', `osascript -l JavaScript -e 'do shell script "sudo id"'`],
    ['deno run', `deno run 'sudo id'`],
    ['deno eval with its own option before the code', `deno eval --unstable 'sudo id'`],
  ])('still finds the elevation when %s sits between the binary and its program flag', (_label, command) => {
    expect(classifyCommand(command).class, command).toBe('privileged');
  });
});

describe('fix round 1: MAX_ENCODED_CHARS must not be a downgrade path', () => {
  it('does not downgrade class by padding an encoded command past the decode limit', () => {
    // Returning null above the limit meant padding the payload traded `privileged` for
    // `destructive` — a strictly weaker answer available to anyone who can pad a string.
    // A bounded prefix keeps the elevation near the front of the payload visible no
    // matter how much an attacker appends after it.
    const padded = encode(`sudo id # ${'A'.repeat(25_000)}`);
    expect(classifyCommand(`pwsh -EncodedCommand ${padded}`).class).toBe('privileged');
  });
});

describe('fix round 1: pwsh/powershell flag matching is case-insensitive, nothing else is', () => {
  it.each([
    '-EncodedCommand', '-encodedcommand', '-enc', '-ec', '-eC', '-e',
    '-ENC', '-EC', '-E', '-EncodedCOMMAND',
  ])('treats %s as -EncodedCommand regardless of case', (flag) => {
    expect(classifyCommand(`pwsh ${flag} ${encode('sudo id')}`).class, flag).toBe('privileged');
  });

  it.each(['-Command', '-command', '-c', '-COMMAND', '-C'])(
    'treats %s as -Command regardless of case',
    (flag) => {
      expect(classifyCommand(`pwsh ${flag} 'sudo id'`).class, flag).toBe('privileged');
    },
  );

  it('leaves every other interpreter case-sensitive', () => {
    // `-E` and `-e` are two different flags to perl (`-E` enables modern features,
    // `-e` runs inline code); folding case here would conflate them for every
    // interpreter, not just the one family whose own parameter binder is
    // case-insensitive. Single-word operands so Task 1's catch-all cannot also
    // explain a `destructive`/`privileged` result — only the flag match itself can.
    expect(classifyCommand(`python3 -C somefile.py`).class).toBe('safe');
    expect(classifyCommand(`ruby -E somefile.rb`).class).toBe('safe');
  });
});

describe('fix round 3: powershell.exe / pwsh.exe / PowerShell all resolve to the table entry', () => {
  // The three INTERPRETERS lookup sites key on `stripPath(unquote(word))`, which
  // removes a directory but not a `.exe` suffix, and compare case-sensitively.
  // Only the bare lowercase `powershell` spelling reached the table before this
  // fix — every one of these classified `safe`, carrying an undecoded `sudo id`.
  it.each([
    ['powershell.exe', `powershell.exe -EncodedCommand ${encode('sudo id')}`],
    ['pwsh.exe', `pwsh.exe -EncodedCommand ${encode('sudo id')}`],
    ['PowerShell (capitalised, no extension)', `PowerShell -EncodedCommand ${encode('sudo id')}`],
    ['PowerShell.exe (capitalised with extension)', `PowerShell.exe -EncodedCommand ${encode('sudo id')}`],
    ['PWSH.EXE (all caps)', `PWSH.EXE -EncodedCommand ${encode('sudo id')}`],
    ['pwsh.cmd', `pwsh.cmd -EncodedCommand ${encode('sudo id')}`],
    // A POSIX-style path, not a Windows one: this tokeniser treats a
    // backslash as a shell escape (see `tokenizeSegmentsDetailed`), which is
    // the right reading for the remote shells this file already assumes
    // throughout — a Windows path separator is a different, undocumented
    // gap this fix does not take on.
    ['a path plus the .exe spelling', `/usr/local/bin/pwsh.EXE -EncodedCommand ${encode('sudo id')}`],
  ])('decodes -EncodedCommand for %s', (_label, command) => {
    expect(classifyCommand(command).class, command).toBe('privileged');
  });

  it('still treats an unrecognised .exe as an unrecognised binary, not an interpreter', () => {
    // The fallback must not turn every `.exe` word into an interpreter lookup —
    // only a name the table already knows once the suffix and case are folded.
    expect(classifyCommand(`notepad.exe -EncodedCommand ${encode('sudo id')}`).class).toBe('safe');
  });

  it('folds .exe and case for every table entry, not only pwsh/powershell', () => {
    // The measured bug names pwsh/powershell, but the lookup site takes a
    // command word from an SSH session, and the target can just as well be a
    // Windows host running `python.exe` or `Node.EXE` as one running
    // `pwsh.exe` — every interpreter here can appear the same way. Scoping
    // the fallback to two names would leave the identical gap open for the
    // rest of the table, so this pins that the fold is general: it is the
    // binary-name question, decided once, not a pwsh-specific carve-out.
    expect(classifyCommand(`Python3.EXE -c "import os; os.system('sudo id')"`).class).toBe('destructive');
  });

  it('leaves flag matching case-sensitive for every interpreter this does not concern', () => {
    // Folding the BINARY name is a different question from folding its
    // FLAGS: perl's -E and -e are two different flags, and that distinction
    // is untouched by this fix. Both these interpreters resolve by an exact,
    // case-sensitive table lookup already (no suffix, no case to fold), so
    // if this fix had widened flag matching instead of binary-name matching,
    // it would have shown up here.
    expect(classifyCommand(`python3 -C somefile.py`).class).toBe('safe');
    expect(classifyCommand(`ruby -E somefile.rb`).class).toBe('safe');
  });
});

describe('fix round 2: an unrecognised pwsh option with a value must not hide -EncodedCommand', () => {
  // `-ExecutionPolicy` is skipped as an unrecognised flag, but its *value* `Bypass` is a
  // bare word — not a flag, not skippable — so `programAfterFlag` gave up right there and
  // never reached `-EncodedCommand`. `hasUnreadableProgram` failed the same way, so there
  // was no `destructive` floor either, and the catch-all cannot rescue it: a base64
  // payload is one token with no whitespace. `-ExecutionPolicy Bypass` plus an encoded
  // payload is the single most common real-world hostile pwsh spelling.
  it('finds -EncodedCommand past -ExecutionPolicy Bypass', () => {
    expect(classifyCommand(`pwsh -ExecutionPolicy Bypass -EncodedCommand ${encode('sudo id')}`).class)
      .toBe('privileged');
  });

  it('finds -EncodedCommand past two unrecognised options in a row', () => {
    expect(
      classifyCommand(`pwsh -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encode('sudo id')}`).class,
    ).toBe('privileged');
  });

  it('finds -EncodedCommand past -WindowStyle Hidden, and works for powershell too', () => {
    expect(
      classifyCommand(`powershell -WindowStyle Hidden -EncodedCommand ${encode('sudo id')}`).class,
    ).toBe('privileged');
  });

  it('pins the mechanism: a non-elevating payload past the same option stays destructive', () => {
    // If this were `privileged` too, the test above could be passing because pwsh
    // invocations are treated as privileged outright, not because -EncodedCommand was
    // actually found and decoded. `readable: false` means the mere presence of the
    // program is enough for `destructive`; only its *content* elevates further.
    expect(classifyCommand(`pwsh -ExecutionPolicy Bypass -EncodedCommand ${encode('Get-Process')}`).class)
      .toBe('destructive');
  });

  it('does not widen an unrelated wrapper: nsenter -m sh -c still requires no unknown value between them', () => {
    // The historical case the current `programAfterFlag` behaviour protects: `sh` here
    // is not the segment's head (nsenter is), so the fix below — scoped to an
    // interpreter found at position 0 — must not touch this shape. Still finds the
    // elevation (nothing sits between `-m` and `sh -c`, so this was never broken); the
    // point is that it still runs through the ordinary, narrower path.
    expect(classifyCommand(`nsenter -t 1 -m sh -c 'sudo id'`).class).toBe('privileged');
  });

  it('does not reopen mention-vs-invocation: a mid-command "pwsh" that is a value, not the binary, stays safe', () => {
    // The case the `from === 0` scoping exists for, constructed the same shape as
    // `grep -e perl -e python`: `pwsh` here is the VALUE of an unrelated tool's own
    // flag (`--search`), never actually invoked. `isFlagValue` cannot catch this one —
    // `--search` is not one of pwsh's own program-bearing words, so it only guards the
    // exact-flag-collision shape, not an arbitrary unrelated flag's value. Tolerating
    // an unknown word on the way to `-EncodedCommand` for ANY position `pwsh` is found
    // at, not just position 0, would read this as a real invocation and decode a
    // payload that was never handed to pwsh at all.
    const command = `customtool --search pwsh -ExecutionPolicy Bypass -EncodedCommand ${encode('sudo id')}`;
    expect(classifyCommand(command).class).toBe('safe');
  });
});

/**
 * The maintainer's ruling: the catch-all's speculative operands must not feed
 * FORBIDDEN_RULES' unconditional denylist. `findForbiddenMatch` recurses into
 * `nestedCommands`, and `FORBIDDEN_RULES` is forbidden regardless of role, tier
 * or approval — but the catch-all is a guess about an unrecognised binary's
 * operands, and a guess may raise a command's *class* (which role, tier and
 * approval still get to weigh in on) but must not produce a refusal nobody can
 * override. `$()`, backticks and `sh -c` are certain carriers — the shell really
 * will run what they hold — and keep their recursion into the denylist.
 *
 * Measured before this fix: `git commit -m 'reboot the worker pool'` was a hard
 * deny (ruleId `denylist`) on an admin/dev profile with `approvalPolicy: 'auto'`
 * — a role and tier that holds `privileged` outright and a policy that prompts
 * for nothing, denied anyway, because the quoted commit message happened to
 * start with a forbidden word.
 */
describe('the catch-all cannot feed the unconditional denylist', () => {
  const adminAutoDev = {
    name: 'dev-admin', host: 'h', port: 22, user: 'deploy', auth: 'agent', tty: false,
    timeout: 60_000, maxChars: 5000, maxOutputBytes: 1_048_576, group: 'dev',
    role: 'admin', readOnly: false, approvalPolicy: 'auto', cert: false,
    announceAgent: true, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600_000,
    sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
    transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
  } as unknown as Profile;
  const engineForRuling = new PolicyEngine(DEFAULT_RULES);
  const decideAsAdmin = (command: string) => engineForRuling.evaluate(command, adminAutoDev, 'run-command');

  it('no longer hard-denies a speculative catch-all match', () => {
    const result = decideAsAdmin("git commit -m 'reboot the worker pool'");
    expect(result.ruleId).not.toBe('denylist');
    expect(result.commandClass).toBe('destructive');
    // admin/dev holds destructive outright and approvalPolicy is auto, so
    // nothing here should even prompt — the point is not merely "not an
    // absolute deny", it is "treated as the ordinary destructive command
    // this profile is already trusted with".
    expect(result.decision).toBe('allow');
  });

  it.each([
    ["a $() substitution", 'echo $(shutdown -h now)'],
    ['a backtick substitution', 'echo `shutdown -h now`'],
    ['sh -c', "sh -c 'shutdown -h now'"],
    ['pwsh -EncodedCommand', `pwsh -EncodedCommand ${encode('shutdown -h now')}`],
  ])('certain carriers still reach the denylist: %s', (_label, command) => {
    const result = decideAsAdmin(command);
    expect(result.ruleId, command).toBe('denylist');
    expect(result.decision, command).toBe('deny');
  });

  it('a speculative-only carrier is raised to destructive, not refused outright', () => {
    const result = decideAsAdmin("whatever 'shutdown -h now'");
    expect(result.ruleId).not.toBe('denylist');
    expect(result.commandClass).toBe('destructive');
    expect(result.decision).toBe('allow');
  });

  it('nestedCommands drops the speculative operand when told this is for the denylist', () => {
    // The mechanism directly: the catch-all's push is what speculativeOperands
    // gates, and findForbiddenMatch is the caller that must pass false.
    expect(nestedCommands("whatever 'shutdown -h now'", true)).toContain('shutdown -h now');
    expect(nestedCommands("whatever 'shutdown -h now'", false)).not.toContain('shutdown -h now');
  });

  it('findForbiddenMatch itself no longer matches the speculative-only shape', () => {
    expect(findForbiddenMatch("whatever 'shutdown -h now'")).toBeNull();
    expect(findForbiddenMatch("git commit -m 'reboot the worker pool'")).toBeNull();
  });

  it('findForbiddenMatch still matches every certain carrier', () => {
    expect(findForbiddenMatch("sh -c 'shutdown -h now'")).not.toBeNull();
    expect(findForbiddenMatch('echo $(shutdown -h now)')).not.toBeNull();
    expect(findForbiddenMatch('echo `shutdown -h now`')).not.toBeNull();
  });
});

/**
 * `foundProgram` used to be one boolean per segment: the moment ANY word in the
 * segment resolved to an interpreter's program, the catch-all was skipped for
 * every OTHER operand in that segment too — including ones the interpreter
 * never touched. An unrecognised binary's own operand, sitting right next to a
 * harmless `sh -c true`, was defused by it.
 *
 * Measured before this fix: `unknownbin 'sudo id'` classified `privileged` —
 * the catch-all working as designed — but `unknownbin sh -c true 'sudo id'`
 * classified `safe`: `sh -c` consumed `true` as its program (itself harmless
 * and pushed), which set the segment-wide flag and silenced the catch-all
 * before it ever looked at `'sudo id'`.
 */
describe('the catch-all is not defused for the whole segment by one benign interpreter call', () => {
  it('a speculative operand is caught on its own', () => {
    expect(classifyCommand("unknownbin 'sudo id'").class).toBe('privileged');
  });

  it('a benign sh -c earlier in the same segment must not silence a later operand', () => {
    expect(classifyCommand("unknownbin sh -c true 'sudo id'").class).toBe('privileged');
  });

  it('still does not double-count the operand an interpreter actually consumed', () => {
    // `sh -c` here really does consume `'sudo id'` as its program — that is a
    // certain carrier, pushed unconditionally by the interpreter loop, not the
    // catch-all. The class must still land on `privileged`; this is a sanity
    // check that the fix does not depend on double-pushing the same text.
    expect(classifyCommand("unknownbin sh -c 'sudo id'").class).toBe('privileged');
  });
});

/**
 * `programAfterFlag`'s `tolerateUnknownWordsAtHead` — the pwsh/powershell
 * tolerance for an unrecognised option's bare value (`-ExecutionPolicy
 * Bypass`) sitting between the interpreter and `-EncodedCommand` — only took
 * effect at `from === 0`. That is the position of the interpreter itself only
 * when nothing precedes it; behind any exec wrapper (`env`, `nohup`, `nice`,
 * `timeout`, `xargs`, …) the interpreter sits at position 1 or later, and the
 * tolerance never engaged.
 *
 * Measured: `env pwsh -ExecutionPolicy Bypass -EncodedCommand <b64 of sudo
 * id>` classified `safe` — the exact shape #266's fix closed for a bare
 * `pwsh`, still open one wrapper away.
 */
describe('fix round 4: the pwsh tolerance reaches past an exec wrapper, not just position 0', () => {
  it.each([
    ['env', `env pwsh -ExecutionPolicy Bypass -EncodedCommand ${encode('sudo id')}`],
    ['nohup', `nohup pwsh -ExecutionPolicy Bypass -EncodedCommand ${encode('sudo id')}`],
    ['timeout 5', `timeout 5 pwsh -ExecutionPolicy Bypass -EncodedCommand ${encode('sudo id')}`],
    ['env, powershell spelling', `env powershell -WindowStyle Hidden -EncodedCommand ${encode('sudo id')}`],
  ])('finds -EncodedCommand behind %s', (_label, command) => {
    expect(classifyCommand(command).class, command).toBe('privileged');
  });

  it('does not reopen mention-vs-invocation: pwsh as an unrelated flag value stays safe', () => {
    // The exact shape `from === 0` used to protect, now protected by
    // `from === effectiveCommandIndex(words)` instead: `pwsh` here is a VALUE
    // of `customtool`'s own `--search` flag, never actually invoked, and
    // `customtool` — not `pwsh` — is the effective command word.
    const command = `customtool --search pwsh -ExecutionPolicy Bypass -EncodedCommand ${encode('sudo id')}`;
    expect(classifyCommand(command).class).toBe('safe');
  });

  it('does not widen an unrelated wrapper: nsenter -m sh -c is unaffected', () => {
    // sh is not pwsh-family (no -EncodedCommand in its programBearingWords), so
    // tolerateUnknownWordsAtHead is false for it regardless of position; this
    // shape was never broken and must not become newly sensitive to this fix.
    expect(classifyCommand(`nsenter -t 1 -m sh -c 'sudo id'`).class).toBe('privileged');
  });
});
