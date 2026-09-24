import { describe, it, expect } from 'vitest';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { classifyCommand, READ_ONLY_ALLOWLIST, READERS } from '../../../src/policy/classifier.js';
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
    for (const [name, entry] of Object.entries(READERS)) {
      expect(typeof entry.readOnly, name).toBe('boolean');
      expect(typeof entry.operandsAreData, name).toBe('boolean');
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
    ['tclsh', `tclsh -c 'exec systemctl stop nginx'`],
    ['deno eval', `deno eval 'new Deno.Command("systemctl").outputSync()'`],
    ['pwsh -Command', `pwsh -Command 'Stop-Service nginx'`],
  ])('treats a program handed to %s as unreadable', (_label, command) => {
    // No elevation in these payloads, so Task 1's scan does not reach them. This
    // is the half that needs the name.
    expect(classifyCommand(command).class, command).toBe('destructive');
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
