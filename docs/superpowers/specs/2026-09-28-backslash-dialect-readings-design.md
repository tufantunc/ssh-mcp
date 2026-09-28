# Backslash readings: classify both shells' parses, not one shell's guess

**Advisory:** GHSA-972x-g47g-3922 (draft, embargoed)
**Work happens in:** `tufantunc/ssh-mcp-ghsa-972x-g47g-3922`, branch `advisory-fix-1`.
Nothing reaches the public repository before the advisory is published.
**Release:** minor.

## Problem

The classifier receives a string, not an argv. It must guess how the host's
shell will split that string into words before it can say what runs — and the
guess is made without knowing which shell sits at the other end. OpenSSH on
Linux runs the POSIX shell of the target user; on Windows the default is
`cmd.exe`. The two disagree about one byte in particular: for POSIX a backslash
escapes the next character, for `cmd.exe` it is an ordinary path separator. The
tokeniser picks the POSIX reading (`src/policy/classifier.ts:916-936`), and
every disagreement between the two readings is a place where the classifier
describes a command the host does not run.

That disagreement is the advisory. Measured on 2.13.0 through
`PolicyEngine.evaluate`, profile `operator`, group `prod`,
`approvalPolicy = ask-destructive` (line anchors are as of `1ccee48`):

| command head | class | decision |
|---|---|---|
| `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -EncodedCommand <b64>` | `destructive` | deny |
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -EncodedCommand <b64>` | `safe` | **allow** |

The POSIX reading deletes every backslash, so the command word arrives as the
glued `C:WindowsSystem32WindowsPowerShellv1.0powershell.exe`. `stripPath`
cuts on `/` only (`classifier.ts:1337-1341`), `resolveInterpreter` strips an
`.exe` suffix but nothing else (`classifier.ts:795-799`), so no interpreter is
recognised, `-EncodedCommand` is never decoded, and the payload-free shell
command that remains classifies `safe`. On Windows 11 (build 26200) the same
line, run by `cmd.exe`, executes the encoded program. An `operator` holding
`safe` but not `destructive` runs arbitrary PowerShell without approval — the
same shape as GHSA-qvx5-rxrj-9vfh, one dialect over.

The advisory names a second divergence: inside double quotes the tokeniser
also drops a backslash before an ordinary character (`classifier.ts:926`).
POSIX keeps it there — within double quotes only `$`, `` ` ``, `"`, `\` and
newline are escapable. This reading is wrong for POSIX *and* for Windows, and
it distorts operands too: `"C:\logs"` arrives as `C:logs`.

## The question, and the answer

> The classifier cannot know whether the host shell is POSIX or `cmd.exe`.
> What should it do with a command word — and operands — containing
> backslashes?

It must not choose. When one string has two defensible parses, the classifier
is describing *both hosts' commands*, and policy must hold on whichever host
receives it. So: **parse the command under both dialects, classify both
parses, and let the worse class win.** The second parse runs only when the
command contains a backslash at all; commands without one are byte-identical
under both dialects and keep today's single-pass behaviour.

This is GHSA-qvx5's contract — classify the command a shell would actually
run — generalised from "the shell" to "every shell that might be there".

## Why the narrower fixes were rejected

**Literal-only tokenisation** (backslash is always an ordinary character, so
`C:\…\powershell.exe` survives intact) closes the Windows reading by opening
the POSIX one: on a POSIX host `r\m -rf /etc` *is* `rm -rf /etc`, and a
literal-only tokeniser hands the classifier an unknown binary `r\m` — `safe`.
That is GHSA-qvx5's bypass, mirrored. Trading one host's blindness for the
other's is not a fix; only holding both readings is.

**An ambiguity gate** (any backslash surviving in a command word makes the
command unnameable, so it falls to the role gate and is refused or gated)
fails closed and is cheap. But it punishes the native spelling of a supported
platform — `type C:\logs\app.log` carries no interpreter and still gets
gated — and it replaces understanding with a refusal. The project's last two
advisory fixes went the other way (qmx6 decoded the payload, qvx5 read the
command the shell runs). The gate is recorded as the fallback if dual parsing
proves unimplementable, not as the design.

## Contract

When a command contains a backslash, every classification decision is made
once per dialect — POSIX and Windows — and combined worst-case:

- A denial, elevation or payload found under **either** reading applies.
- A grant (`read-only` via proven-read grammar, a reader match, a glob staying
  quoted) requires **every** reading to qualify.

Both rules are one rule: the command's class is the maximum over the readings
under `CLASS_RANK`. The cost of disagreement falls on the caller as an
approval or refusal they can see, never on the policy as an allow. Commands
without a backslash are classified exactly as before, by one parse, with no
behaviour change.

## Design

### The two dialects

A dialect is one rule about one byte, applied by the scanners:

- **posix** — unquoted `\` escapes the next character (today's behaviour,
  `classifier.ts:931`); inside double quotes `\` escapes only `` $ ` " \ `` and
  newline, and is **retained** before every other character (the fix for
  `classifier.ts:926`); inside single quotes it stays literal (unchanged).
- **windows** — `\` is an ordinary character everywhere, quoted or not.

The windows rule is not an approximation of `cmd.exe`; it *is* `cmd.exe`'s
rule. `cmd.exe` has no backslash escapes at the shell level at all. Everything
else in the scanner — which characters separate words, which quotes group — is
shared by both dialects. The dialect is a parameter, not a second scanner:
`tokenizeSegmentsDetailed(command, honorQuotes, dialect)` and
`firstUnquotedGlobWord(command, honorQuotes, dialect)` grow one branch each,
and no other scan logic diverges.

Word boundaries may differ between readings (`a\ b` is one word to POSIX, two
to `cmd.exe`), which is why the readings produce independent word lists rather
than one list with annotations.

### Path stripping cuts on both separators

`stripPath` takes the cut at the *later* of the last `/` and the last `\`.
The windows reading needs it (`C:\…\powershell.exe` → `powershell.exe` →
`resolveInterpreter` strips `.exe` → `powershell` → payload decoded). The
POSIX reading needs it too once double quotes keep backslashes:
`"C:\…\powershell.exe" -EncodedCommand …` tokenises, POSIX-accurately, to a
word still carrying separators. `/sbin/reboot` is unchanged, and the POSIX
reading's unquoted words contain no backslashes to cut on, so the change is
inert where it does not apply.

### One unescape per dialect, then never again

Today `unquote` (`classifier.ts:1315-1324`) strips a surrounding quote pair
*and* re-runs POSIX backslash removal on words that the tokeniser has already
processed. Two layers of quote removal applied to one word is how a faithful
word becomes a glued one: under the fixed double-quote rule the POSIX reading
delivers `C:\…\powershell.exe` intact, and `unquote` would eat it back.

The invariant instead — already pinned for awk by
`test/unit/policy/awk.test.ts` ("no second unquote"):

> By the time a word reaches `resolveInterpreter` or `stripPath`, its bytes
> are exactly the argv its dialect's shell would pass. Quote removal happens
> once, in the scanner, under that dialect.

Concretely, `unquote` keeps only the job that is still theirs to do —
stripping the surrounding quote pair from words produced by the
`honorQuotes = false` fallback rescan — and its backslash removal follows the
dialect of the scan that produced the word: applied for the POSIX fallback
(`\sudo` in the fallback is still `sudo`), never applied in the windows
reading, and never applied to words the quote-honouring scan already
processed. Where exactly that lands is an implementation-plan question; the
invariant is the spec.

### Where the readings combine

`classifyCommand(command)` (`classifier.ts:2148-2191`) becomes the combination
point:

```
readings = command.includes('\\') ? [posix, windows] : [posix]
class    = max over readings of classify-under-that-dialect(command)
```

Everything downstream — `nestedCommands`' per-word interpreter loop
(`classifier.ts:1126-1154`), the `-EncodedCommand` decode gate
(`classifier.ts:1149-1152`), the speculative operand reader (`1176-1182`),
`classifyOuter`'s reader grammars, privilege prefixes — runs unchanged on each
reading's word lists, because they already consume whatever the scanners
produce. Recursive classification of an operand re-enters `classifyCommand`
and inherits the rule on its own string.

Two decision paths tokenize outside `classifyCommand` and must take the same
maximum:

- `findForbiddenMatch` (`classifier.ts:1583-1608`) — the built-in denylist
  fires if **either** reading matches.
- `firstUnquotedGlobWord` (`classifier.ts:47-86`) — the proven-read glob gate
  holds only when the glob word is quoted in **every** reading.

`PolicyEngine.evaluate` needs no change: it already decides from
`classifyCommand`'s class and `findDenyMatch`, both of which are now
worst-case. The audit for the implementation plan is the enumeration of every
caller of `tokenizeSegments`, `tokenizeSegmentsDetailed`,
`firstUnquotedGlobWord` and `unquote`; each either consumes a single dialect's
output (fine — it sits inside one reading's pass) or is a decision point (must
combine). No third category exists.

### What the fix does not rely on

The catch-all operand reader is not part of the fix. An encoded payload is a
single word without whitespace, so the catch-all cannot see it; the advisory
is closed by the interpreter table resolving `powershell` out of the
backspelled path, which is the same mechanism that already handles the bare,
`.exe` and forward-slash spellings.

## Explicitly not fixed, with reasons

- **`cmd.exe`'s quote dialect.** Single quotes do not group in `cmd.exe`, `^`
  escapes, and `%VAR%` expansion are unmodelled. The windows reading changes
  only backslash semantics and keeps the shared quote model, which sits on the
  conservative side of the divergence: keeping single-quote grouping can only
  merge words, and a merged, whitespace-bearing operand is one the catch-all
  reads as a command, not one it skips.
- **PowerShell as the host shell.** A Windows host configured with PowerShell
  as the default SSH shell parses with its own rules (backtick escapes).
  Out of scope; recorded as residual risk below.
- **Windows CRT argument-passing.** How `"C:\dir\"` splits between the shell
  and the program's runtime affects argv after the shell; the classifier
  models the shell.
- **New interpreters.** `cmd`, `cscript`, `wscript`, `mshta` are carriers
  with their own program-bearing flags and belong to a separate audit of the
  `INTERPRETERS` table, not to a parsing fix.

## Residual risks, recorded not closed

- A command whose readings disagree in severity is classified by the worse
  one even when the actual host would have run the benign one. The caller
  sees an approval, not a silent allow — the intended direction, but it is a
  real prompt on Windows-native commands whose backslashes a POSIX host would
  have eaten.
- The windows reading models the shell's parse, not the program's. A glob
  inside a `for` loop or a program that expands its own wildcards is beyond
  any shell model; pre-existing, unchanged by this design.
- Dialect divergence beyond the backslash (single quotes, `^`, `%VAR%`)
  remains a single-reading approximation, per "Explicitly not fixed".

## Testing

New suite `test/unit/policy/backslash-readings.test.ts`, alongside
`quote-removal.test.ts` and `carrier-completeness.test.ts`:

1. **The advisory table, verbatim.** All four spellings — bare, `.exe`,
   forward-slash, backslash — with an elevation payload class `privileged`
   and with a plain destructive payload class `destructive`, quoted and
   unquoted, plus the `pwsh` spelling. None may classify `safe`.
2. **POSIX fidelity retained.** `r\m -rf /etc` stays `destructive`,
   `\sudo id` stays `privileged`, `to\uch /tmp/x` stays a write — the qvx5
   suite must pass unchanged.
3. **Double-quote fix.** `"C:\logs"` reaches matchers as `C:\logs`, not
   `C:logs`; a `"…\powershell.exe" -EncodedCommand` head resolves under the
   reading that keeps its separators.
4. **Worst-case combination, both directions.** A string `safe` under POSIX
   and `destructive` under windows classifies `destructive`; the mirror case
   too. A reader whose grammar matches under one reading only falls off
   `read-only`.
5. **Separator cuts.** `stripPath` on `C:\…\powershell.exe`,
   `\\server\share\powershell.exe`, `/sbin/reboot`, plain `reboot`.
6. **No-backslash gate.** For commands without a backslash, classification is
   bit-identical to the single-pass path (guard against the second pass
   leaking in a semantic change).
7. **Fallback rescan.** An unterminated quote still demotes to
   `honorQuotes = false` under both dialects and still resolves the elevation
   it was hiding (`echo "hi; C:\…\powershell.exe -EncodedCommand …`).
8. **Denylist.** A built-in denied binary reached through a backspelled path
   fires in the reading that resolves it.

Existing suites are the regression contract: `quote-removal`,
`carrier-completeness`, `proven-read`, `awk` (the no-second-unquote pins) all
pass unchanged. No test today pins backslash-before-ordinary-character inside
double quotes or a backslashed command word, so no pinned behaviour is
expected to move.

## Release

Patch. A security fix that closes a bypass; no API or config surface changes.
Changeset with the implementation PR, per CONTRIBUTING.
