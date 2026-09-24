# Carrier completeness: what happens to the operands of a binary we do not recognise

**Status:** design approved in chat, spec awaiting review
**Advisory:** GHSA-qmx6-47vm-3vf7 (accepted, draft) — reported by @MartOcd1709
**Embargo:** this document describes an unpatched vulnerability. It lives in the
private fork and must not reach the public repository before the advisory is
published.

## The problem, as measured

`src/policy/classifier.ts` decides what to do with a command's operands from two
allowlists:

```
READ_ONLY_ALLOWLIST   68 binaries   operandsAreData() -> skip the carrier scan
INTERPRETERS          13 binaries   an operand is a program -> read it
everything else                     operands never examined -> safe
```

The third bucket is the vulnerability. Measured on 2.11.0, `operator`/`prod`,
`ask-destructive`:

```
direct    privileged  DENY   sudo id
carried   safe        ALLOW  osascript -e 'do shell script "sudo id"'
```

A command the policy refuses outright runs with no prompt, and the audit record
labels it `safe`. Also bypassing: `lua -e`, `Rscript -e`, `bun -e`, `deno eval`,
`tclsh -c`, `pwsh`/`powershell -Command`, and `pwsh -EncodedCommand <base64>`.

Two facts narrow and widen the impact respectively:

- Payloads whose *text* matches a destructive pattern still classify
  `destructive` even when carried — `osascript -e 'do shell script "rm -rf /srv"'`
  is caught. The laundering concentrates on **elevation** and on payloads that
  match no text pattern.
- `-EncodedCommand` hides the payload from every text scan, and Windows is an
  explicitly supported target with its own integration file
  (`test/integration/windows-compat.test.ts`). The advisory leads with
  `osascript`/macOS; for this project the Windows form is the heavier one,
  because macOS appears in the README only as a *client* config path.

## Why the narrow fix was rejected

Adding the eight names to `INTERPRETERS` closes exactly the measured forms and
leaves the structure that produced them. The advisory says so; so does this
repo's own F6 note — *"fixing carriers individually is what produced this
history."*

This is the **third** time the same asymmetry has been patched. `classifier.ts:406`
records the second:

> The elevation scan reads tokens produced by splitting on `;&|` and whitespace,
> so it only ever saw the outer command … The destructive scan never had this
> problem because it reads the raw text — which is why `echo $(rm -rf /)` was
> classified correctly the whole time. This closes that asymmetry by pulling the
> inner commands out so they can be classified in their own right.

GHSA-v8jh-gv7v-3gvq was fixed by extending *what counts as an inner command*.
This advisory is that fix failing on a carrier nobody listed.

## Design

### A. Elevation detection becomes structure-independent

The asymmetry is exact and visible in the source:

```
DESTRUCTIVE_PATTERNS          unanchored  -> scans the whole text
LEADING_PRIVILEGE_PREFIXES    /^\s*sudo\b/ -> matches only at the command word
```

Which is why `echo "rm -rf /srv"` is `destructive` and `echo "sudo id"` is
`read-only`.

Add the unanchored counterpart the destructive side already has (`isDestructive`
→ `matchesEitherForm`). It runs in `classifyOuter` **after** the anchored
`elevatedBinaryOf` check fails, and is subject to the operand exemption below.

This closes seven carrier forms without naming any of them.

**Accepted cost.** A command in neither allowlist whose text contains `sudo`,
`doas`, `su` or `pkexec` rises to `privileged`. This is the same trade the
project already ships for destructive patterns: `grep 'rm -rf /' /var/log/syslog`
— a pure read — classifies `destructive` today. The tolerance is not new; it is
being applied consistently.

**Not closed by A.** `-EncodedCommand`, because the payload is base64. Closed by
C instead.

### B. The dual-purpose Set is split

`READ_ONLY_ALLOWLIST` answers two different questions today:

```
"does this binary only read?"                 -> class assignment
"can this binary's operands hide a command?"  -> carrier-scan exemption
```

#217's review found that adding entries for the first silently disabled the
second, because one Set is read by two mechanisms. The codebase has already had
to route around this once: `find` **is** in `READ_ONLY_ALLOWLIST`, so
`operandsAreData(find …)` returns true and the carrier scan is skipped — and the
only way to keep `find … -exec sudo id +` working was to put the `FIND_EXEC` scan
*outside* the gate.

Split them:

| set | question |
|---|---|
| `READ_ONLY_ALLOWLIST` | unchanged name, unchanged job: class assignment |
| `OPERANDS_NEVER_COMMANDS` | the carrier-scan exemption |

The name is the point. An exemption named `operandsAreData` is what made the
conflation invisible; a name that states the claim makes adding to the wrong one
read as wrong.

**Membership: all 68 entries, unchanged.** The split is about which question each
set answers, not about moving anyone between them.

Excluding `find` was the obvious move and was measured to buy nothing. Three
mechanisms answer "can this binary's operands hide a command", and only the first
is gated by the exemption:

| mechanism | gated by the exemption? |
|---|---|
| the interpreter carrier scan | yes |
| `DISQUALIFYING_ARGS` | no — runs unconditionally |
| `FIND_EXEC_FLAGS` | no — runs unconditionally |

With `find` still exempt, `find … -exec sudo id +` is `privileged`,
`find … -exec python3 -c … +` is `destructive`, and
`find … -exec lua -e … +` is `destructive` — all three via `DISQUALIFYING_ARGS`,
which fires on `-exec` whatever the gate says. The special case is already doing
the job the exclusion would have done.

That is worth writing down rather than quietly dropping: the exclusion was in an
earlier draft of this spec, justified by reasoning about what *should* follow from
the rename, and the measurement contradicted it.

**An audit of the 68 was part of this work and found a separate bug.**
`sort --compress-program=X` makes GNU sort exec X for every temporary file it
spills — measured against coreutils 9.11, an attacker-named script ran 14,224
times for one 200k-line input. It classified `read-only`, so a `readOnly` viewer
could run an arbitrary program through `read-command` while running that same
program directly was refused. That is a lower-privileged reach than this
advisory's bypass, which needs `operator` or `admin`.

It is **not** part of this advisory and gets no advisory of its own, by the
maintainer's decision. It is fixed separately on branch
`fix/sort-compress-program` in this fork — one entry in `DISQUALIFYING_ARGS`,
the table that already held `find`'s `-exec` family — and ships in the same
release as this work.

The rest of the sweep: `git -c core.pager=X log` executes X but classifies
`safe`, so it does not reach a viewer and sits in this advisory's bucket rather
than a new one; every other execution-adjacent flag among the 68
(`--ext-diff`, `--format`, `--printf`, `-m`, `-M`) runs nothing.

**A attaches here, not to the read-only set.** `grep 'sudo' auth.log` stays quiet
because grep's operands are data — not because grep is a reader. Right reason.

### C. `INTERPRETERS` gains the measured names

All `readable: false`, matching `python`/`perl`/`node`: handing them a program at
all is `destructive` without reading it. This is existing friction, not new —
`python3 -c 'print(1)'` is already `destructive`.

| binary | program-bearing words |
|---|---|
| `osascript` | `-e` |
| `lua` | `-e` |
| `Rscript` | `-e` |
| `bun` | `-e` |
| `tclsh` | `-c` |
| `deno` | `eval` |
| `pwsh`, `powershell` | `-c`, `-Command`, `-e`, `-EncodedCommand` |

Two shape changes:

- **`flags` is renamed `programBearingWords`.** `deno eval` is a subcommand, not
  a flag. Putting it in a field called `flags` would work and would lie.
- **`-EncodedCommand` is decoded.** `readable: false` already makes the bare
  presence of a program `destructive`, so recognising the flag closes the bypass
  on its own. Decoding the base64 (UTF-16LE, as PowerShell emits) is what
  separates `destructive` from `privileged` — and that distinction decides
  whether an `admin` on `prod` gets a prompt or a refusal. Decoding is a few
  lines and applies to this one flag.

## Explicitly not fixed

- An interpreter nobody has listed, invoked with a payload that contains no
  elevation and matches no destructive pattern, still classifies `safe`. A
  narrows this to a much smaller set than today; it does not empty it.
- The friction constraint ("a command that runs silently today should run
  silently tomorrow") is met for the named examples — `kubectl`, `make`,
  `docker`, `terraform` — and is pinned by a test corpus rather than by
  assertion.

## Testing

New file `test/unit/policy/carrier-completeness.test.ts`.

1. **Every advisory form, through the engine.** Not `classifyCommand`:
   `readonly-guarantee.test.ts` exists because "the bug was what the engine then
   permitted". Assert **class and decision together** — on `operator`/`prod` both
   `destructive` and `privileged` deny, so the decision alone cannot say which
   mechanism fired. That trap was live in #217.
2. **The friction corpus.** `kubectl get pods`, `make deploy`,
   `docker run -e FOO=bar img`, `terraform apply`, `grep 'sudo' auth.log`,
   `find / -name perl` must each keep today's class. This is the constraint made
   executable.
3. **The split is a naming change, and the spec says so rather than dressing it
   as a guarantee.** With identical membership there is no test that can tell the
   two sets apart by content, and writing one that appears to would be the same
   error this repo keeps finding. What the split buys is that the next person
   adding a reader has to decide the second question explicitly, because the name
   asks it. The behaviour it protects is already pinned by the existing
   carrier-scan case in `readonly-guarantee.test.ts`
   (`sftp:list /tmp sh -c 'sudo id'` → `privileged`), which is the regression
   #217's review found.

   One thing worth measuring during implementation: swap which set
   `operandsAreData` reads and see whether anything fails. If nothing does, the
   split is inert today — still worth having for the reason above, but the spec
   should not claim more than that.
4. **Base64.** Elevation payload → `privileged`; benign payload → `destructive`;
   **malformed base64 → `destructive`, not a throw.** The decoder reads an
   attacker-controlled string.
5. **Mutation discipline.** Every test is accepted only after its production line
   is deleted and it is measured failing.

No new cost test: the elevation scan reads the same text `isDestructive` already
reads. The existing `awk.test.ts` cost cases were observed flaking under
full-suite load during this design round — tracked separately, not part of this
change.

## Release

Work happens in the private fork; the advisory stays in draft until the fix
merges.

**Version: minor.** Classification results change — a command that ran silently
can now prompt. This is the 2.8.0 rule ("a config that started yesterday can
refuse to start today") in its behavioural form. Not major: no configuration key
is removed.

After merge: publish the advisory, fill `patched_versions`, keep @MartOcd1709
credited. CVE request is the maintainer's call.
