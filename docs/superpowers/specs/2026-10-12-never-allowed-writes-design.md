# The never-allowed list refuses the writes it promises, in the forms an agent writes them

**Advisory:** GHSA-rrxj-hcj2-vwm6 (draft; the class stays out of public text until it is published).
**Work happens in:** worktree `ghsa-rrxj`, branch `ghsa-rrxj-never-allowed-writes`, from `main` at `723a7c5`.
**Release:** minor.
**Embargo:** pushed only to the advisory's temporary private fork. No public PR, issue,
comment, changeset or commit text describes the class before publication.

## Problem

The README's never-allowed list says "writes to `/etc/cron`, `/etc/systemd` or
`authorized_keys`" are refused "whatever the role or approval policy". The rules behind
that sentence — three regexes in `FORBIDDEN_PATTERNS` (`src/policy/classifier.ts`) — match
one spelling of one kind of write: a `>` redirect against `/etc/cron`/`/etc/systemd` as a
literal prefix, and only the `~/.ssh/authorized_keys` spelling for keys. Every other way of
writing those files, including both SFTP write tools, never reaches the list.

Measured on `main` at `723a7c5` (`PolicyEngine`, default rules, admin, `approvalPolicy =
"auto"`); `findForbiddenMatch` is the never-allowed check, `class` is what governs the call
when it does not fire:

| command | never-allowed | class | runs on |
|---|---|---|---|
| `echo k > ~/.ssh/authorized_keys` | deny | destructive | nothing |
| `echo k > /root/.ssh/authorized_keys` | pass | safe | prod |
| `echo k > ~root/.ssh/authorized_keys` | pass | safe | prod |
| `tee -a ~/.ssh/authorized_keys` | pass | safe | prod |
| `cp k ~/.ssh/authorized_keys` | pass | safe | prod |
| `cp k /etc/cron.d/x` | pass | safe | prod |
| `install -m 600 k /root/.ssh/authorized_keys` | pass | safe | prod |
| `dd of=/root/.ssh/authorized_keys` | pass | safe | prod |
| `mv k /etc/systemd/system/x.service` | pass | safe | prod |
| `sudo cp k /root/.ssh/authorized_keys` | pass | privileged | staging/dev |
| `sh -c "cp k /root/.ssh/authorized_keys"` | pass | safe | prod |
| `sftp-upload` → `/root/.ssh/authorized_keys` | pass | destructive | staging/dev |
| `sftp-upload-file` → `/etc/cron.d/x` | pass | destructive | staging/dev |
| `echo x > /etc/cron.d/x` | deny | destructive | nothing |

(The advisory's own table measured the same on 2.17.0; the rows above were re-measured on
this branch's base commit. Two more rows belong to the same defect, in the opposite
direction — refusals that fire on text a shell does not act on, see decision 6.)

## Decisions

Taken in the design round on 2026-10-12, each with the alternative it was chosen over.
(#230's spec is the direct precedent: `docs/superpowers/specs/2026-10-04-denylist-remote-path-design.md`.)

1. **Which paths the guarantee covers: the README's three, read as path families.**
   `/etc/cron` and `/etc/systemd` are subtree prefixes — any path under them, including
   `/etc/crontab` by today's prefix reading — matched after lexical normalization, absolute
   form only. `authorized_keys` is any path whose last two segments are
   `.ssh/authorized_keys`: `~/.ssh/authorized_keys`, `~root/…`, `/root/…`, `/home/u/…`, a
   relative `.ssh/authorized_keys`, and the Windows spellings through the `\`-as-separator
   readings. `authorized_keys2` and a non-default sshd `AuthorizedKeysFile` are not
   covered; they are residuals for the operator's denylist (decision 7).
   *Rejected:* keeping the three literal spellings — that is the measured defect.

2. **One path predicate, defined once, consumed by both check sites.** A new module
   `src/policy/never-allowed-writes.ts` exports `findNeverAllowedWriteTarget(path)`:
   the path as given, then `normalizeRemotePath` of it, then
   `normalizeRemotePathForWindows` of it tested case-insensitively (the three readings
   #230 already built for operator patterns) against the three families. The classifier's
   shell-side rule and the engine's resource-side check both call it, so the two cannot
   drift. The engine's own history is the warning here: it used to keep a parallel copy of
   the built-in patterns that had already drifted (see the comment above
   `FORBIDDEN_PATTERNS`).
   *Rejected:* implementing the match twice (regexes in the classifier, readings in the
   engine) — the drift above is what that produces.

3. **SFTP write tools are covered through the resource, which declares the write.**
   `PolicyResource` gains `remoteWrite?: boolean`. `sftp-upload` and `sftp-upload-file`
   set it; the read tools (`sftp-list`, `sftp-download`, `sftp-download-file`) do not. In
   `findDenyMatch`, before the operator-pattern early return, a declared remote write is
   tested against the three readings by the shared predicate, with the built-in refusal
   wording ("cannot be switched off"). The OPA input's `resource` gains `remoteWrite` for
   the same reason it gained the path readings (#230).
   *Rejected:* parsing the synthetic verb out of the composed command string — that
   recouples a security decision to a presentation layout #230 just decoupled, and the
   tool layer knows the fact as a field.

4. **Shell commands are covered by certain write forms only — redirects and a closed
   verb list — read from resolved tokens, never from raw text.** The three regexes
   `>\s*/etc/cron`, `>\s*/etc/systemd`, `>\s*~/.ssh/authorized_keys` are removed from
   `FORBIDDEN_PATTERNS`, superseded by one word-based `FORBIDDEN_RULES` entry per family
   (scan shared, three labels) that fires when:

   - a **shell redirect** (`>`, `>>`, `1>`, `2>`, `&>`, the attached `>path`, the quoted
     `> "path"`) has a target naming a covered path — recognized only where the shell
     would perform one: an unquoted `>` at the start of a word or as a word of its own,
     tracked through the tokenizer's quote state. A quoted `">/etc/cron.d/x"` is data,
     not a redirect;
   - the segment's head (past privilege prefixes and the existing segment machinery) is
     **`tee`** — every non-flag operand is a write target; **`cp` / `mv` / `install`** —
     the destination candidates: the value of `-t`/`--target-directory` if present, else
     the last non-flag operand, plus — because that operand may name a directory — the
     same joined with the basename of every other non-flag operand (so `cp authorized_keys
     ~/.ssh/` is caught, not just `cp k ~/.ssh/authorized_keys`); for `install -d`, every
     non-flag operand; **`dd`** — the value of an `of=` operand.

   The scan runs per dialect (both readings when a backslash is present) and reaches
   nested commands through the existing `nestedCommands(command, false, …)` recursion in
   `findForbiddenMatchInDialect`, so `sh -c "cp k /root/.ssh/authorized_keys"` and
   `echo $(tee -a /etc/cron.d/x)` are covered by the same carriers the other rules use.
   *Rejected:* widening the regex list (`tee\s+-a\s*…`, `cp\s+…`) — a regex cannot read
   dequoted, normalized or Windows spellings without reintroducing the `\S*`-backtracking
   shapes this file has banned once already, and cannot see the SFTP tools at all.

5. **Reads stay allowed, everywhere.** `cat`/`grep`/`head`/`tail` over these paths,
   `sftp-download`, `sftp-download-file`, `sftp-list /etc/cron.d` keep today's class and
   decision. The new checks fire only in write contexts: a redirect target, a write verb's
   destination, or a tool-declared `remoteWrite`. Explicit rows in every test file guard
   this.
   *Rejected:* matching covered paths anywhere in the command — that refuses `cat
   ~/.ssh/authorized_keys` and `grep -c ssh /etc/cron.d/x`, which no reading of the README
   promises and the readOnly profile depends on.

6. **A guess still may not manufacture an unconditional refusal.** The maintainer's
   `speculativeOperands: false` ruling is unchanged: the new scan reads resolved tokens
   and certain carriers only, never the catch-all operands of an unrecognised binary, and
   the resource field is a fact the tool layer states, not a guess. Two over-refusals the
   raw regexes produce today are corrected with this: `git commit -m "echo x > /etc/cron"`
   and `echo "> /etc/cron.d/y"` are measured **deny** on `main` — a quoted mention is not
   a write — and become allowed, the same direction as #91's mention-vs-invocation fix.
   `git commit -m 'tee -a /etc/cron.d/x'` (no `>` in the text) is allowed today and stays
   allowed.

7. **The README and SECURITY.md promise exactly the forms above, and name the residuals.**
   The never-allowed sentence lists the covered write forms (SFTP upload tools' remote
   path; shell redirects; the destination of `tee`, `cp`, `mv`, `install`, `dd of=`) and
   says other spellings are governed by class and approval. The residuals named:
   other write verbs (`sed -i`, `rsync`, `truncate`, an interpreter's program), a
   non-default `AuthorizedKeysFile` (including `authorized_keys2`), writes whose
   destination is computed by the target (`cd` + relative, variables), and — carried over
   from #230 — symlinks and 8.3 short names on Windows. SECURITY.md's residual-risks
   section gains the matching rows. No completeness is claimed anywhere: extracting paths
   from shell text cannot be made complete (#230 decision 1), and the documents say what
   is covered rather than implying the rest is impossible.
   *Rejected:* keeping the unconditional sentence as written and only widening the
   implementation — the gap between a complete-sounding promise and a partial mechanism
   is the defect this advisory reports.

8. **No new measurements on the Windows VM.** The path readings are #230's, measured over
   SFTP on Windows 11 build 26200; this design reuses them unchanged. The shell-side
   redirect/verb forms are POSIX-shell and cmd.exe syntax questions already answered by
   the tokenizer's two dialects. If implementation surfaces a spelling the readings do
   not decide, it becomes a documented residual rather than a new measurement.

## Behaviour after the fix

Same table, same profile (`admin`, `auto`), after the change:

| command | never-allowed | note |
|---|---|---|
| `echo k > ~/.ssh/authorized_keys` | deny | word-based now |
| `echo k > /root/.ssh/authorized_keys` | **deny** | the measured gap |
| `echo k > ~root/.ssh/authorized_keys` | **deny** | |
| `echo k > "//etc/cron.d/x"` | **deny** | quoted target, normalized reading |
| `tee -a ~/.ssh/authorized_keys` | **deny** | |
| `cp k ~/.ssh/authorized_keys` | **deny** | |
| `cp authorized_keys ~/.ssh/` | **deny** | directory-destination composition |
| `cp -t /etc/cron.d x` | **deny** | |
| `install -m 600 k /root/.ssh/authorized_keys` | **deny** | |
| `dd of=/root/.ssh/authorized_keys` | **deny** | |
| `mv k /etc/systemd/system/x.service` | **deny** | |
| `sudo cp k /root/.ssh/authorized_keys` | **deny** | privilege prefix stepped over |
| `sh -c "cp k /root/.ssh/authorized_keys"` | **deny** | certain carrier |
| `sftp-upload` → `/root/.ssh/authorized_keys` | **deny** | resource declares the write |
| `sftp-upload-file` → `/etc/cron.d/x` | **deny** | |
| `cat ~/.ssh/authorized_keys` | pass, `read-only` | reads unchanged |
| `sftp-download` → `/root/.ssh/authorized_keys` | pass | |
| `sftp-list /etc/cron.d` | pass | |
| `git commit -m 'tee -a /etc/cron.d/x'` | pass | mention, no `>` in text |
| `git commit -m "echo x > /etc/cron"` | pass | corrected over-refusal |
| `echo "> /etc/cron.d/y"` | pass | corrected over-refusal |
| `sed -i 1d ~/.ssh/authorized_keys` | pass, `safe` | residual, documented |
| `rsync k /root/.ssh/authorized_keys` | pass, `safe` | residual, documented |

## Files

- `src/policy/never-allowed-writes.ts` — new: the path predicate over the three readings.
- `src/policy/classifier.ts` — the three `FORBIDDEN_PATTERNS` regexes removed; the
  shell-form scan and its `FORBIDDEN_RULES` entries added; no change to
  `speculativeOperands`, the tokenizer, or class assignment.
- `src/policy/engine.ts` — `PolicyResource.remoteWrite`, the built-in resource check in
  `findDenyMatch`, `remoteWrite` in the OPA input.
- `src/tools/file-tools.ts`, `src/tools/transfer-tools.ts` — the two write tools declare
  `remoteWrite: true`.
- `README.md`, `SECURITY.md` — decision 7.
- `.changeset/` — one neutral minor changeset.

## Testing

TDD throughout; each test is seen failing first and counts only if it fails with its
production line removed (mutation run on a backup, restored after). Foreign mutants too —
normalizer-shaped edge cases the author of a line tends not to write: `//`, `/./`, `..`,
trailing separators, `~`-prefixed and drive-letter spellings, `\\?\` and `::$DATA`,
trailing dot runs, case variants.

- `test/unit/policy/never-allowed-writes.test.ts` — the predicate: family membership per
  reading, and non-membership (reads' paths, `authorized_keys2`, unrelated paths).
- classifier tests — the shell rows of both tables above (deny rows, read rows, corrected
  over-refusals, mention rows), both dialects where a backslash is involved.
- `test/unit/policy/engine.test.ts` — the resource rows: `remoteWrite` + covered path →
  built-in deny wording; `remoteWrite` + benign path → allowed; no `remoteWrite` (every
  read tool) + covered path → allowed; the check runs with an empty operator denylist.
- a tools-level test mirroring `test/unit/tools/denylist-remote-path.test.ts` — every
  SFTP tool through its real handler: writes to covered paths refused, reads of the same
  paths not, no operator denylist configured.

No wall-clock timing in any test.

## Review round (2026-10-12, after implementation)

Five specialist reviewers over the branch; every Medium+ finding verified by probe and
cleared with the same TDD rules. Corrections folded into decision 4's mechanism:

- the redirect operator set gained `>|` (noclobber override), and a closing quote no
  longer ends a target word — the shell concatenates the tail (`> ""~/x` measured as a
  bypass before the fix);
- `-t`/`--target-directory` is read in all three spellings (`-t DIR`, `-tDIR`,
  `--target-directory=DIR`, `--target-directory DIR`) — the separate-value long form was
  mis-parsed into a garbage destination;
- GNU option permutation is stepped over (`install k DEST -m 600`), and `xargs`'s own
  value-taking flags no longer hide the verb it wraps (`xargs -I {} cp {} …`);
- the older `dd of=/dev/…` rule reads its head through `effectiveCommandIndex` too
  (`env dd of=/dev/sda` was missed), and the three-family scan is cached per
  (command, dialect) the way `normalizeCommand` is.

Documented residuals rather than code, per decision 8: cmd.exe's `copy`, `move` and
`robocopy` verbs are named in README/SECURITY (their switch spellings — `/Y` trailing a
destination — are exactly a spelling the readings do not decide). The changeset stays
minimal until publication, when it is expanded with the compatibility note below.

## Compatibility

A working setup can start failing: shell forms and SFTP uploads that name these paths
previously ran for roles holding `safe`/`destructive` under permissive approval modes, and
now are refused outright. That is the advisory's fix, and it is why the release is
**minor**, not patch. The corrected direction is narrower: the two quoted-mention
over-refusals (decision 6) stop refusing, which no README sentence ever promised.
