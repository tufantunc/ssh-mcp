# Task 2 friction: existing assertions that now fail

Produced by wiring `READERS[*].grammar` into `classifyOuter`'s allowlist branch
(`src/policy/classifier.ts`). Every grammar-needed entry (`arp`, `date`, `file`,
`find`, `hostname`, `ifconfig`, `ip addr`, `ip route`, `journalctl`, `sort`,
`ss`, `uniq`, `git branch`, `git diff`, `git log`, `git remote`, `git show`)
now carries `{ args: 'getopt' | 'exact', operands: { max: 0 } }` — no flags, no
operands — so only a **bare** invocation of one of these still matches. Any
argument at all now fails the grammar and the command falls from `read-only`
to `safe`. That is the entire cause of every row below: each one calls a
grammar-needed reader with at least one argument, which an earlier round of
this file's own tests had pinned as `read-only` (or, for the `readOnly`-profile
tests, as `allow`).

`'any'` readers (`cat`, `ls`, `grep`, …) are untouched — their grammar accepts
any argument — and so is `READ_ONLY_SYNTHETIC` (the SFTP verbs), which never
reaches the grammar at all.

Per the task-2 brief, these were left red on purpose: Task 3's audit is what
decides, per entry, whether the bare-only grammar was too strict and should be
widened (adding the actual flags/operands the binary supports), or whether the
form really should be `safe`. Nothing in this table was edited, skipped, or
marked `it.fails` during Task 2.

Two of the nine failing `it` blocks below assert the policy engine's
`decision` (`allow`/`deny`) rather than `classifyCommand(...).class` directly,
because they run through `PolicyEngine.evaluate` for a `readOnly` profile. For
those the "expected/got class" columns describe the class shift that drives
the decision shift; the row is still counted from the actual failing
assertion.

**Task 3 resolution.** `audit.md`'s "Friction tablosu kararları" section ruled
on all 25 rows: 20 are accepted — the audit widened the relevant entry's
grammar (`arp`, `date`, `diff`, `file`, `find`, `hostname`, `ifconfig`, `ip
addr`, `ip route`, `journalctl`, `netstat`, `sort`, `ss`, `systemctl status`,
`uniq`, and the five `git` two-word entries) so the command in the row is
recognised again and the row's original `read-only`/`allow` expectation now
holds unedited — and 5 are accepted refusals (rows 21–25, all `sort`): the
real binary only reads in each case, but the grammar cannot tell that apart
from a flag a viewer might actually want to set (`-T`) or an abbreviation
`getopt_long` itself cannot resolve (`--c`, `--ox`, `--cx`), so it refuses the
whole word — the accepted cost of the fail-closed design, not a bug. Those
five rows' tests were updated to expect `safe`/`deny`, each with a one-line
reason (`test/unit/policy/readonly-guarantee.test.ts`). See the `Decision`
column below for the ruling on each row, and
`.superpowers/sdd/2026-09-25-proven-read/audit.md` for the full reasoning.

**Count: 25 assertions, across 9 `it` blocks, in 4 files — 20 accepted as
`read-only`/`allow` once the audit's grammar was wired in, 5 accepted
refusals with their test expectation updated to `safe`/`deny` (rows 21–25).**

Several rows come from either a plain `for (const command of [...])
expect(...)` loop or two bare sequential `expect(...)` statements, rather than
`it.each`. Vitest's single run of such a test stops at the *first* failing
`expect` and never executes the rest of the function body, so only one row per
`it` block is a directly-observed vitest failure per run; the sibling
commands on the same lines are still real, still-now-safe regressions —
independently confirmed by calling `classifyCommand` on each one directly,
outside the suite, after the first was out of the way — but are masked from a
single run's console output by the earlier throw. This affects the
`classifier.test.ts` rows at lines 235–237 and the `readonly-guarantee.test.ts`
rows at lines 43, 207–210, 239, 340, 349–350 and 356–357.

| # | File | Line | Test name | Command | Expected class | Got class | Engine decision (readOnly profile) | Task 3 ruling |
|---|---|---|---|---|---|---|---|---|
| 1 | test/unit/policy/classifier.test.ts | 235 | `elevation and exec wrappers (GHSA-6f54-mjqq-2jp8)` > `leaves mentions and ordinary searches alone` | `journalctl -u sudo` | read-only | safe | n/a (`classifyCommand` test, no engine) | **accepted** — `-u` is a `journalctl` valueFlag; test passes unedited |
| 2 | test/unit/policy/classifier.test.ts | 236 | `elevation and exec wrappers (GHSA-6f54-mjqq-2jp8)` > `leaves mentions and ordinary searches alone` | `find /etc -name "*.conf"` | read-only | safe | n/a (`classifyCommand` test, no engine) | **accepted** — `-name` is a `find` valueFlag, `/etc` is a free operand; test passes unedited |
| 3 | test/unit/policy/classifier.test.ts | 237 | `elevation and exec wrappers (GHSA-6f54-mjqq-2jp8)` > `leaves mentions and ordinary searches alone` | `find /var/log -type f` | read-only | safe | n/a (`classifyCommand` test, no engine) | **accepted** — `-type` is a `find` valueFlag; test passes unedited |
| 4 | test/unit/policy/carrier-completeness.test.ts | 68 | `an unrecognised binary cannot hide a command in its operands` > `leaves the commands an operator runs all day alone` | `find / -name perl` | read-only | safe | n/a (`classifyCommand` test, no engine) | **accepted** — same `-name` valueFlag; test passes unedited |
| 5 | test/unit/policy/quote-removal.test.ts | 97 | `what the rewrite must not break` | `find . -name "*.ts"` | read-only | safe | n/a (`classifyCommand` test, no engine) | **accepted** — same; test passes unedited |
| 6 | test/unit/policy/quote-removal.test.ts | 418 | `the narrow review round's findings` > `%s is a search, not a carrier` | `find . -name perl -type f` | read-only | safe | n/a (`classifyCommand` test, no engine) | **accepted** — `-name`/`-type` both valueFlags; test passes unedited |
| 7 | test/unit/policy/quote-removal.test.ts | 419 | `the narrow review round's findings` > `%s is a search, not a carrier` | `find . -name node -newer /tmp/x` | read-only | safe | n/a (`classifyCommand` test, no engine) | **accepted** — `-newer` is a valueFlag, `/tmp/x` its value; test passes unedited |
| 8 | test/unit/policy/quote-removal.test.ts | 420 | `the narrow review round's findings` > `%s is a search, not a carrier` | `find . -type f -perm 644` | read-only | safe | n/a (`classifyCommand` test, no engine) | **accepted** — `-perm` is a valueFlag; test passes unedited |
| 9 | test/unit/policy/readonly-guarantee.test.ts | 43 | `a readOnly profile cannot write, whatever the command is called` > `still permits the reading it exists for` | `find /etc -name "*.conf"` | read-only | safe | allow → deny | **accepted** — decision reverts to `allow`; test passes unedited |
| 10 | test/unit/policy/readonly-guarantee.test.ts | 43 | `a readOnly profile cannot write, whatever the command is called` > `still permits the reading it exists for` | `journalctl -u sshd` | read-only | safe | allow → deny | **accepted** — decision reverts to `allow`; test passes unedited |
| 11 | test/unit/policy/readonly-guarantee.test.ts | 207 | `a reader that can be told to execute is not read-only` > `still allows the sorting a viewer actually does` | `sort -u /var/log/app.log` | read-only | safe | allow → deny | **accepted** — `-u` is a `sort` flag; decision reverts to `allow` |
| 12 | test/unit/policy/readonly-guarantee.test.ts | 207 | `a reader that can be told to execute is not read-only` > `still allows the sorting a viewer actually does` | `sort -k2 -n /etc/passwd` | read-only | safe | allow → deny | **accepted** — `-k`/`-n` are `sort` value/flag; decision reverts to `allow` |
| 13 | test/unit/policy/readonly-guarantee.test.ts | 208 | `a reader that can be told to execute is not read-only` > `still allows the sorting a viewer actually does` | `sort --reverse /tmp/x` | read-only | safe | allow → deny | **accepted** — `--reverse` is a `sort` flag; decision reverts to `allow` |
| 14 | test/unit/policy/readonly-guarantee.test.ts | 208 | `a reader that can be told to execute is not read-only` > `still allows the sorting a viewer actually does` | `sort /etc/hostname` | read-only | safe | allow → deny | **accepted** — bare operand, no `sort` operand limit; decision reverts to `allow` |
| 15 | test/unit/policy/readonly-guarantee.test.ts | 209 | `a reader that can be told to execute is not read-only` > `still allows the sorting a viewer actually does` | `sort /var/log/compress-stats.log` | read-only | safe | allow → deny | **accepted** — same; decision reverts to `allow` |
| 16 | test/unit/policy/readonly-guarantee.test.ts | 210 | `a reader that can be told to execute is not read-only` > `still allows the sorting a viewer actually does` | `sort --key=2 /tmp/compressed-sizes.txt` | read-only | safe | allow → deny | **accepted** — `--key=` attached value; decision reverts to `allow` |
| 17 | test/unit/policy/readonly-guarantee.test.ts | 239 | `a reader that can be told to execute is not read-only` > `does not treat an unrelated short-flag cluster as -o` | `sort -tofile /etc/passwd` | read-only | safe | allow → deny | **accepted** — `-t`'s value is `ofile` (attached), not `-o`; decision reverts to `allow` |
| 18 | test/unit/policy/readonly-guarantee.test.ts | 239 | `a reader that can be told to execute is not read-only` > `does not treat an unrelated short-flag cluster as -o` | `sort -t: -k2,2n /etc/passwd` | read-only | safe | allow → deny | **accepted** — two valueFlags; decision reverts to `allow` |
| 19 | test/unit/policy/readonly-guarantee.test.ts | 340 | `sort: the write CLASS, not four spellings of it` > `does not treat sort's own value-taking short flags as reaching -o in a cluster` | `sort -ko /tmp/k` | read-only | safe | allow → deny | **accepted** — `-k`'s value is `o` (attached); decision reverts to `allow` |
| 20 | test/unit/policy/readonly-guarantee.test.ts | 340 | `sort: the write CLASS, not four spellings of it` > `does not treat sort's own value-taking short flags as reaching -o in a cluster` | `sort -So /tmp/k` | read-only | safe | allow → deny | **accepted** — `-S`'s value is `o` (attached); decision reverts to `allow` |
| 21 | test/unit/policy/readonly-guarantee.test.ts | 340 | `sort: the write CLASS, not four spellings of it` > `does not treat sort's own value-taking short flags as reaching -o in a cluster` | `sort -To /tmp/k` | read-only | safe | allow → deny | **refusal accepted** — `-T` (temporary-directory) picks a write location a viewer has no use for; left out of the grammar on purpose. Test updated to expect `safe`/`deny`, split into its own assertion with a one-line reason |
| 22 | test/unit/policy/readonly-guarantee.test.ts | 349 | `sort: the write CLASS, not four spellings of it` > `does not treat an ambiguous long-option prefix as a write` | `sort --c=/tmp/payload.sh /tmp/k` | read-only | safe | allow → deny | **refusal accepted** — `--c` is genuinely ambiguous (`--check`/`--compress-program`); the grammar does not perform getopt_long's prefix resolution and refuses the word outright. Test updated to expect `safe`/`deny` |
| 23 | test/unit/policy/readonly-guarantee.test.ts | 350 | `sort: the write CLASS, not four spellings of it` > `does not treat an ambiguous long-option prefix as a write` | `sort --c /tmp/payload.sh /tmp/k` | read-only | safe | allow → deny | **refusal accepted** — same reason as #22. Test updated to expect `safe`/`deny` |
| 24 | test/unit/policy/readonly-guarantee.test.ts | 356 | `sort: the write CLASS, not four spellings of it` > `does not treat a word that merely starts the same letters as a match` | `sort --ox=/tmp/x /tmp/k` | read-only | safe | allow → deny | **refusal accepted** — `--ox` is not a prefix of any `sort` long option; unrecognised by the real binary too. Test updated to expect `safe`/`deny` |
| 25 | test/unit/policy/readonly-guarantee.test.ts | 357 | `sort: the write CLASS, not four spellings of it` > `does not treat a word that merely starts the same letters as a match` | `sort --cx=/tmp/x /tmp/k` | read-only | safe | allow → deny | **refusal accepted** — same reason as #24. Test updated to expect `safe`/`deny` |

## Excluded: one failure that is not a reader-with-arguments case

`test/unit/policy/carrier-completeness.test.ts:127`, test `the two questions
the read-only allowlist used to answer` > `makes every reader answer both
questions`, also now fails:

```
expect(entry, name).toEqual({ readOnly: true, operandsAreData: true });
```

This is not a reader-with-arguments classification change — no command
argument is involved. It fails because the test hard-codes the *exact*
two-key shape `READERS` entries had before this task, and this task's own
required change (`READERS` entries gain a third, required `grammar` field —
see task-1/task-2 briefs and the design doc's Data shape section) makes every
entry a three-key object, which no longer deep-equals the old two-key literal.
The test's own comment anticipated exactly this kind of guard ("A name cannot
be added for its class without stating whether its operands can hide a
command") but was written before `grammar` existed as a field to state. It
also asserts `Object.keys(READERS).length` — unaffected, still 68.

Per the task-2 brief this was reported as a concern rather than listed as
friction: it needed a decision (most likely, updating the test's literal shape
once Task 3 had settled what a finished `grammar` value looks like), not a
grammar/audit answer.

**Task 3 resolution:** rather than widening the literal to
`{ readOnly: true, operandsAreData: true, grammar: expect.anything() }` (which
would still assert nothing about `grammar`'s two boolean-shaped neighbours
beyond their presence), the test now checks `entry.readOnly` and
`entry.operandsAreData` individually against `true`, field by field, which is
what the test's own stated purpose ("asserts the VALUES, not just their
type") already called for and does not need to grow every time `READERS`
gains another field. The `grammar` field itself is covered by its own table
test in `test/unit/policy/proven-read.test.ts` ("every READERS entry has a
grammar"). The `Object.keys(READERS).length` assertion is untouched — still
68.
