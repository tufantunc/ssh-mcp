# Proven Read Implementation Plan (task skeleton)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **This plan is a skeleton.** Each task names its files, interfaces, test
> targets and acceptance criteria. The spec is the single source for measured
> forms and exact values, and tasks point at its sections instead of restating
> them.

**Goal:** Grant `read-only` only when every argument of a reader is proven to be
data under a declared grammar. Anything unproven falls to `safe`.

**Architecture:** A new pure matcher (`src/policy/reader-grammar.ts`), a
required `grammar` field on every `READERS` entry, one check in
`classifyOuter`'s allowlist branch, and a refusal message that names the
rejected word. `DISQUALIFYING_ARGS` and the escalation checks are untouched and
still run first.

**Tech Stack:** TypeScript, vitest, fast-check (already a dev dependency).

**Spec:** `docs/superpowers/specs/2026-09-25-proven-read-design.md`

## Global Constraints

- Work only in `/Users/tufantunc/Desktop/Projects/Personal/ssh-mcp-ghsa-mwmj-jr2h-q546`, branch `advisory-fix-1`. Nothing reaches the public repository before GHSA-mwmj-jr2h-q546 is published.
- The change may only move a class from `read-only` to `safe`. No other class may change, in either direction.
- `DISQUALIFYING_ARGS`, `operandsAreData`, the carrier scan and `READ_ONLY_SYNTHETIC` keep their current behaviour.
- A test is accepted only after its production line has been deleted and the test has been measured failing.
- Engine-level tests assert class **and** decision together.
- Cost assertions use growth ratios, not wall clock.
- Release is a **minor** changeset.
- Commands: `npm run typecheck`, `npm run test:unit`, `npm run lint`, and `COMPOSE_PROJECT_NAME=ssh-mcp npm run test:integration` for the integration suite. Read the suite-level summary, not only the `Tests` line.

## Review Focus

1. **Existing tests rewritten to go green.** Many current tests expect `read-only` for a reader with arguments. Every such expectation that changes must be a recorded decision: either widen the grammar or accept the refusal with a reason. It must never be a silent edit.
2. **Two-word entries.** The grammar must start at `words[2]` for `git log`, `ip route`, `docker ps` and `systemctl status`, never at `words[1]`.
3. **Correctness condition 1 (spec § Correctness conditions).** A word the matcher consumes as a value must be one the binary also consumes as a value. No optional-argument option may appear in `valueFlags`.
4. **Quoted and escaped words.** A quoted option reaches the grammar dequoted, and must be judged exactly like its unquoted spelling.
5. **Both refusal paths name the word.** That covers the engine's role-binding denial and `read-command`'s `enforceClass` refusal.

---

### Task 1: The matcher

**Files:**
- Create: `src/policy/reader-grammar.ts`
- Test: `test/unit/policy/reader-grammar.test.ts`

**Interfaces:**
- Produces: `export type ArgGrammar` (exact shape from spec § Data shape).
- Produces: `export function matchesGrammar(words: readonly string[], grammar: ArgGrammar): { ok: true } | { ok: false; word: string }`. The failing word feeds Task 5. `ok: true` for `'any'`.

- [ ] Write failing tests for every rule in spec § The matcher:
  - `'any'`
  - `--` terminator, lone `-`
  - getopt cluster with flag and value-flag characters, and an unknown character in a cluster
  - attached and separate short values
  - exact long options, `--name=value` only for value flags
  - an abbreviated long option refused
  - `exact` style refusing clusters
  - `operands.max`, `operands.first`, `operands.each`
  - a value flag at the end of the words with no value → refused
- [ ] Run and confirm they fail.
- [ ] Implement. The module imports nothing from `classifier.ts`.
- [ ] Run, confirm they pass, then mutate each branch and confirm a test fails.
- [ ] Commit: `feat(policy): argument grammar matcher for readers`

### Task 2: Wire the grammar into the classifier, fail-closed

**Files:**
- Modify: `src/policy/classifier.ts` (`READERS` type and entries, `classifyOuter` allowlist branch)
- Test: `test/unit/policy/proven-read.test.ts` (new)

**Interfaces:**
- Consumes: `ArgGrammar`, `matchesGrammar` from Task 1.
- Produces: `READERS` entries typed `{ readOnly: boolean; operandsAreData: boolean; grammar: ArgGrammar }`. `grammar` is required.
- Produces: `classifyOuter` returns `safe` when the reader's grammar rejects. The rejected word is kept on the returned value for Task 5 (internal field, not yet exported on `ParsedCommand`).

- [ ] Write the table test: every `READERS` entry has a grammar, and every `'any'` entry has a non-empty `audit`.
- [ ] Set grammars:
  - entries on the spec's *'any' candidates* list: `'any'` with an `audit` string marked for confirmation in Task 3;
  - entries on the *grammar needed* list: `{ args: 'getopt' }` or `{ args: 'exact' }` with **no** flags or operands. This is the B rule, "no arguments", so the branch is fail-closed from its first commit.
- [ ] Add the grammar check after the `SHELL_CONTROL_CHARS` check, applying the two-word offset.
- [ ] Run `npm run test:unit`. Record **every** existing assertion that now fails, with file, line and command, in `docs/superpowers/plans/2026-09-25-proven-read-friction.md`. Do not edit those tests in this task, and do not mark them `it.fails` or skip them. The suite stays red for exactly the listed items and nothing else. State the count in the commit body.
- [ ] Commit: `feat(policy): read-only requires a declared argument grammar`

> Ruling: Task 2 lands a knowingly red suite limited to the listed friction items, because Task 3 is where each one gets decided. If the executor prefers a green checkpoint, Tasks 2 and 3 can be merged into one review unit. Record which way was taken in the ledger.

### Task 3: The audit, and the grammars for mode-bearing readers

**Files:**
- Modify: `src/policy/classifier.ts` (`READERS` grammars and audit strings)
- Modify: tests listed in the friction file (each change justified in the file)
- Modify: `docs/superpowers/plans/2026-09-25-proven-read-friction.md` (a decision per row)

**Interfaces:**
- Consumes: the Task 2 table and friction list.
- Produces: final grammars for every entry on the spec's *grammar needed* list, and confirmed or corrected `audit` strings for every `'any'` entry.

- [ ] For each `'any'` candidate, confirm the claim against the implementations the name resolves to (GNU, busybox, BSD/macOS; the test containers and the local Mac are available) and write the `audit` string. Any candidate that turns out to have a write or exec mode moves to the grammar list.
- [ ] Settle the spec's open audit questions in writing: `git status` index refresh, `top`/`htop` non-interactive modes, `ss` and `file` (measured, or recorded as documented-only).
- [ ] For each mode-bearing entry, write the grammar from the options that only read on every implementation, following both authoring rules in spec § Correctness conditions. Each entry gets a source comment.
- [ ] Walk the friction file. For each row, either the grammar now accepts the command (it only reads), or the refusal is accepted and the test is updated with a one-line reason.
- [ ] Add the spec's friction corpus (spec § Testing, item 3) to `proven-read.test.ts` as `read-only` expectations.
- [ ] Run the unit suite green, and mutate one grammar line per entry to confirm a test notices.
- [ ] Commit: `fix(policy): grammars for readers with a write mode`

### Task 4: Windows switch operands

**Files:**
- Modify: `src/policy/classifier.ts` (`sort` and `arp` grammars)
- Test: `test/unit/policy/proven-read.test.ts`

**Interfaces:**
- Consumes: Task 3 grammars for `sort` and `arp`.
- Produces: the `operands.each` rule from spec § Windows on exactly those two entries.

- [ ] Write failing tests: the spec's Windows forms fall to `safe`; a POSIX path with a second `/` still passes; `find /var -name x` is unaffected.
- [ ] Add the rule to the two entries, and record in their source comments that it comes from a Windows measurement (build 26200).
- [ ] Re-confirm the spec's Windows `sort` measurement on the VM with the current build synced (see memory: Windows test VM). Do not run any state-changing `arp` form.
- [ ] Commit: `fix(policy): refuse Windows switch operands on sort and arp`

### Task 5: The refusal names the word

**Files:**
- Modify: `src/types.ts` (`ParsedCommand`, `PolicyEvaluation`)
- Modify: `src/policy/classifier.ts` (`classifyCommand` carries the rejection when the final class is the outer `safe`)
- Modify: `src/policy/engine.ts` (`evaluate`, `explainRoleDenial`)
- Modify: `src/tools/pipeline.ts` (`enforceClass` refusal)
- Test: `test/unit/policy/proven-read.test.ts`, plus the existing pipeline or tool test file that covers `read-command`

**Interfaces:**
- Produces: `ParsedCommand.readOnlyRejection?: { binary: string; word: string }`.
- Produces: `PolicyEvaluation.readOnlyRejection?: { binary: string; word: string }`, copied from the parse.
- Message text, verbatim from the spec: `` `<binary>` is read-only only with the options its grammar lists; `<word>` is not one of them. ``

- [ ] Write failing tests:
  - `readOnly` profile denial reason contains the binary and the word;
  - `viewer`/prod denial reason, same;
  - `read-command` `enforceClass` refusal, same;
  - no rejection field when a nested command raised the class above `safe`;
  - no rejection field when the command is simply not a reader.
- [ ] Implement. `explainRoleDenial` takes the parsed command, not only its class.
- [ ] Confirm the OPA input shape is unchanged, or extend it deliberately and say so in the changeset.
- [ ] Commit: `feat(policy): say which word cost a reader its read-only class`

### Task 6: Measured forms through the engine

**Files:**
- Test: `test/unit/policy/proven-read.test.ts`

- [ ] For every row of both tables in spec § Measured, assert `safe` + deny for a `readOnly` profile and for `viewer`/prod, class and decision together.
- [ ] Confirm each test fails on the base commit (`a297c73`) by running it against a checkout of that commit, and passes on the branch.
- [ ] Commit: `test(policy): the advisory's forms, driven through the engine`

### Task 7: Differential verification (not committed as a test)

> Ruling: the spec lists the differential fuzz under Testing, but the base classifier cannot be imported from the branch. It runs as a verification step instead, from the scratchpad, against a build of `a297c73` in a separate worktree. What costs if wrong: nothing ships untested, since the invariant is still checked. The committed suite simply does not re-check it on every run.

- [ ] Build `a297c73` and the branch head into separate directories.
- [ ] Generate reader-led inputs with fast-check (every `READERS` name, random option and operand words, quoting) plus the existing classifier test corpora.
- [ ] Assert the invariant from Global Constraints over at least 200k cases. Record the counts (unchanged, `read-only` → `safe`, anything else) in the ledger. Any "anything else" row is a stop.

### Task 8: Docs, residuals, changeset

**Files:**
- Modify: `SECURITY.md` (UNC residual next to the DNS/ICMP egress note; the proven-read contract)
- Modify: `README.md` (what `readOnly` and `viewer` now guarantee, and how a refusal names the word)
- Create: `.changeset/<name>.md` (minor)

- [ ] The changeset says which spellings now fall to `safe` (by category, pointing at the refusal message), and that the class of no other command changed.
- [ ] Every factual claim in the docs traces to a test or a measurement recorded in this branch.
- [ ] Commit: `docs: proven-read contract, residuals, changeset`

### Final verification

- [ ] `npm run typecheck`, `npm run lint`, `npm run test:unit`, and the integration suite with `COMPOSE_PROJECT_NAME=ssh-mcp`, all green, read at suite level.
- [ ] Whole-branch review.
- [ ] Before publication (maintainer): update the advisory's table with the spec's second table, then merge, release, fill `patched_versions` and publish.
