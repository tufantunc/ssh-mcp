# Classifier invariants as property tests

**Status:** design approved in chat (questions answered by the maintainer's delegate).
**Work happens in:** worktree `config-reload-and-classifier-invariants`; this piece ships as
its own PR, opened before the config-reload PR (`2026-10-23-config-reload-design.md`).
**Release:** none. Tests only, so no changeset.

## Why

Every policy advisory this year had the same shape: a spelling or a composition of a
command that should be `privileged` or `destructive` classified lower, usually `safe`, the
one class that runs with no approval prompt. Each was fixed with example-based tests that
pin the spellings the report and the review round found. Nothing states the rules those
examples are instances of, so the next variant is found by a reporter rather than by the
suite.

This change writes the rules down as fast-check properties over `classifyCommand`
(`src/policy/classifier.ts`) and `PolicyEngine.evaluate` (`src/policy/engine.ts`), so that
a regression, or a new variant of an old class, fails `npm test` before it ships.

## Goals

- Properties for the invariants the classifier and engine already promise, each generated
  over structured inputs rather than plain random strings: plain `fc.string()` almost never
  produces a shell-meaningful command (the same reasoning as
  `test/property/sanitizer.property.test.ts`).
- Fast enough for every CI run, on every OS job, including the macOS runner.
- Failures that are reproducible from the CI log.

## Non-goals

- No classifier or engine changes. If a property shows the code is wrong, that is a
  finding, handled as below, not something this PR fixes.
- No wiring of the differential corpus (`test/differential/`) into CI. It has its own
  CI-time cost and is a separate decision.
- No wall-clock or CPU-time assertions; the cost tests in `test/unit/policy/` own that.

## Anti-goals

- A property that is weakened (a narrowed generator, an added exception) until it passes,
  without saying so in its comment. An exception the classifier documents (for example the
  interactive-session limit in `SECURITY.md`) is stated in the property's comment, with
  the reason.
- **Committing a property that fails on current `main`.** See "When a property fails".

## When a property fails on current `main`

A failing property here is a candidate vulnerability, not a test bug.

1. Stop. Do not commit the property, its generator, or a test name that hints at it.
2. Report it privately to the maintainer with the failing counterexample and the fast-check
   seed, so it can go through the private advisory process.
3. Ship only the properties that pass today. The failing one returns later with its fix.

Nothing in the PR body, commit messages or this document describes such a gap. This
document lists exactly the properties that ship. A withheld invariant is removed from the
list below in the same PR, the rest renumbered, and nothing mentions it, so that "the
design minus the test file" reveals nothing. For the same reason this document is not
pushed anywhere public until the private random-seed runs (see "Budget and
reproducibility") have finished.

**When the rule itself is wrong.** A property can fail because the rule as written here is
semantically wrong, not because the code is. One example: a word whose meaning really does
change when it is quoted. Such a property may be narrowed, under three conditions:

- The narrowing is a **named exclusion in the generator**, never a weakened assertion.
- Its comment cites the concrete shell behaviour: a one-line example input, and why the
  lower class is correct.
- Each narrowing is listed in the PR body. It is a statement about shell semantics, not
  about a gap, so it is safe to make public.

Any doubt whether it is semantics or a gap means it is a gap: stop, no commit, report it
privately with the seed and the counterexample.

## The invariants

`CLASS_RANK` is not exported. The test keeps its own copy, written as a literal and checked
against the `CommandClass` union. This is the house style: the contract is a literal in the
test, not something imported from the code under test.

### Classifier (`classifyCommand`)

1. **Never throws** on any input, including arbitrary strings, unbalanced quotes and
   substitutions, control characters and very deep nesting. It always returns a valid
   `CommandClass`.
2. **Deterministic.** Classifying the same string twice gives the same class.
3. **Privilege prefix.** Every member of the privilege-prefix set, followed by any command
   or by nothing, classifies `privileged`. The set is written as a literal in the test.
4. **Composition never lowers.** For commands `A` and `C` joined by `;`, `&&`, `||`, `|` or
   newline, the class of the whole is at least the class of each part. Generators keep each
   part lexically closed: balanced quotes, no trailing escape, balanced substitutions. The
   synthetic `sftp:`/`session:` words are kept out.
5. **Wrappers never lower.** Prefixing a command with an exec wrapper that takes no operand
   (for example `nohup`, `command`, `env` with only assignments, `nice` with a numeric
   flag) gives a class at least that of the bare command.
6. **Neutral variants never lower.** Leading or trailing whitespace, a tab instead of a
   space between words, and quoting a word whose quoted text contains no glob character,
   whitespace, separator, `$`, backtick or backslash all give a class at least that of the
   plain form. Some quotings are excluded on purpose, because quoting them really does
   change what the shell runs:
   - a glob, which legitimately turns a reader `read-only`;
   - a word shaped like an assignment (`NAME=value`), which stops being an assignment
     when quoted;
   - a leading `~`, which is no longer expanded when quoted.
7. **Never-allowed implies destructive.** A command the never-allowed list matches
   classifies at least `destructive`. "Matches" means `findForbiddenMatch`, which reads
   both the POSIX and the cmd.exe reading of a command containing a backslash, as the
   engine does. The property is not limited to the POSIX default of `isForbidden`.
8. **Read-only implies no metacharacter.** A command that classifies `read-only` contains
   none of the classifier's own shell control characters. The test copies
   `SHELL_CONTROL_CHARS` (`classifier.ts`) as a literal. This pins the
   documented refusal, not a general theory of shell-special characters: a reader whose
   grammar accepts any argument may legitimately take a quoted glob.
9. **A read-only rejection implies safe.** When `readOnlyRejection` is set, the class is
   `safe`.

### Engine (`PolicyEngine.evaluate`, default rules)

10. **readOnly is a ceiling.** For a `readOnly` profile, every decision other than `deny`
    has `commandClass === 'read-only'`.
11. **Never-allowed ignores role.** A command the never-allowed list matches (by
    `findForbiddenMatch`, both readings, as in 7) is `deny` for every role, host group
    and approval policy. A second property does the same for the never-allowed **write
    paths**, given as a `PolicyResource` (`remoteWrite` / `remotePath`) on an SFTP write.
12. **Approval-policy shape.** `auto` and `deny` never return `require-approval`, and
    `ask-all` never returns `allow`.
13. **Monotone in class for the default bindings.** For a fixed profile and commands
    that the never-allowed list does **not** match, a command of a higher class never
    gets a more permissive decision than a command of a lower class (`allow` >
    `require-approval` > `deny`). The never-allowed check runs before class is
    considered, so a forbidden command is denied whatever its class.

The builder may add properties in the same families. Each needs a comment saying what it
pins and why its generator is shaped the way it is.

## Generators

- Built from parts, like the sanitizer suite: weighted `fc.oneof` over fragments the
  classifier cares about (reader binaries, wrappers, privilege prefixes, interpreters,
  separators, quotes, substitutions, paths) plus short free strings.
- Caps: a command of at most ~200 characters, at most 4 combined segments, and nesting
  depth of at most 2, except in a dedicated "never throws" property that also covers deep
  nesting at a small `numRuns`.
- No long runs of unbalanced openers. Those are a cost hazard, not a correctness check.

## Budget and reproducibility

- `numRuns`: 1000 per classifier property and 200 per engine property. Build the
  `PolicyEngine` once outside the property, not per case.
  - If a measurement shows a property costing well over a few seconds, its `numRuns` may
    come down to no less than 200. The comment says why.
  - The suite must fit vitest's per-test timeout on the slowest CI runner (macOS).
- **The seed is fixed in CI and in a plain `npm test`.** A random seed in public CI could
  one day find a real gap and print its counterexample in a public log and a red public
  check, which would be disclosure. So:
  - the default is a constant seed;
  - `FC_SEED` overrides it for a local run;
  - exploring new seeds happens only privately: locally, or in a private fork.
  
  fast-check's failure output (seed and path) is left intact, so a failure can be replayed.
- The suite runs under `npm run test:unit`, which already includes `test/property/`. On a
  developer machine it should add a few seconds at most. The builder measures this and
  states it in the PR.
- Before opening the PR, the builder runs the suite privately over a number of random
  seeds, at least 20, and treats any failure under "When a property fails".

## Files

- New: `test/property/classifier.property.test.ts` and
  `test/property/policy-engine.property.test.ts`, or one file if the builder prefers. They
  follow the existing `test/property/*.property.test.ts` conventions: vitest
  `describe`/`it`, `import fc from 'fast-check'`, explicit `numRuns`, and a JSDoc comment
  per generator.
- No source changes.

## Left to the builder

- The exact fragment vocabularies, weights and shrinking-friendly structure.
- Whether invariants 4–6 share one generator.
- How to express "at least" (a rank helper in the test).
- Mutation checks: for at least invariants 3, 4 and 7, temporarily break the corresponding
  code path locally and confirm the property fails, then restore. Record which mutations
  were tried in the PR body; do not commit the mutations.
