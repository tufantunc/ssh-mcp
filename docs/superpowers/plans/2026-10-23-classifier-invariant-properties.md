# Classifier Invariant Properties Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pin the classifier's and policy engine's invariants as fast-check properties, so a variant that lowers a command's class fails `npm test` before release.

**Architecture:** Two property files under `test/property/`, sharing one module of generators and one seed helper. There are no source changes. Properties that fail on current `main` are withheld and reported privately, never committed.

**Tech Stack:** TypeScript, vitest 5, fast-check 4.

**Spec:** `docs/superpowers/specs/2026-10-23-classifier-invariant-properties-design.md`

## Global Constraints

- Tests only. No `src/` change and no changeset.
- **The seed is fixed by default.** `FC_SEED` overrides it for local runs only. CI never uses a random seed.
- **A property that fails on current `main`** is not committed, nor its generator, nor a hinting test name. Report it privately with the seed and the counterexample, and remove it from the spec's list (renumbering the rest, mentioning nothing) in the same PR.
- **A rule that is semantically wrong** may be narrowed only by a *named exclusion in the generator*, with a comment giving a one-line shell example and the reason. Each narrowing is listed in the PR body. If in doubt, treat it as a gap.
- `numRuns`: 1000 per classifier property and 200 per engine property. A property may drop to no less than 200, with the reason in its comment.
- Generated commands are ≤ ~200 characters, ≤ 4 segments, and nested at most 2 deep. The exception is the dedicated never-throws deep-nesting case, which runs a small `numRuns`.
- No wall-clock assertions.
- Nothing is pushed until Task 4's private sweep has finished.

## Review Focus

1. **Generators that never reach the interesting space.** A property can pass while asserting nothing. Each generator has a sanity test asserting that its outputs include at least one `privileged`, `destructive` and `read-only` result over a fixed sample. Owner: Task 1.
2. **A seed that moves silently.** The helper must use the constant when `FC_SEED` is unset or empty, and reject a non-integer `FC_SEED` loudly. Owner: Task 1.
3. **Timeout on macOS CI.** The whole suite has to fit vitest's default 5 s per-test timeout. Task 4 measures every property and sets an explicit `timeout` on any `it` over 2 s locally.
4. **Composition generator producing unclosed parts.** That makes a false "lowered" failure. The generator closes quotes and substitutions by construction, and a sanity test checks the balance. Owner: Task 1.
5. **An engine property passing because the profile is denied everything.** Each engine property asserts that its sample contains at least one `allow` decision. Owner: Task 3.

---

### Task 0: Branch for this PR

**Files:** none (git only)

- [ ] **Step 1:** In the worktree, create the PR branch from `origin/main`. **Do not bring the spec or plan over yet.** They list every invariant, and a later "withhold and renumber" commit would leave the original list in pushed history. They are added in Task 4, after the private sweep, in their final form.

```bash
git fetch origin
git switch -c test/classifier-invariant-properties origin/main
```

**Never push the worktree's original branch** (`worktree-config-reload-and-classifier-invariants`). It carries the full first draft of both specs.

- [ ] **Step 2:** `npm ci`, then run `npm run test:unit`. Expected: green baseline. Record the wall time.

### Task 1: Shared generators and seed helper

**Files:**
- Create: `test/property/fc-seed.ts`
- Create: `test/property/command-arbitraries.ts`
- Test: `test/property/command-arbitraries.property.test.ts`

**Interfaces:**
- Produces:
  - `fcParams(numRuns: number): fc.Parameters<unknown>`: returns `{ numRuns, seed }`.
  - `FC_DEFAULT_SEED = 20261023`.
  - `CLASS_RANK: Record<CommandClass, number>`: a literal `{ 'read-only': 0, safe: 1, destructive: 2, privileged: 3 }`.
  - `atLeast(a: CommandClass, b: CommandClass): boolean`.
  - Arbitraries, each a `fc.Arbitrary<string>`:
    - `simpleCommand`: one segment, lexically closed;
    - `closedCommand`: up to 2 nesting levels, closed;
    - `separator`: `;`, `&&`, `||`, `|` or `\n`;
    - `privilegePrefix`: the 11 names from `PRIVILEGE_PREFIXES`, copied as a literal;
    - `operandFreeWrapper`: `nohup`, `command`, `exec`, `setsid`, `time`, `env A=1`, `nice -5`;
    - `quotableWord`: a word with no glob character, whitespace, separator, `$`, backtick, backslash or `=`, and no leading `~`;
    - `anyString`: unconstrained, up to 200 characters.

- [ ] **Step 1: Write the failing sanity tests**

Each test samples 300 values from an arbitrary with `fc.sample(arb, { numRuns: 300, seed: FC_DEFAULT_SEED })` and asserts:
- `fcParams` uses `FC_DEFAULT_SEED` when `process.env.FC_SEED` is unset or `''`, uses the integer when it is set, and throws on `'abc'`;
- `closedCommand`: every sample has an even count of unescaped `'` and `"`, and balanced `$(`/`)`;
- the classes of `closedCommand` samples (via `classifyCommand`) include `read-only`, `safe`, `destructive` and `privileged`;
- every `quotableWord` sample fails `/[*?\[\]\s;&|<>`$\\=]|^~/`.

- [ ] **Step 2:** `npx vitest --run test/property/command-arbitraries.property.test.ts`. Expected: FAIL (the modules do not exist).

- [ ] **Step 3: Implement the two modules**

Build the arbitraries from weighted `fc.oneof` over fragment vocabularies (readers like `ls`/`cat`/`grep`, interpreters, `find`, `rm`, paths, flags), in the style of `test/property/sanitizer.property.test.ts`. Close quotes and substitutions by construction, never by filtering. Each arbitrary gets a JSDoc saying why it is shaped that way.

- [ ] **Step 4:** Run the same test. Expected: PASS.

- [ ] **Step 5:** Commit, with the message `test: generators and seed helper for classifier properties`.

### Task 2: Classifier properties (invariants 1–9)

**Files:**
- Create: `test/property/classifier.property.test.ts`

**Interfaces:**
- Consumes: Task 1's exports, `classifyCommand` and `findForbiddenMatch` from `src/policy/classifier.ts`.

- [ ] **Step 1: Write the properties**, one `it` each, using `fc.assert(fc.property(...), fcParams(1000))`:
  1. **Never throws.** For any string from `anyString`, `classifyCommand(s).class` is one of the four classes. A second `it` covers deeply nested `$( … )`, 50 deep, with `fcParams(200)`.
  2. **Deterministic.** Classifying `c` twice gives the same `.class`, for `closedCommand`.
  3. **Privilege prefix.** For `p` from `privilegePrefix` and `c` from `simpleCommand` or `''`, ``classifyCommand(`${p} ${c}`.trim()).class === 'privileged'``.
  4. **Composition never lowers.** For `a` and `c` from `closedCommand` and `s` from `separator`, the class of `` `${a} ${s} ${c}` `` is at least the class of `a` and at least the class of `c`.
  5. **Wrappers never lower.** For `w` from `operandFreeWrapper` and `c` from `simpleCommand`, the class of `` `${w} ${c}` `` is at least the class of `c`.
  6. **Neutral variants never lower.** Leading/trailing whitespace, a tab between words, and single or double quoting of one `quotableWord` inside `c`: each variant's class is at least the class of `c`.
  7. **Never-allowed implies destructive.** When `findForbiddenMatch(c) !== null`, the class of `c` is at least `destructive`. Add a fragment vocabulary of never-allowed shapes to `closedCommand`'s weights, so hits are not rare. Assert that ≥ 1% of samples hit.
  8. **Read-only implies no metacharacter.** When the class is `read-only`, `!/[;&|<>`$(){}\n\r]/.test(c)`.
  9. **A read-only rejection implies safe.** When `readOnlyRejection` is set, the class is `safe`.

- [ ] **Step 2:** `npx vitest --run test/property/classifier.property.test.ts`. Expected: PASS. **If any property fails,** stop: do not commit it. Follow the Global Constraints, then continue with the rest.

- [ ] **Step 3: Mutation check.** Locally only; revert each mutation before the next:
  - delete `'sudo'` from `PRIVILEGE_PREFIXES` → invariant 3 must fail;
  - make `classifyCommandInDialect` skip its `Math.max`/rank raise over nested commands → invariant 4 must fail (or 1/2 still pass and 4 fails);
  - make `isDestructive` return `false` → invariant 7 must fail.
  
  Note each result for the PR body. Confirm `git diff src/` is empty afterwards.

- [ ] **Step 4:** Commit, with the message `test: classifier invariants as properties`.

### Task 3: Engine properties (invariants 10–13)

**Files:**
- Create: `test/property/policy-engine.property.test.ts`

**Interfaces:**
- Consumes:
  - Task 1's exports;
  - `PolicyEngine` and `DEFAULT_RULES` from `src/policy/engine.ts`;
  - a local `makeProfile(overrides)` copied from `test/unit/policy/engine.test.ts`.

The engine is built once per file. Profiles come from `fc.record` over:
- role: `admin` | `operator` | `viewer`
- group: `prod` | `staging` | `dev`
- approvalPolicy: `auto` | `ask-destructive` | `ask-all` | `deny`
- readOnly: `true` | `false`

- [ ] **Step 1: Write the properties**, using `fcParams(200)`:
  10. **readOnly is a ceiling.** With `readOnly: true`, every decision that is not `deny` has `commandClass === 'read-only'`.
  11. **Never-allowed ignores role.**
      - Commands: when `findForbiddenMatch(c) !== null`, `decision === 'deny'` for every profile.
      - Write paths: a second `it` evaluates `'sftp:upload <path>'` with `{ remotePath, remoteWrite: true }`, where the path is drawn from never-allowed families (`/etc/cron.d/x`, `/etc/systemd/system/x.service`, `/home/u/.ssh/authorized_keys`, and `//` or `/./` spellings of them). The decision is `deny` for every profile. Check the exact SFTP command string the tools compose in `src/tools/transfer-tools.ts` and use that form.
  12. **Approval-policy shape.**
      - With `auto` or `deny`, the decision is never `require-approval`.
      - With `ask-all`, it is never `allow`.
  13. **Monotone in class.** For a fixed profile and two commands, neither of which `findForbiddenMatch` matches: if the first one's class ranks higher, its decision is not more permissive (`allow` 2 > `require-approval` 1 > `deny` 0).

  Each `it` also asserts that its sample contained at least one `allow` (Review Focus 5). Count over the run, then assert after `fc.assert`.

- [ ] **Step 2:** `npx vitest --run test/property/policy-engine.property.test.ts`. Expected: PASS. A failure follows the Global Constraints.

- [ ] **Step 3:** Commit, with the message `test: policy engine invariants as properties`.

### Task 4: Private sweep, timing, PR

**Files:** Modify only if a property is withheld:
- `docs/superpowers/specs/2026-10-23-classifier-invariant-properties-design.md`: remove it and renumber.
- the plan: same.

- [ ] **Step 1: Private seed sweep.** Run this locally. Nothing from it is committed or pasted anywhere public.

```bash
for s in $(seq 1 25); do FC_SEED=$RANDOM$s npx vitest --run test/property/ >/tmp/fc-sweep-$s.log 2>&1 || echo "seed run $s FAILED"; done
```

Expected: no FAILED line. Any failure follows the Global Constraints: report privately and withhold that property. Delete `/tmp/fc-sweep-*.log` afterwards.

- [ ] **Step 2: Timing.** Run `npx vitest --run test/property/ --reporter=verbose`. Record each property's time. Lower `numRuns` (≥ 200, with a comment) or set an explicit `it` timeout wherever needed, so that no `it` exceeds 2 s locally. Run `npm run test:unit` and record the added wall time compared with Task 0.

- [ ] **Step 3:** Run `npm run typecheck` and `npm run test:unit`. Expected: both green.

- [ ] **Step 3b: Add the docs in their final form.** Copy the spec and this plan from the worktree branch. If a property was withheld, first remove it from both lists and renumber, without mentioning it. Commit them in one commit (`docs: design and plan for classifier invariant properties`). Check with `git log -p` on this branch that no earlier commit in it contains a withheld invariant.

- [ ] **Step 4: Review.** Run the `review-pro` skill on the branch. Fix confirmed findings, then re-run Step 3.

- [ ] **Step 5: Push and open the PR.**
  - Title: `test: classifier and policy invariants as property tests`.
  - Body:
    - what each property pins;
    - the mutation results;
    - the narrowings, if any;
    - the timing;
    - "tests only, no changeset".
  - The body says nothing about withheld properties.
