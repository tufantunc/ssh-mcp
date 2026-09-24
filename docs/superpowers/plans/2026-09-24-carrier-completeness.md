# Carrier Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a binary the classifier does not recognise from laundering an elevated or dangerous command into the `safe` class.

**Architecture:** Three changes to `src/policy/classifier.ts`. (A) Elevation detection gains the unanchored, whole-text form the destructive scan already has, so a carrier nobody listed cannot hide `sudo`. (B) The one Set that answers two questions is split so the carrier-scan exemption has its own name. (C) The interpreter table gains the measured names, its `flags` field is renamed to describe what it holds, and `-EncodedCommand` is decoded so what it carries is classified rather than merely counted.

**Tech Stack:** TypeScript, vitest, changesets. No new dependencies — base64 and UTF-16LE decoding are `Buffer`.

**Spec:** `docs/superpowers/specs/2026-09-24-carrier-completeness-design.md`

## Global Constraints

- **All work happens in this repository** — `tufantunc/ssh-mcp-ghsa-qmx6-47vm-3vf7`, the temporary private fork for GHSA-qmx6-47vm-3vf7. Nothing may be pushed to `tufantunc/ssh-mcp` before the advisory is published.
- **Branch:** continue on `fix/sort-compress-program`, which already carries the separate `sort --compress-program` fix and the spec. Do not open a second branch; the two ship together.
- **Every test is accepted only after its production line is deleted and the test is measured failing.** Record the mutation and its result in the commit message. Six tests in this repo's recent history passed for the wrong reason and none was caught by reading.
- **Assert class and decision together** whenever a test drives the policy engine. On `operator`/`prod` both `destructive` and `privileged` deny, so the decision alone cannot say which mechanism fired.
- **Changeset: `minor`.** Classification results change; a command that ran silently can now prompt. The 2.9.0 awk security fix set this precedent.
- **Run `npm run build` before any `node -e` probe against `build/`** — the probes read compiled output, not source.

## Decision recorded

The spec specified two Sets with identical membership. The maintainer chose one
table with two answers instead, and Task 2 is written to that:

```ts
const READERS: Record<string, { readOnly: boolean; operandsAreData: boolean }>
```

Two literals holding the same 68 names can be copy-pasted and can drift in the
direction nobody notices. One table forces both decisions at the point of adding
a name, which is what the spec wanted the naming to achieve, and leaves one list
to keep true.

## Review Focus

Five input classes the spec implies that no task's happy path exercises, most likely to bite first:

1. **A word that merely contains an elevation name.** `/home/su/notes`, `sudoku.txt`, `/etc/subuid`, `/var/su-backup`. An unanchored `\bsu\b` matches `/su/` because slashes are non-word characters. Today all of these are `read-only`. Test added to Task 1.
2. **A path-prefixed or quoted carrier.** `/usr/bin/osascript -e …`, `"osascript" -e …`. `stripPath`/`unquote` exist for this and the new entries must go through them like the old ones. Test added to Task 3.
3. **Base64 that is well-formed but decodes to nothing useful.** `Buffer.from(x, 'base64')` never throws — it silently drops invalid characters — so the failure mode is a wrong answer, not an exception. Test added to Task 3.
4. **A very large `-EncodedCommand` operand.** Decoding is attacker-controlled work performed before the policy decision. Test added to Task 3.
5. **Elevation reached only through a substitution inside an unknown carrier.** `osascript -e "$(printf 'sudo id')"`. `nestedCommands` already pulls substitutions out; this pins that A and the existing scan compose rather than one shadowing the other. Test added to Task 1.

---

### Task 1: Elevation detection stops depending on position

**Files:**
- Modify: `src/policy/classifier.ts` — add `carriesElevation()` next to `isDestructive()` (around line 869), call it from `classifyOuter()` (around line 1267)
- Test: `test/unit/policy/carrier-completeness.test.ts` (create)

**Interfaces:**
- Consumes: `matchesEitherForm(command, test)` (line 399), `operandsAreData(words)` (line 941), `tokenizeSegmentsDetailed(command)` returning `{ words: string[]; sep: string }[]`
- Produces: `carriesElevation(command: string): boolean` — used by nothing else; Task 3 relies on `classifyOuter` returning `privileged` for a decoded payload that elevates.

- [ ] **Step 1: Write the failing test**

Create `test/unit/policy/carrier-completeness.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { classifyCommand } from '../../../src/policy/classifier.js';
import type { Profile } from '../../../src/types.js';

/**
 * GHSA-qmx6-47vm-3vf7: a binary the classifier does not recognise laundered an
 * elevated command into `safe`, the class that raises no prompt and is granted to
 * operator and admin on every tier.
 *
 * Driven through the engine, not `classifyCommand` alone: what was wrong is what
 * the engine then permitted. Class is asserted alongside the decision because on
 * this profile every class above `safe` denies identically, so the decision cannot
 * say which mechanism fired.
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

describe('elevation is found wherever a shell would act on it', () => {
  it.each([
    ['osascript', `osascript -e 'do shell script "sudo id"'`],
    ['lua', `lua -e 'os.execute("sudo id")'`],
    ['Rscript', `Rscript -e 'system("sudo id")'`],
    ['bun', `bun -e 'require("child_process").execSync("sudo id")'`],
    ['tclsh', `tclsh -c 'exec sudo id'`],
    ['an unknown binary', `whatever-tool -e 'sudo id'`],
  ])('refuses elevation carried by %s', (_label, command) => {
    expect(decide(command).commandClass, command).toBe('privileged');
    expect(decide(command).decision, command).toBe('deny');
  });

  it('finds elevation reached only through a substitution inside an unknown carrier', () => {
    // nestedCommands already pulls `$(...)` out. This pins that the new scan and
    // the existing one compose rather than one shadowing the other.
    const command = `whatever-tool -e "$(printf 'sudo id')"`;
    expect(decide(command).commandClass).toBe('privileged');
  });

  it('leaves a word that merely contains an elevation name alone', () => {
    // An unanchored \bsu\b matches `/su/` — slashes are non-word characters. These
    // are all `read-only` today and a false positive here is a refused log read.
    for (const command of ['ls /home/su/notes', 'cat sudoku.txt', 'echo substitute',
                           'ls -la /var/su-backup', 'cat /etc/subuid']) {
      expect(classifyCommand(command).class, command).toBe('read-only');
    }
  });

  it('leaves the commands an operator runs all day alone', () => {
    // The friction constraint, executable. Each must keep the class it has today.
    for (const [command, expected] of [
      ['kubectl get pods', 'safe'],
      ['make deploy', 'safe'],
      ['docker run -e FOO=bar img', 'safe'],
      ['terraform apply', 'safe'],
      ['grep \'sudo\' /var/log/auth.log', 'read-only'],
      ['find / -name perl', 'read-only'],
    ] as const) {
      expect(classifyCommand(command).class, command).toBe(expected);
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run test/unit/policy/carrier-completeness.test.ts`
Expected: the six `it.each` cases and the substitution case FAIL (each reports `safe`, not `privileged`). The two "leaves alone" cases PASS — they are the guard rails, and they must pass before and after.

- [ ] **Step 3: Add the detector**

In `src/policy/classifier.ts`, immediately after `isDestructive()` (which ends around line 869) and before `const LEADING_PRIVILEGE_PREFIXES`:

```ts
/**
 * Elevation anywhere in a segment, not only at its command word.
 *
 * `LEADING_PRIVILEGE_PREFIXES` is `^`-anchored, so it only ever sees the command
 * word. `DESTRUCTIVE_PATTERNS` is not, which is why `echo "rm -rf /"` has always
 * been `destructive` while `echo "sudo id"` was `read-only`. A carrier nobody
 * listed — `osascript -e 'do shell script "sudo id"'` — fell in that gap
 * (GHSA-qmx6-47vm-3vf7). This is the unanchored counterpart the destructive side
 * already had.
 *
 * Per segment, and skipped for a segment whose operands are data, so a reader
 * searching a log for the word keeps working: `grep 'sudo' /var/log/auth.log`.
 *
 * The leading `[^\w-]` matters. `\bsu\b` alone matches `/home/su/notes`, because
 * a slash is a non-word character; requiring a non-word, non-hyphen character
 * before the name still matches `"sudo id"` and `;sudo` while leaving a path
 * segment named `su` alone. `-` is excluded so `--sudo-like` does not read as
 * elevation, and the trailing lookahead is `\s|$` rather than `\s` so a segment
 * ending in the word still matches. Measured against eight cases in both
 * directions: `"sudo id"`, a leading `sudo`, a trailing `sudo`, `/home/su/notes`,
 * `sudoku.txt`, `/etc/subuid`, `/var/su-backup`, `substitute`.
 */
const CARRIED_PRIVILEGE = /(?:^|[^\w-])(?:sudo|doas|pkexec|su)(?=\s|$)/;

function carriesElevation(command: string): boolean {
  return tokenizeSegmentsDetailed(command).some(({ words }) => {
    if (operandsAreData(words)) return false;
    return matchesEitherForm(words.join(' '), (form) => CARRIED_PRIVILEGE.test(form));
  });
}
```

In `classifyOuter()`, after the existing anchored check (around line 1267) and before the `hasUnreadableProgram` line:

```ts
  const elevated = elevatedBinaryOf(trimmed);
  if (elevated !== null) {
    return { binary: elevated, fullCommand, class: 'privileged' as CommandClass };
  }

  // The same question, asked of the whole segment rather than its command word.
  if (carriesElevation(trimmed)) {
    return { binary, fullCommand, class: 'privileged' as CommandClass };
  }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run test/unit/policy/carrier-completeness.test.ts`
Expected: PASS.

Then run the whole suite: `npx vitest run test/unit test/property`
Expected: 1067 passed (the count after the `sort` fix). **If anything else fails, do not adjust the failing test — stop and report it.** A pre-existing test failing here is the friction constraint telling you A is too broad.

- [ ] **Step 5: Mutate to verify the tests are load-bearing**

Run each, record the result, restore between:

| mutation | expected |
|---|---|
| delete the `carriesElevation` call from `classifyOuter` | the six carrier cases fail |
| `CARRIED_PRIVILEGE` → `/(?:^|[^\w-])(?:sudo|doas|pkexec|su)\b/` (drop the lookahead) | the "merely contains" case fails on `/home/su/notes` |
| drop the `operandsAreData` guard from `carriesElevation` | the friction case fails on `grep 'sudo' …` |

If any mutation leaves the suite green, the corresponding test does not test what its name says — fix the test, not the mutation.

- [ ] **Step 6: Commit**

```bash
git add src/policy/classifier.ts test/unit/policy/carrier-completeness.test.ts
git commit -m "fix(policy): find elevation wherever a shell would act on it"
```

The message must record the three mutations and their results.

---

### Task 2: The dual-purpose Set is split

**The maintainer chose the single table — see "Decision recorded" above.**

**Files:**
- Modify: `src/policy/classifier.ts` — replace the `READ_ONLY_ALLOWLIST` literal (line 23) with the `READERS` table and derive the Set from it; change `operandsAreData()` (line 941) to read `READERS[...].operandsAreData`
- Test: `test/unit/policy/carrier-completeness.test.ts` (append)

**Interfaces:**
- Consumes: the existing `READ_ONLY_ALLOWLIST` literal
- Produces: `READERS: Record<string, { readOnly: boolean; operandsAreData: boolean }>`, exported alongside the derived `READ_ONLY_ALLOWLIST` so tests can assert on both

- [ ] **Step 1: Record the measurement the spec asks for**

Before changing anything, establish whether the split is load-bearing today. Swap the set `operandsAreData` reads to a deliberately different one — an empty Set — and run the suite:

```bash
npm run build && npx vitest run test/unit test/property
```

Write the result into the commit message in Step 5, in these words or their negation: *"with the exemption emptied, N tests fail, so the exemption is load-bearing; with the two sets holding identical membership, swapping which one `operandsAreData` reads changes nothing, so the split is a naming change and nothing more."*

The spec forbids claiming more for the split than this measurement supports.

- [ ] **Step 2: Write the test**

Append to `test/unit/policy/carrier-completeness.test.ts`:

```ts
import { READ_ONLY_ALLOWLIST, READERS } from '../../../src/policy/classifier.js';

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
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npx vitest run test/unit/policy/carrier-completeness.test.ts`
Expected: FAIL — `READERS` is not exported yet.

- [ ] **Step 4: Make the change**

In `src/policy/classifier.ts`, replace the `READ_ONLY_ALLOWLIST` literal (line 23) with the table, and derive the Set from it:

```ts
/**
 * The binaries this classifier will vouch for, and what it vouches for about them.
 *
 * Two questions, kept apart because one Set answering both is how #217 turned the
 * interpreter carrier scan off for two verbs by adding them to a list about
 * classes:
 *
 *   readOnly         does this binary only read?  -> decides the class
 *   operandsAreData  can its operands hide a command?  -> decides whether the
 *                    carrier scan runs
 *
 * Both are `true` for every entry today. The value is not the contents but that
 * the type will not let the next person add a name without answering both.
 *
 * Two mechanisms answer the second question outside this table and are not
 * affected by it — `DISQUALIFYING_ARGS` and `FIND_EXEC_FLAGS` — which is why
 * `find` can carry `operandsAreData: true` while `find … -exec sudo id +` is
 * still `privileged`.
 *
 * The two-word entries are looked up only for the class: `operandsAreData` reads
 * a single word, so those rows never reach the second question.
 */
const READERS: Record<string, { readOnly: boolean; operandsAreData: boolean }> = {
  "arp":              { readOnly: true, operandsAreData: true },
  "basename":         { readOnly: true, operandsAreData: true },
  "cat":              { readOnly: true, operandsAreData: true },
  "comm":             { readOnly: true, operandsAreData: true },
  "cut":              { readOnly: true, operandsAreData: true },
  "date":             { readOnly: true, operandsAreData: true },
  "df":               { readOnly: true, operandsAreData: true },
  "diff":             { readOnly: true, operandsAreData: true },
  "dig":              { readOnly: true, operandsAreData: true },
  "dirname":          { readOnly: true, operandsAreData: true },
  "docker images":    { readOnly: true, operandsAreData: true },  // two-word: class only
  "docker inspect":   { readOnly: true, operandsAreData: true },  // two-word: class only
  "docker logs":      { readOnly: true, operandsAreData: true },  // two-word: class only
  "docker ps":        { readOnly: true, operandsAreData: true },  // two-word: class only
  "docker stats":     { readOnly: true, operandsAreData: true },  // two-word: class only
  "du":               { readOnly: true, operandsAreData: true },
  "echo":             { readOnly: true, operandsAreData: true },
  "false":            { readOnly: true, operandsAreData: true },
  "file":             { readOnly: true, operandsAreData: true },
  "find":             { readOnly: true, operandsAreData: true },
  "free":             { readOnly: true, operandsAreData: true },
  "git branch":       { readOnly: true, operandsAreData: true },  // two-word: class only
  "git diff":         { readOnly: true, operandsAreData: true },  // two-word: class only
  "git log":          { readOnly: true, operandsAreData: true },  // two-word: class only
  "git remote":       { readOnly: true, operandsAreData: true },  // two-word: class only
  "git show":         { readOnly: true, operandsAreData: true },  // two-word: class only
  "git status":       { readOnly: true, operandsAreData: true },  // two-word: class only
  "grep":             { readOnly: true, operandsAreData: true },
  "head":             { readOnly: true, operandsAreData: true },
  "host":             { readOnly: true, operandsAreData: true },
  "hostname":         { readOnly: true, operandsAreData: true },
  "htop":             { readOnly: true, operandsAreData: true },
  "id":               { readOnly: true, operandsAreData: true },
  "ifconfig":         { readOnly: true, operandsAreData: true },
  "iostat":           { readOnly: true, operandsAreData: true },
  "ip addr":          { readOnly: true, operandsAreData: true },  // two-word: class only
  "ip route":         { readOnly: true, operandsAreData: true },  // two-word: class only
  "journalctl":       { readOnly: true, operandsAreData: true },
  "ls":               { readOnly: true, operandsAreData: true },
  "netstat":          { readOnly: true, operandsAreData: true },
  "nslookup":         { readOnly: true, operandsAreData: true },
  "ping":             { readOnly: true, operandsAreData: true },
  "printenv":         { readOnly: true, operandsAreData: true },
  "printf":           { readOnly: true, operandsAreData: true },
  "ps":               { readOnly: true, operandsAreData: true },
  "pwd":              { readOnly: true, operandsAreData: true },
  "readlink":         { readOnly: true, operandsAreData: true },
  "realpath":         { readOnly: true, operandsAreData: true },
  "seq":              { readOnly: true, operandsAreData: true },
  "sort":             { readOnly: true, operandsAreData: true },
  "ss":               { readOnly: true, operandsAreData: true },
  "stat":             { readOnly: true, operandsAreData: true },
  "systemctl status": { readOnly: true, operandsAreData: true },  // two-word: class only
  "tail":             { readOnly: true, operandsAreData: true },
  "test":             { readOnly: true, operandsAreData: true },
  "top":              { readOnly: true, operandsAreData: true },
  "tr":               { readOnly: true, operandsAreData: true },
  "traceroute":       { readOnly: true, operandsAreData: true },
  "true":             { readOnly: true, operandsAreData: true },
  "uname":            { readOnly: true, operandsAreData: true },
  "uniq":             { readOnly: true, operandsAreData: true },
  "uptime":           { readOnly: true, operandsAreData: true },
  "vmstat":           { readOnly: true, operandsAreData: true },
  "wc":               { readOnly: true, operandsAreData: true },
  "whereis":          { readOnly: true, operandsAreData: true },
  "which":            { readOnly: true, operandsAreData: true },
  "who":              { readOnly: true, operandsAreData: true },
  "whoami":           { readOnly: true, operandsAreData: true },
};

/** The class half of READERS, as the shape its consumers already expect. */
const READ_ONLY_ALLOWLIST = new Set(
  Object.entries(READERS).filter(([, e]) => e.readOnly).map(([name]) => name),
);
```

Change `operandsAreData` (line 941) to read the other half:

```ts
function operandsAreData(words: string[]): boolean {
  const idx = effectiveCommandIndex(words);
  if (idx === -1) return false;
  return READERS[stripPath(unquote(words[idx]))]?.operandsAreData === true;
}
```

Add `READERS` to the export statement at the end of the file.

- [ ] **Step 5: Run the tests and commit**

Run: `npx vitest run test/unit test/property`
Expected: all pass, same count as after Task 1.

```bash
git add src/policy/classifier.ts test/unit/policy/carrier-completeness.test.ts
git commit -m "refactor(policy): one table, two answers, instead of one set answering two questions"
```

The message carries the Step 1 measurement.

---

### Task 3: The interpreter table gains the measured names, and decodes what it can

**Files:**
- Modify: `src/policy/classifier.ts` — `INTERPRETERS` (line 209), `programAfterFlag` call sites (lines 480-484, 1144-1147)
- Test: `test/unit/policy/carrier-completeness.test.ts` (append)

**Interfaces:**
- Consumes: `programAfterFlag(words, from, flags)` (line 999), `isFlagValue(words, i, flags)`, `stripPath`, `unquote`
- Produces: `INTERPRETERS` entries keyed by binary with `{ programBearingWords: string[]; readable: boolean }`

- [ ] **Step 1: Write the failing test**

Append to `test/unit/policy/carrier-completeness.test.ts`:

```ts
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

  it('still refuses an encoded payload that does not elevate', () => {
    // readable: false means the presence of a program is enough.
    expect(classifyCommand(`pwsh -EncodedCommand ${encode('Get-Process')}`).class).toBe('destructive');
  });

  it('does not throw on base64 that decodes to nothing useful', () => {
    // Buffer.from(x, 'base64') never throws — it drops invalid characters — so the
    // failure mode is a wrong answer, not an exception. Both must be safe.
    for (const junk of ['!!!!not base64!!!!', '', 'QQ', 'a'.repeat(4001)]) {
      expect(() => classifyCommand(`pwsh -EncodedCommand ${junk}`)).not.toThrow();
      expect(classifyCommand(`pwsh -EncodedCommand ${junk}`).class).toBe('destructive');
    }
  });

  it('stays cheap on a large encoded operand', () => {
    // Decoding is attacker-controlled work done before the policy decision. The
    // bound is a growth ratio, not a wall clock: this repo's CI runs under
    // coverage and an absolute bound once failed at 3677ms.
    const small = encode('Get-Process '.repeat(100));
    const large = encode('Get-Process '.repeat(10_000));
    const time = (c: string) => { const t = performance.now(); classifyCommand(c); return performance.now() - t; };
    time(`pwsh -EncodedCommand ${small}`); // warm
    const ratioSmall = time(`pwsh -EncodedCommand ${small}`);
    const ratioLarge = time(`pwsh -EncodedCommand ${large}`);
    expect(ratioLarge).toBeLessThan(Math.max(ratioSmall * 200, 50));
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run test/unit/policy/carrier-completeness.test.ts`
Expected: the seven interpreter cases, both path/quote cases and both encoded cases FAIL (each reports `safe`).

- [ ] **Step 3: Rename the field**

In `src/policy/classifier.ts`, change the `INTERPRETERS` type and every entry's key from `flags` to `programBearingWords`:

```ts
const INTERPRETERS: Record<string, { programBearingWords: string[]; readable: boolean }> = Object.assign(
```

`deno` takes `eval`, a subcommand rather than a flag, so a field called `flags` would have held something that is not one.

Update the three readers:
- line 480-484 in `nestedCommands`: `spec.flags` → `spec.programBearingWords` (two uses)
- line 1146-1147 in `hasUnreadableProgram`: `spec.flags` → `spec.programBearingWords` (two uses)

Run `npm run typecheck` — it will name every site you missed.

- [ ] **Step 4: Add the entries**

```ts
  // Measured on 2.11.0: each of these classified `safe` while the identical
  // attack through python3 -c classified `destructive` (GHSA-qmx6-47vm-3vf7).
  // `readable: false` throughout, matching python/perl/node: the program is not
  // shell text, so its presence is what counts rather than its content.
  osascript: { programBearingWords: ['-e'], readable: false },
  lua: { programBearingWords: ['-e'], readable: false },
  Rscript: { programBearingWords: ['-e'], readable: false },
  bun: { programBearingWords: ['-e'], readable: false },
  tclsh: { programBearingWords: ['-c'], readable: false },
  // `eval` is a subcommand, not a flag — the field is named for what it holds.
  deno: { programBearingWords: ['eval'], readable: false },
  pwsh: { programBearingWords: ['-c', '-Command', '-e', '-EncodedCommand'], readable: false },
  powershell: { programBearingWords: ['-c', '-Command', '-e', '-EncodedCommand'], readable: false },
```

- [ ] **Step 5: Decode `-EncodedCommand`**

Recognising the flag already makes the command `destructive` via `readable: false`. Decoding is what lets elevation inside it reach `privileged`, which is the difference between an admin on prod getting a prompt and getting a refusal.

Add next to `programAfterFlag`:

```ts
/** How much base64 is worth decoding before the answer stops changing. */
const MAX_ENCODED_CHARS = 64 * 1024;

/**
 * The command inside `-EncodedCommand`, or null.
 *
 * PowerShell encodes UTF-16LE, so decoding as utf8 yields text with a NUL between
 * every character and no pattern matches it. `Buffer.from(x, 'base64')` never
 * throws — it drops characters outside the alphabet — so malformed input produces
 * a wrong answer rather than an exception, and the caller must treat null and
 * nonsense alike: the flag alone has already made the command `destructive`.
 */
function decodedPowerShellCommand(operand: string): string | null {
  if (operand.length > MAX_ENCODED_CHARS) return null;
  const decoded = Buffer.from(operand, 'base64').toString('utf16le');
  return decoded.includes('�') || decoded.trim() === '' ? null : decoded;
}
```

In `nestedCommands`, inside the existing interpreter loop (around line 480), after `programAfterFlag` returns a program:

```ts
        const program = programAfterFlag(words, i, spec.programBearingWords);
        if (program !== null) {
          found.push(program);
          // An encoded program is opaque to every text scan until it is decoded.
          if (words.includes('-EncodedCommand')) {
            const decoded = decodedPowerShellCommand(program);
            if (decoded !== null) found.push(decoded);
          }
        }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `npx vitest run test/unit/policy/carrier-completeness.test.ts`
Expected: PASS.

Run: `npx vitest run test/unit test/property`
Expected: all pass.

- [ ] **Step 7: Mutate to verify the tests are load-bearing**

| mutation | expected |
|---|---|
| remove the `osascript` entry | the osascript case fails |
| remove the `deno` entry | the deno case fails |
| decode as `utf8` instead of `utf16le` | the `-EncodedCommand` elevation case fails |
| drop the `MAX_ENCODED_CHARS` guard | the cost case fails, or records that it does not — if it does not, say so rather than keeping a bound that pins nothing |
| `readable: true` on `osascript` | the osascript case fails |

- [ ] **Step 8: Commit**

```bash
git add src/policy/classifier.ts test/unit/policy/carrier-completeness.test.ts
git commit -m "fix(policy): read the interpreters that were missing, and decode what hides"
```

---

### Task 4: Changeset and release preparation

**Files:**
- Create: `.changeset/carrier-completeness.md`

- [ ] **Step 1: Write the changeset**

```markdown
---
"ssh-mcp": minor
---

A binary the classifier does not recognise can no longer launder an elevated command into the `safe` class.

Elevation is now found wherever a shell would act on it, not only at a command's first word — the unanchored form the destructive scan has always had. `osascript -e 'do shell script "sudo id"'` classified `safe` and ran with no prompt on a profile that refuses `sudo id` outright; it now classifies `privileged`. The same applies to any carrier, including ones nobody has listed.

The interpreter table also gains `osascript`, `lua`, `Rscript`, `bun`, `tclsh`, `deno eval` and `pwsh`/`powershell`, so a program handed to one of them is `destructive` even when it carries no elevation and matches no destructive pattern. `pwsh -EncodedCommand` is decoded, so what it carries is classified rather than merely counted.

Reported by @MartOcd1709.
```

- [ ] **Step 2: Run the full suite one more time**

```bash
npm run typecheck && npm run build && npx vitest run test/unit test/property && npm run test:e2e
```

Integration tests need the Docker targets: `docker compose --profile test up -d --build`.

- [ ] **Step 3: Commit and push to the fork**

```bash
git add .changeset/carrier-completeness.md
git commit -m "chore: changeset for GHSA-qmx6-47vm-3vf7"
git push origin fix/sort-compress-program
```

- [ ] **Step 4: Hand back for the disclosure steps**

These are the maintainer's, not an implementer's: merging the fork's branch into the public repository, publishing the advisory with `patched_versions` filled, keeping @MartOcd1709 credited, and deciding whether to request a CVE.
