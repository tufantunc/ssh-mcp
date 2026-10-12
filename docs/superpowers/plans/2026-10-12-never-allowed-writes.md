# Never-Allowed Writes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the never-allowed list refuse the writes the README promises — to `/etc/cron`, `/etc/systemd` and any user's `authorized_keys` — from shell redirects, the destination operands of `tee`/`cp`/`mv`/`install`/`dd of=`, and the SFTP upload tools' remote path.

**Architecture:** One path predicate (`src/policy/never-allowed-writes.ts`) over the three path readings #230 built (as given, normalized, Windows case-insensitive), consumed by a new word-based forbidden rule in the classifier and by a resource check in the engine; the tool layer declares which calls write their remote path via `PolicyResource.remoteWrite`.

**Tech Stack:** TypeScript (ESM, Node), vitest, existing in-process tool harness (`test/unit/tools/harness.ts`).

**Spec:** `docs/superpowers/specs/2026-10-12-never-allowed-writes-design.md` (GHSA-rrxj-hcj2-vwm6, embargoed).

## Global Constraints

- Embargo: no commit text, changeset text or public artifact may describe the vulnerability class. Neutral wording only. Push only to the advisory's temporary private fork, never `origin`.
- Git in this worktree: call `/usr/bin/git` (a user hook rewrites bare `git` to `rtk git`, which the worktree guard refuses).
- Every commit carries the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` (branch-wide SDD ledger ruling).
- TDD: each test is seen failing first, and counts only if it fails with its production line removed. Mutation runs happen on a backup copy which is restored afterwards. Foreign mutants (below) are run too.
- No wall-clock timing in tests.
- `node_modules` in this worktree is an untracked symlink — never commit it.
- Unit test command: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run <file>`; typecheck: `npm run typecheck`.
- Release is **minor**; the changeset text stays neutral (`fix(policy): harden the built-in never-allowed rules`).

---

### Task 1: The path predicate — `src/policy/never-allowed-writes.ts`

**Files:**
- Create: `src/policy/never-allowed-writes.ts`
- Test: `test/unit/policy/never-allowed-writes.test.ts`

**Interfaces:**
- Consumes: `normalizeRemotePath`, `normalizeRemotePathForWindows` from `src/policy/remote-path.ts` (existing, exported).
- Produces: `findNeverAllowedWriteTarget(path: string): NeverAllowedWriteTarget | null` and `neverAllowedWriteLabel(target: NeverAllowedWriteTarget): string`, where `NeverAllowedWriteTarget = '/etc/cron' | '/etc/systemd' | 'authorized_keys'`. Tasks 2 and 3 import these.

- [ ] **Step 1: Write the failing test**

Create `test/unit/policy/never-allowed-writes.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import {
  findNeverAllowedWriteTarget,
  neverAllowedWriteLabel,
} from '../../../src/policy/never-allowed-writes.js';

describe('findNeverAllowedWriteTarget', () => {
  describe('the /etc/cron family', () => {
    it.each([
      '/etc/cron.d/x',
      '/etc/crontab',                 // covered by the prefix reading, as the old regex read it
      '/etc/cron.daily/backup',
      '/etc/cron',                    // the directory itself
      '//etc/cron.d/x',               // normalized reading
      '/etc/./cron.d/x',
      '/etc/cron.d/../cron.d/x',
      '/etc/cron.d/x/',               // trailing separator
      '/ETC/CRON.D/X',                // Windows reading, case-insensitive
      '\\etc\\cron.d\\x',
    ])('%s names a covered path', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBe('/etc/cron');
    });

    it.each([
      'etc/cron.d/x',                 // relative: no absolute /etc
      '/var/etc/cron.d/x',
      '/etc/passwd',
      '/home/u/cron.d/x',
    ])('%s does not', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBeNull();
    });
  });

  describe('the /etc/systemd family', () => {
    it.each([
      '/etc/systemd/system/x.service',
      '//etc/systemd/system/x.service',
      '/ETC/SYSTEMD/system/x.service',
      '\\etc\\systemd\\system\\x.service',
    ])('%s names a covered path', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBe('/etc/systemd');
    });

    it.each(['/usr/lib/systemd/system/x.service', '/etc/system']) // trailing partial... see mutant note
      ('%s does not', (path) => {
        expect(findNeverAllowedWriteTarget(path)).toBeNull();
      });
  });

  describe("any user's authorized_keys", () => {
    it.each([
      '~/.ssh/authorized_keys',
      '~root/.ssh/authorized_keys',
      '/root/.ssh/authorized_keys',
      '/home/u/.ssh/authorized_keys',
      '.ssh/authorized_keys',         // relative
      '~/.ssh//authorized_keys',      // normalized reading
      '~/x/../.ssh/authorized_keys',
      'C:\\Users\\a\\.ssh\\authorized_keys',
      'C:/Users/a/.ssh/AUTHORIZED_KEYS.',   // Windows reading: case + trailing dot
      '\\\\server\\share\\.ssh\\authorized_keys::$DATA',
      '\\\\?\\C:\\x\\.ssh\\authorized_keys',
    ])('%s names a covered path', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBe('authorized_keys');
    });

    it.each([
      '~/.ssh/authorized_keys2',
      '~/.ssh/id_ed25519',
      '/home/u/docs/authorized_keys', // not inside .ssh
      'authorized_keys',              // a bare filename is not the path
      '',
      '.',
      '/tmp/x',
    ])('%s does not', (path) => {
      expect(findNeverAllowedWriteTarget(path)).toBeNull();
    });
  });

  it('labels name the family for refusal wording', () => {
    expect(neverAllowedWriteLabel('/etc/cron')).toBe('writing to /etc/cron');
    expect(neverAllowedWriteLabel('/etc/systemd')).toBe('writing to /etc/systemd');
    expect(neverAllowedWriteLabel('authorized_keys')).toBe("writing to any user's authorized_keys");
  });
});
```

Note: `/etc/system` **does** match — `startsWith('/etc/systemd')` is false for `/etc/system`, so the
"does not" row above is correct as written; do not "fix" it to fire. (`/etc/cronography` conversely
*does* fire under `/etc/cron` — the unbounded prefix is inherited from the old regex on purpose;
fail-closed.)

- [ ] **Step 2: Run it to make sure it fails**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/never-allowed-writes.test.ts`
Expected: FAIL — cannot resolve `../../../src/policy/never-allowed-writes.js`.

- [ ] **Step 3: Write the implementation**

Create `src/policy/never-allowed-writes.ts`:

```ts
import { normalizeRemotePath, normalizeRemotePathForWindows } from './remote-path.js';

/**
 * Which of the README's never-allowed write families a path names.
 *
 * The README sentence covers three targets — writes to `/etc/cron`, `/etc/systemd`
 * and `authorized_keys` — and this type is how a refusal names which one fired,
 * from either check site: the classifier's shell-form rule and the engine's
 * resource check.
 */
export type NeverAllowedWriteTarget = '/etc/cron' | '/etc/systemd' | 'authorized_keys';

/**
 * The `/etc` families are prefix matches with no boundary: `/etc/crontab` sits under
 * `/etc/cron` the same way `/etc/cron.d/x` does, which is how the redirect regex this
 * module replaces always read it. A sibling that merely starts like the directory
 * (`/etc/cronography`) fires too — over-refusal in the fail-closed direction this
 * engine takes everywhere else.
 */
const NEVER_DIRS = ['/etc/cron', '/etc/systemd'] as const;

/** The keys family: any path whose last two segments are `.ssh/authorized_keys`. */
const KEYS_TAIL = '/.ssh/authorized_keys';

/**
 * The refusal wording for a family, defined once because two check sites quote it:
 * the classifier's ForbiddenRule label and the engine's built-in deny reason.
 */
export function neverAllowedWriteLabel(target: NeverAllowedWriteTarget): string {
  switch (target) {
    case '/etc/cron': return 'writing to /etc/cron';
    case '/etc/systemd': return 'writing to /etc/systemd';
    case 'authorized_keys': return "writing to any user's authorized_keys";
  }
}

function familyOf(path: string): NeverAllowedWriteTarget | null {
  for (const dir of NEVER_DIRS) {
    if (path.startsWith(dir)) return dir;
  }
  if (path.endsWith(KEYS_TAIL) || path === KEYS_TAIL.slice(1)) return 'authorized_keys';
  return null;
}

/**
 * Whether `path` names one of the never-allowed write targets, in any spelling the
 * path readings resolve.
 *
 * The same three readings `[policy].denylist` sees (#230): the path as given; a
 * lexically normalized reading (`//`, `/./`, `..`, trailing separators, `\` as a
 * separator); and the Windows reading of it, case-insensitively — so `Authorized_Keys.`,
 * `authorized_keys::$DATA` and backslash spellings reach the same refusal. On a POSIX
 * target some of those are different files; refusing them is the safe direction, the
 * same trade the operator denylist already makes.
 *
 * What this does not do is resolve anything on the target: a relative path stays
 * relative, symlinks are not followed, and an 8.3 short name is not expanded (#230's
 * documented residuals, inherited here).
 */
export function findNeverAllowedWriteTarget(path: string): NeverAllowedWriteTarget | null {
  return familyOf(path)
    ?? familyOf(normalizeRemotePath(path))
    ?? familyOf(normalizeRemotePathForWindows(path).toLowerCase());
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/never-allowed-writes.test.ts`
Expected: PASS (all rows).

- [ ] **Step 5: Mutation checks (backup first, restore after)**

```bash
cp src/policy/never-allowed-writes.ts /tmp/naw.bak
```

For each mutant below: apply the edit, run
`npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/never-allowed-writes.test.ts`,
confirm FAIL, then restore (`cp /tmp/naw.bak src/policy/never-allowed-writes.ts`).

1. Own mutant: delete the `normalizeRemotePath(path)` reading → the `//`- and `/./`-prefixed rows fail.
2. Own mutant: delete the `normalizeRemotePathForWindows(...)` reading → the case-variant, trailing-dot, `::$DATA` and `\\?\` rows fail.
3. Own mutant: drop `|| path === KEYS_TAIL.slice(1)` → the relative `.ssh/authorized_keys` row fails.
4. Foreign mutant: change `path.startsWith(dir)` to `path.startsWith(dir + '/')` → the `/etc/crontab` and `/etc/cron` rows fail (the no-boundary prefix is load-bearing).
5. Foreign mutant: change `path.endsWith(KEYS_TAIL)` to `path.endsWith('authorized_keys')` → the `/home/u/docs/authorized_keys` negative row fails (the `.ssh/` anchor is load-bearing).

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add src/policy/never-allowed-writes.ts test/unit/policy/never-allowed-writes.test.ts
/usr/bin/git commit -m "feat(policy): never-allowed write path predicate

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: The shell-form rule in the classifier

**Files:**
- Modify: `src/policy/classifier.ts` — remove three `FORBIDDEN_PATTERNS` regexes; add the redirect/verb scans and three `FORBIDDEN_RULES` entries.
- Test: `test/unit/policy/never-allowed-writes.test.ts` (extend, same file as Task 1 — the concern is one).

**Interfaces:**
- Consumes: `findNeverAllowedWriteTarget`, `neverAllowedWriteLabel`, `NeverAllowedWriteTarget` (Task 1); in-file `tokenizeSegments`, `effectiveCommandIndex`, `stripPath`, `DOUBLE_QUOTE_ESCAPABLE`, `ShellDialect`, `ForbiddenRule`.
- Produces: no new exports. The three new `FORBIDDEN_RULES` labels are `'writing to /etc/cron'`, `'writing to /etc/systemd'`, `"writing to any user's authorized_keys"` (from `neverAllowedWriteLabel`), returned by `findForbiddenMatch`.

- [ ] **Step 1: Write the failing tests**

Append to `test/unit/policy/never-allowed-writes.test.ts`:

```ts
import { findForbiddenMatch } from '../../../src/policy/classifier.js';

const CRON = 'writing to /etc/cron';
const SYSTEMD = 'writing to /etc/systemd';
const KEYS = "writing to any user's authorized_keys";

describe('the never-allowed write forms (findForbiddenMatch)', () => {
  describe('refuses', () => {
    it.each([
      // Redirects, in the spellings the old regexes missed.
      ['echo k > ~/.ssh/authorized_keys', KEYS],
      ['echo k > /root/.ssh/authorized_keys', KEYS],
      ['echo k > ~root/.ssh/authorized_keys', KEYS],
      ['echo k >>/root/.ssh/authorized_keys', KEYS],
      ['echo k >"/root/.ssh/authorized_keys"', KEYS],
      ['echo k > "/root/.ssh/authorized_keys"', KEYS],
      ['echo x 2> /etc/cron.d/y', CRON],
      ['echo x 2>> /etc/cron.d/y', CRON],
      ['echo x &> /etc/cron.d/y', CRON],
      ['echo x > /etc/cron.d/y', CRON],
      ['echo x > //etc/cron.d/y', CRON],
      ['echo x > /etc/systemd/system/x.service', SYSTEMD],
      ['echo k > C:\\Users\\a\\.ssh\\authorized_keys', KEYS],
      // Write verbs, destination operand.
      ['tee -a ~/.ssh/authorized_keys', KEYS],
      ['sudo tee -a /etc/cron.d/x', CRON],
      ['cp k ~/.ssh/authorized_keys', KEYS],
      ['cp authorized_keys ~/.ssh/', KEYS],
      ['cp -t /etc/cron.d x', CRON],
      ['cp --target-directory=/etc/cron.d x', CRON],
      ['install -m 600 k /root/.ssh/authorized_keys', KEYS],
      ['install -d /etc/cron.d/x', CRON],
      ['mv k /etc/systemd/system/x.service', SYSTEMD],
      ['dd of=/root/.ssh/authorized_keys', KEYS],
      // Wrappers and carriers.
      ['sudo cp k /root/.ssh/authorized_keys', KEYS],
      ['env cp k /root/.ssh/authorized_keys', KEYS],
      ['sh -c "cp k /root/.ssh/authorized_keys"', KEYS],
      ['echo $(tee -a /etc/cron.d/x)', CRON],
    ])('%s', (command, label) => {
      expect(findForbiddenMatch(command)).toBe(label);
    });
  });

  describe('does not refuse', () => {
    it.each([
      // Reads stay allowed.
      'cat ~/.ssh/authorized_keys',
      'grep -c ssh /etc/cron.d/x',
      'tail /etc/systemd/system/x.service',
      // Mentions are not writes (the maintainer's speculativeOperands ruling).
      "git commit -m 'tee -a /etc/cron.d/x'",
      'git commit -m "echo x > /etc/cron"',
      'echo "> /etc/cron.d/y"',
      'echo "cp k /root/.ssh/authorized_keys"',
      // Uncovered writes and non-targets.
      'echo x > /tmp/y',
      'cp k /tmp/authorized_keys',
      'sed -i 1d ~/.ssh/authorized_keys',
      'tee --help',
      'cp k',
      'echo x >',
    ])('%s', (command) => {
      expect(findForbiddenMatch(command)).toBeNull();
    });
  });
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/never-allowed-writes.test.ts`
Expected: FAIL — every "refuses" row that is not a bare `>` redirect returns null today; the two
quoted-mention rows in "does not refuse" (`git commit -m "echo x > /etc/cron"`, `echo "> /etc/cron.d/y"`)
fail in the *opposite* direction (they return a match on main — the over-refusal being corrected).

- [ ] **Step 3: Implement**

In `src/policy/classifier.ts`:

3a. Add the import at the top, next to the other `./` policy imports:

```ts
import { findNeverAllowedWriteTarget, neverAllowedWriteLabel, type NeverAllowedWriteTarget } from './never-allowed-writes.js';
```

3b. Delete these three lines from `FORBIDDEN_PATTERNS` (superseded by the word-based rule):

```ts
  />\s*\/etc\/cron/,
  />\s*\/etc\/systemd/,
  />\s*~\/\.ssh\/authorized_keys/,
```

3c. Add the scans above the `FORBIDDEN_RULES` definition (after `chownsRoot`):

```ts
/**
 * One dequoted word starting at `start`, as the redirect-target reader needs it.
 *
 * Stops at whitespace, at a character that begins another shell construct (`; | & < >
 * ( )`), or at the end. A word that opens with a quote is read to its close and the
 * quotes are dropped — `> "/etc/cron.d/x"` and `> /etc/cron.d/x` name the same target.
 * A mid-word quote (`> a"b"c`) is handled the same way the tokeniser handles it.
 */
function readDequotedWord(command: string, start: number, dialect: ShellDialect): string {
  const n = command.length;
  if (start >= n || /[\s;&|<>()]/.test(command[start])) return '';
  let word = '';
  let quote: string | null = command[start] === '"' || command[start] === "'" ? command[start] : null;
  let escaped = false;
  for (let i = quote === null ? start : start + 1; i < n; i++) {
    const ch = command[i];
    if (escaped) { word += ch; escaped = false; continue; }
    if (dialect === 'posix' && ch === '\\') {
      if (quote === "'") { word += ch; continue; }
      if (quote === '"') {
        const next = command[i + 1];
        if (next === undefined || DOUBLE_QUOTE_ESCAPABLE.has(next)) { escaped = true; continue; }
        word += ch; continue;
      }
      escaped = true; continue;
    }
    if (quote) {
      if (ch === quote) break;
      word += ch; continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (/[\s;&|<>()]/.test(ch)) break;
    word += ch;
  }
  return word;
}

/**
 * Every shell-redirect target in `command`, dequoted the way the shell will pass it.
 *
 * A redirect is an unquoted `>` — alone (`> f`), attached to the word it ends
 * (`echo x>f`, which bash also reads as a redirect), doubled (`>>`), with an fd
 * prefix (`2>`, `2>>`) or the both-streams spellings (`&>`, `&>>`, `>&`). A `>`
 * inside quotes is data (`echo "> f"` prints a string) and yields nothing, which
 * is what separates this scan from the raw regexes it replaces: those fired on
 * the quoted text too, so a commit message quoting a redirect was a refusal
 * nobody could switch off (measured on main).
 *
 * The target is the next word after the operator, quoted or attached. An operator
 * with nothing readable after it is a syntax error the remote shell would report,
 * and yields nothing. `>(...)` process substitution yields nothing here too — its
 * inner command is a carrier `nestedCommands` already reads.
 */
function redirectTargets(command: string, dialect: ShellDialect): string[] {
  const targets: string[] = [];
  const n = command.length;
  let quote: string | null = null;
  let escaped = false;
  for (let i = 0; i < n; i++) {
    const ch = command[i];
    if (escaped) { escaped = false; continue; }
    if (dialect === 'posix' && ch === '\\' && quote !== "'") { escaped = true; continue; }
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch !== '>' && !(ch === '&' && command[i + 1] === '>')) continue;

    let j = ch === '&' ? i + 2 : i + 1;
    if (command[j] === '>') j++;   // >>
    if (command[j] === '&') j++;   // >& fd duplication
    while (j < n && /\s/.test(command[j])) j++;
    const word = readDequotedWord(command, j, dialect);
    if (word !== '') targets.push(word);
    i = j - 1;
  }
  return targets;
}

/**
 * The destination operands of the verbs whose argv names the file they write.
 *
 * A closed list, on purpose. `tee` writes every non-flag operand; `cp`, `mv` and
 * `install` write their destination operand — the value of `-t`/
 * `--target-directory` when present, else the last positional — and, because that
 * operand may name a directory the sources are copied *into*, the same joined with
 * each source's basename, so `cp authorized_keys ~/.ssh/` is caught rather than
 * only `cp k ~/.ssh/authorized_keys`. `install -d` creates every operand.
 * `dd of=` writes the value. Every other verb is a documented residual: a guess
 * about an unrecognised binary's operands must not reach this list (the
 * `speculativeOperands: false` ruling), and #230's decision 1 already ruled that
 * extracting paths from shell text can never be complete — so the README lists
 * these forms and names the rest as governed by class and approval instead.
 *
 * `env cp …`, `sudo cp …` and `timeout 5 cp …` reach the verb through
 * `effectiveCommandIndex`, which steps privilege prefixes and exec wrappers the
 * same way the elevation scan does.
 */
function writeVerbTargets(command: string, dialect: ShellDialect): string[] {
  const targets: string[] = [];
  for (const words of tokenizeSegments(command, dialect)) {
    const idx = effectiveCommandIndex(words);
    if (idx === -1) continue;
    const head = stripPath(words[idx]);
    const args = words.slice(idx + 1);
    const positional = args.filter((a) => !a.startsWith('-'));

    if (head === 'tee') {
      targets.push(...positional);
      continue;
    }
    if (head === 'dd') {
      for (const arg of args) {
        if (arg.startsWith('of=')) targets.push(arg.slice(3));
      }
      continue;
    }
    if (head === 'cp' || head === 'mv' || head === 'install') {
      if (head === 'install' && args.some((a) => a === '-d' || a === '--directory')) {
        targets.push(...positional);
        continue;
      }
      const tFlag = args.find((a) => a === '-t' || a.startsWith('--target-directory'));
      let dest: string | null = null;
      let sources = positional;
      if (tFlag !== undefined) {
        dest = tFlag === '-t'
          ? args[args.indexOf(tFlag) + 1] ?? null
          : tFlag.slice(tFlag.indexOf('=') + 1) || null;
      } else if (positional.length >= 2) {
        dest = positional[positional.length - 1];
        sources = positional.slice(0, -1);
      }
      if (dest === null || dest === '') continue;
      targets.push(dest);
      for (const src of sources) {
        const base = stripPath(src);
        if (base !== '') targets.push(`${dest}/${base}`);
      }
    }
  }
  return targets;
}

/**
 * Which never-allowed family this command's certain write forms name, or null.
 * Both dialects are tried by the caller (findForbiddenMatchInDialect), and nested
 * commands reach this through the same recursion every other rule uses.
 */
function findNeverAllowedWriteFamily(command: string, dialect: ShellDialect): NeverAllowedWriteTarget | null {
  for (const candidate of [...redirectTargets(command, dialect), ...writeVerbTargets(command, dialect)]) {
    const target = findNeverAllowedWriteTarget(candidate);
    if (target !== null) return target;
  }
  return null;
}
```

3d. Extend `FORBIDDEN_RULES` (after the `chownsRoot` entry):

```ts
  ...(['/etc/cron', '/etc/systemd', 'authorized_keys'] as const).map((family) => ({
    label: neverAllowedWriteLabel(family),
    test: (command: string, dialect: ShellDialect) => findNeverAllowedWriteFamily(command, dialect) === family,
  })),
```

- [ ] **Step 4: Run the tests**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/never-allowed-writes.test.ts`
Expected: PASS. Then the classifier's own suites, for regressions against the removed regexes:

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/classifier.test.ts test/unit/policy/engine.test.ts test/unit/policy/quote-removal.test.ts test/unit/policy/backslash-readings.test.ts`
Expected: PASS. If a classifier test asserted the old `>\s*\/etc\/cron` label, update it to the new
label — the behavior (refusal) is unchanged for those spellings, only the wording moved.

- [ ] **Step 5: Mutation checks**

```bash
cp src/policy/classifier.ts /tmp/classifier.bak
```

Each mutant: apply, run the Task-2 suite, confirm FAIL, restore from `/tmp/classifier.bak`.

1. Own mutant: in `writeVerbTargets`, change `head === 'tee'` to `false && head === 'tee'` → the `tee` rows fail.
2. Own mutant: in `redirectTargets`, delete the `if (word !== '') targets.push(word);` line → every redirect row fails.
3. Own mutant: in `writeVerbTargets`, delete the `targets.push(dest);` line (keep compositions) → `cp -t /etc/cron.d x` still fires via composition, but `install -d /etc/cron.d/x` and `cp k /root/.ssh`-shaped directory destinations narrow — the `install -d` row must fail.
4. Foreign mutant: in `redirectTargets`, delete the quote-state lines (`if (quote) { … }` and the quote-assignment branch) → `echo "> /etc/cron.d/y"` and `git commit -m "echo x > /etc/cron"` fail as false refusals.
5. Foreign mutant: in `readDequotedWord`, change the stop set `/[\s;&|<>()]/` to `/\s/` → `echo x > /etc/cron.d/y ; safe`-style trailing-separator rows would swallow the separator; verify with a one-off row `echo x > /etc/cron.d/y; id` added temporarily to the suite (it must stay CRON), confirm the mutant breaks it, remove the row, restore.

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add src/policy/classifier.ts test/unit/policy/never-allowed-writes.test.ts
/usr/bin/git commit -m "feat(policy): never-allowed write forms in the classifier

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: The engine's resource check — `PolicyResource.remoteWrite`

**Files:**
- Modify: `src/policy/engine.ts` — `PolicyResource`, `findDenyMatch`, the OPA input.
- Test: `test/unit/policy/engine.test.ts` (extend, matching the existing `describe` style there).

**Interfaces:**
- Consumes: `findNeverAllowedWriteTarget`, `neverAllowedWriteLabel` (Task 1); in-file `quotePath`.
- Produces: `PolicyResource.remoteWrite?: boolean` — Task 4's tool handlers set it; the OPA input's `resource.remoteWrite` mirrors it.

- [ ] **Step 1: Write the failing tests**

In `test/unit/policy/engine.test.ts`, inside the top-level `describe('PolicyEngine', …)` block, add (mirroring the file's existing `profile` fixture — reuse whatever variable the neighbouring `denylist sees the remote path` block uses):

```ts
  describe('a declared remote write to a never-allowed path', () => {
    const engine = new PolicyEngine(DEFAULT_RULES);
    // The file's own fixture helper; admin + auto so the class gates that remain
    // (destructive, privileged) do not mask the denylist decision under test.
    const profile = makeProfile({ role: 'admin', name: 'dev', approvalPolicy: 'auto' });
    const UPLOAD_KEYS = 'sftp:upload --overwrite --bytes=1 --sha256=x /root/.ssh/authorized_keys';

    it('is refused with the built-in wording, with no operator denylist at all', () => {
      const result = engine.evaluate(UPLOAD_KEYS, profile, {
        remotePath: '/root/.ssh/authorized_keys',
        remoteWrite: true,
      });
      expect(result.decision).toBe('deny');
      expect(result.ruleId).toBe('denylist');
      expect(result.reason).toMatch(/built-in never-allowed rule/);
      expect(result.reason).toContain("writing to any user's authorized_keys");
      expect(result.reason).toContain('cannot be switched off');
    });

    it('the Windows reading refuses a case-variant spelling', () => {
      const result = engine.evaluate('sftp:upload --overwrite --bytes=1 --sha256=x k', profile, {
        remotePath: 'C:\\Users\\a\\.ssh\\Authorized_Keys.',
        remoteWrite: true,
      });
      expect(result.decision).toBe('deny');
      expect(result.ruleId).toBe('denylist');
    });

    it('a declared write to a benign path is not refused by the built-ins', () => {
      const result = engine.evaluate('sftp:upload --overwrite --bytes=1 --sha256=x /tmp/x', profile, {
        remotePath: '/tmp/x',
        remoteWrite: true,
      });
      expect(result.decision).toBe('allow');
    });

    it('a read of the same path is not refused — remoteWrite is what makes it a write', () => {
      const result = engine.evaluate('sftp:download /root/.ssh/authorized_keys', profile, {
        remotePath: '/root/.ssh/authorized_keys',
      });
      expect(result.decision).toBe('allow');
    });
  });
```

(`makeProfile` is the file's existing fixture helper, shown at its top; the `sftp:download` row
expects `allow` because the class is `read-only` and the admin role holds it.)

- [ ] **Step 2: Run them to make sure they fail**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/engine.test.ts`
Expected: FAIL — the first two rows come back `allow` (or a TS error on the unknown `remoteWrite`
field, which is also a failing state for TDD purposes; write the tests, see them fail at runtime by
temporarily casting if the checker complains first).

- [ ] **Step 3: Implement**

In `src/policy/engine.ts`:

3a. Import:

```ts
import { findNeverAllowedWriteTarget, neverAllowedWriteLabel } from './never-allowed-writes.js';
```

3b. Extend the interface:

```ts
export interface PolicyResource {
  remotePath?: string;
  /**
   * The call writes its remote path. Set by the SFTP upload tools, left unset by the
   * read tools: the never-allowed write paths are refused for a declared write and
   * stay class-governed for a read, and the fact is the tool layer's to state — the
   * engine does not guess it from the composed command string.
   */
  remoteWrite?: boolean;
}
```

3c. In `findDenyMatch`, immediately after the `builtIn` block and **before** the
`if (this.userPatterns.length === 0) return null;` early return:

```ts
    // The built-in never-allowed write paths, tested against a remote path the tool
    // declared it writes. Runs before the early return because the defaults carry no
    // operator denylist — this check is not the operator's to switch on.
    if (resource.remoteWrite && resource.remotePath) {
      const target = findNeverAllowedWriteTarget(resource.remotePath);
      if (target !== null) {
        return `Remote path ${quotePath(resource.remotePath)} matches a built-in never-allowed rule: ` +
          `${neverAllowedWriteLabel(target)}. ` +
          `This list cannot be switched off — the [policy].denylist key adds patterns, it does not remove these.`;
      }
    }
```

3d. In `evaluateWithOpa`'s input, add to `resource`:

```ts
          remoteWrite: resource.remoteWrite || undefined,
```

- [ ] **Step 4: Run the tests**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/engine.test.ts test/unit/policy/opa.test.ts`
Expected: PASS (`opa.test.ts` covers the input shape; extend it with one assertion that `remoteWrite`
is `true` in the input when declared — add it in the same step if the file asserts other `resource`
fields).

- [ ] **Step 5: Mutation checks**

```bash
cp src/policy/engine.ts /tmp/engine.bak
```

1. Own mutant: delete the whole `resource.remoteWrite && resource.remotePath` block → the two refuse rows fail.
2. Own mutant: change `resource.remoteWrite && resource.remotePath` to `resource.remotePath` → the "read of the same path" row fails (a read must not be refused).
3. Foreign mutant: move the block to *after* the `userPatterns.length === 0` early return → the "no operator denylist at all" row fails (the check must run without an operator denylist).

Restore from `/tmp/engine.bak` after each.

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add src/policy/engine.ts test/unit/policy/engine.test.ts test/unit/policy/opa.test.ts
/usr/bin/git commit -m "feat(policy): resource-declared remote writes in the engine

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: The tools declare their writes

**Files:**
- Modify: `src/tools/file-tools.ts` (the `sftp-upload` handler), `src/tools/transfer-tools.ts` (the `sftp-upload-file` handler).
- Test: `test/unit/tools/never-allowed-writes.test.ts` (create, mirroring `test/unit/tools/denylist-remote-path.test.ts`).

**Interfaces:**
- Consumes: `PolicyResource.remoteWrite` (Task 3), the harness (`createHarness`, `textOf`).
- Produces: none.

- [ ] **Step 1: Write the failing test**

Create `test/unit/tools/never-allowed-writes.test.ts`:

```ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHarness, textOf, type Harness } from './harness.js';
import { DEFAULT_RULES } from '../../../src/policy/engine.js';

/**
 * The write tools declare their write, so the built-in never-allowed paths refuse
 * them without any operator denylist; the read tools of the same paths are left to
 * their class. A tool that stops declaring (or a read tool that starts) fails its row.
 */
const ADMIN_AUTO = { role: 'admin' as const, approvalPolicy: 'auto' as const };

let h: Harness;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'ssh-mcp-naw-'));
  await chmod(root, 0o700);
});

afterEach(async () => {
  await h?.close();
  await rm(root, { recursive: true, force: true });
});

async function call(tool: string, args: Record<string, unknown>) {
  h = await createHarness(ADMIN_AUTO, { localPath: { transferRoot: root } }, DEFAULT_RULES);
  return h.client.callTool({ name: tool, arguments: args }) as Promise<any>;
}

describe('the SFTP write tools and the never-allowed paths', () => {
  it.each([
    ['sftp-upload', { remotePath: '/root/.ssh/authorized_keys', content: 'k' }],
    ['sftp-upload', { remotePath: '/etc/cron.d/x', content: 'k' }],
    ['sftp-upload-file', { remotePath: '/root/.ssh/authorized_keys', localPath: 'k' }],
    ['sftp-upload-file', { remotePath: '/etc/systemd/system/x.service', localPath: 'k' }],
  ])('%s to %j is refused by the built-in list', async (tool, args) => {
    const result = await call(tool, args);
    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toMatch(/built-in never-allowed rule/);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  it.each([
    ['sftp-list', { remotePath: '/etc/cron.d' }],
    ['sftp-download', { remotePath: '/root/.ssh/authorized_keys' }],
    ['sftp-download-file', { remotePath: '/root/.ssh/authorized_keys', localPath: 'k' }],
  ])('%s of the same paths is not refused by the built-in list', async (tool, args) => {
    const result = await call(tool, args);
    // The stubbed connection may error for its own reasons; what must not happen is
    // the never-allowed refusal, which would mean a read declared itself a write.
    expect(textOf(result)).not.toMatch(/never-allowed/);
    expect(h.auditRecords.at(-1)?.decision).not.toBe('deny');
  });

  it('a write to a benign path is not refused by the built-ins', async () => {
    const result = await call('sftp-upload', { remotePath: '/tmp/x', content: 'k' });
    expect(textOf(result)).not.toMatch(/never-allowed/);
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/tools/never-allowed-writes.test.ts`
Expected: FAIL — the four refuse rows pass through (the handlers do not declare `remoteWrite` yet).

- [ ] **Step 3: Implement**

In `src/tools/file-tools.ts`, the `sftp-upload` handler's options (line ~68):

```ts
          resource: { remotePath, remoteWrite: true },
```

In `src/tools/transfer-tools.ts`, the `sftp-upload-file` handler's options (line ~294):

```ts
          resource: { remotePath, remoteWrite: true },
```

Leave `sftp-download`, `sftp-list` and `sftp-download-file` exactly as they are, and update the
`PolicyResource` doc comment in `engine.ts` only if the wording above already says it (it does).

- [ ] **Step 4: Run the tests**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/tools/never-allowed-writes.test.ts test/unit/tools/denylist-remote-path.test.ts`
Expected: PASS — the denylist-remote-path suite must stay green (its harness calls now carry
`remoteWrite` for the two upload tools; its assertions are about operator patterns, which still run).

- [ ] **Step 5: Mutation checks**

```bash
cp src/tools/file-tools.ts /tmp/file-tools.bak; cp src/tools/transfer-tools.ts /tmp/transfer-tools.bak
```

1. Own mutant: revert `sftp-upload`'s resource to `{ remotePath }` → its two refuse rows fail.
2. Own mutant: revert `sftp-upload-file`'s resource to `{ remotePath }` → its two refuse rows fail.
3. Foreign mutant: add `remoteWrite: true` to `sftp-download`'s resource → the "read … is not refused" row for `sftp-download` fails.

Restore both files after each.

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add src/tools/file-tools.ts src/tools/transfer-tools.ts test/unit/tools/never-allowed-writes.test.ts
/usr/bin/git commit -m "feat(tools): SFTP write tools declare their remote write

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: README and SECURITY.md

**Files:**
- Modify: `README.md` (the never-allowed paragraph, ~line 596), `SECURITY.md` (the residual-risks section, ~line 231).

- [ ] **Step 1: README — replace the never-allowed paragraph**

Replace:

```markdown
A separate **forbidden** list is never allowed, whatever the role or approval
policy: `rm -rf /`, `mkfs`, `dd of=/dev/`, `shutdown`, `curl|sh`, fork bombs,
writes to `/etc/cron`, `/etc/systemd` or `authorized_keys`, `iptables -F`, and
recursive `chmod 777 /` / `chown /`. Add your own patterns via the policy
denylist; an invalid pattern fails at startup rather than degrading silently.
```

with:

```markdown
A separate **forbidden** list is never allowed, whatever the role or approval
policy: `rm -rf /`, `mkfs`, `dd of=/dev/`, `shutdown`, `curl|sh`, fork bombs,
writes naming `/etc/cron`, `/etc/systemd` or any user's `authorized_keys`,
`iptables -F`, and recursive `chmod 777 /` / `chown /`. A write *names* one of
those paths when it is the remote path of an upload tool, the target of a shell
redirect, or a destination of `tee`, `cp`, `mv`, `install` or `dd of=` — in any
spelling the path readings above resolve. Writes spelled any other way (`sed -i`,
`rsync`, a program handed to an interpreter, a path the target computes) are not
on this list; class and approval govern them, and the operator denylist can close
them. Add your own patterns via the policy denylist; an invalid pattern fails at
startup rather than degrading silently.
```

- [ ] **Step 2: SECURITY.md — add the matching residual rows**

In the "**Residual risks, recorded rather than closed:**" section, add (wording to fit the
section's existing bullet style):

```markdown
- The never-allowed write paths are refused in the forms the README lists — upload
  tools' remote path, shell redirects, and the destinations of `tee`, `cp`, `mv`,
  `install` and `dd of=`. Any other way of writing those files (`sed -i`, `rsync`,
  `truncate`, a program an interpreter reads, a path the target computes from `cd`
  or variables) classifies by verb, not by target, and is governed by class and
  approval instead. `authorized_keys2` and a non-default sshd `AuthorizedKeysFile`
  are not on the list either; the operator denylist covers them.
```

- [ ] **Step 3: Verify**

Run: `grep -n "writes naming" README.md && grep -n "never-allowed write paths" SECURITY.md`
Expected: both print one line each.

- [ ] **Step 4: Commit**

```bash
/usr/bin/git add README.md SECURITY.md
/usr/bin/git commit -m "docs: what the never-allowed list covers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Changeset and full verification

**Files:**
- Create: `.changeset/natural-mechanism.md` (any changeset-style filename).

- [ ] **Step 1: Write the changeset (neutral text)**

```markdown
---
"ssh-mcp": minor
---

fix(policy): harden the built-in never-allowed rules
```

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck`
Expected: clean.

- [ ] **Step 3: Unit suites**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy test/unit/tools`
Expected: PASS.

- [ ] **Step 4: Full suite (Docker integration servers must be up)**

Run: `COMPOSE_PROJECT_NAME=ssh-mcp npm test`
Expected: PASS. If `docker compose ps` shows the ssh-mcp test containers down, start them from the
main checkout first.

- [ ] **Step 5: e2e**

Run: `npm run build && npx vitest --run test/e2e`
Expected: PASS (these skip without `build/`, which this step just produced).

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add .changeset/natural-mechanism.md
/usr/bin/git commit -m "chore: changeset for release

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Review gate (after Task 6)

Run review-pro on the branch against the spec, verify every Medium+ finding, and clear
verified findings with the same TDD rules as above. Then report — do not push; the push
target is the advisory's temporary private fork, which the maintainer creates from the
advisory page.
