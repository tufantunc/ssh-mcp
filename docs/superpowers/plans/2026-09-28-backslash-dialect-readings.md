# Backslash dialect readings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close GHSA-972x-g47g-3922: classify a command under both shells' readings of the backslash (POSIX escape, cmd.exe literal) and hold it to the stricter class, so a backslash-spelled interpreter path can no longer reach the host with a `safe` classification.

**Architecture:** One dialect parameter (`'posix' | 'windows'`) threaded through the existing scanners and every command-taking helper in `src/policy/classifier.ts`. Two public entry points (`classifyCommand`, `findForbiddenMatch`) run the pipeline once per dialect when the command contains a backslash — otherwise once — and keep the worse result. Three fidelity fixes ride along: POSIX-accurate backslash retention inside double quotes, `stripPath` cutting on `\` as well as `/`, and `unquote` no longer re-stripping escapes the scanner already resolved.

**Tech Stack:** TypeScript (strict), vitest, changesets. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-28-backslash-dialect-readings-design.md`

## Global Constraints

- **Embargo:** GHSA-972x-g47g-3922 is draft/embargoed. Work stays in `tufantunc/ssh-mcp-ghsa-972x-g47g-3922`, branch `advisory-fix-1`. Push only `origin` (the private fork is the only remote). Nothing public.
- **Discreet public texts:** changeset text, commit messages and release-facing prose describe the *mechanics* (two dialects, stricter reading, path stripping) — never the impact ("bypass", "allowed without approval", role/tier consequences). Test files may cite the GHSA id and mechanics, like `quote-removal.test.ts` and `carrier-completeness.test.ts` do for their advisories.
- **Release:** one changeset, `"ssh-mcp": minor`.
- **No behaviour change for commands without a backslash** — the second pipeline pass is gated on `command.includes('\\')`, and the differential run (Task 4) must show zero class-rank drops against base `1ccee48`.
- **House comment style:** comments state constraints and measured behaviour, not narration. Cite advisory ids where prior code does.
- Commands: `npm run typecheck`, `npm test` (full), single file `npm test -- test/unit/policy/backslash-readings.test.ts` (vitest via npm script already sets `SSH_MCP_DISABLE_MAIN=1`).
- Line numbers below are as of `1ccee48` + the spec commit `8983b5b`; they shift as tasks land — locate by the quoted code, not only the number.

---

### Task 1: POSIX double-quote fidelity, two-separator path cut, single unescape

**Files:**
- Modify: `src/policy/classifier.ts` (`tokenizeSegmentsDetailed` loop ~916-936, `unquote` ~1315-1324, `stripPath` ~1337-1341)
- Create: `test/unit/policy/backslash-readings.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: `DOUBLE_QUOTE_ESCAPABLE` (module const, Task 2 reuses). Scanner semantics: inside double quotes a backslash is retained unless the next character is `` $ ` " \ `` or a newline. `unquote(word)` strips one surrounding quote pair only. `stripPath` cuts at the later of `/` and `\`.

- [ ] **Step 1: Write the failing tests**

Create `test/unit/policy/backslash-readings.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { classifyCommand } from '../../../src/policy/classifier.js';

/**
 * GHSA-972x-g47g-3922: a backslash is an escape to a POSIX shell and an
 * ordinary path separator to cmd.exe, and the classifier reads a command
 * without knowing which shell will run it. These suites hold it to the
 * stricter of the two readings.
 *
 * Part 1 — byte fidelity of one reading: quoted backslash words keep their
 * bytes (POSIX keeps `\x` inside double quotes before an ordinary character;
 * single quotes were always literal), and a command word's path is cut on
 * both separators before its name is looked up.
 */
const PS_PATH = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const encoded = (text: string) => Buffer.from(text, 'utf16le').toString('base64');

describe('quoted backslash words keep their bytes (GHSA-972x-g47g-3922)', () => {
  it.each([
    [`"${PS_PATH}" -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`"${PS_PATH}" -EncodedCommand ${encoded('rm -rf /etc')}`, 'destructive'],
    [`'${PS_PATH}' -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`'C:\\Windows\\pwsh.exe' -e ${encoded('sudo id')}`, 'privileged'],
    [`"\\\\server\\share\\pwsh.exe" -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
  ])('%s is %s', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });

  it('a backslash before an ordinary character survives inside double quotes', () => {
    // The operand is `C:\logs`, not `C:logs` — one operand either way for an
    // `args: 'any'` reader, so this pins the bytes without pinning a class change.
    expect(classifyCommand('cat "C:\\logs\\app.log"').class).toBe('read-only');
  });

  it('an escaped space still makes one word of one operand', () => {
    // `a\ b` is one operand to POSIX; `cat` accepts any count, so both
    // dialects of the later suite agree here. Pins the escape itself.
    expect(classifyCommand('cat a\\ b').class).toBe('read-only');
  });
});
```

- [ ] **Step 2: Run to verify the interpreter cases fail**

Run: `npm test -- test/unit/policy/backslash-readings.test.ts`
Expected: the five `it.each` cases FAIL with class `safe`; the last two `it`s PASS (they pin behaviour that already holds).

- [ ] **Step 3: Implement the scanner, `unquote` and `stripPath` changes**

In `tokenizeSegmentsDetailed`, convert the loop to indexed form and restrict the double-quote escape. Replace the loop head `for (const ch of command) {` and the two escape sites so the whole loop reads:

```ts
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) {
      // A backslash quotes the next character, so `\reboot` runs reboot. Keeping the
      // character and dropping the backslash is what the shell does.
      current += ch;
      escaped = false;
      continue;
    }
    if (quote) {
      // Backslash is literal inside single quotes; inside double quotes it escapes.
      if (ch === '\\' && quote === '"') {
        const next = command[i + 1];
        // POSIX keeps `\x` before an ordinary character: only $ ` " \ and a
        // newline are escapable, so the backslash survives into the word
        // (GHSA-972x-g47g-3922's second finding — dropping it misread both
        // dialects at once). At end of string there is no next character to
        // protect, and the open quote sends the whole scan to the fallback.
        if (next === undefined || DOUBLE_QUOTE_ESCAPABLE.has(next)) { escaped = true; continue; }
        current += ch;
        continue;
      }
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === '\\') { escaped = true; continue; }
    if (honorQuotes && (ch === '"' || ch === "'")) { quote = ch; quotedWord = true; continue; }
    if (ch === ';' || ch === '&' || ch === '|' || ch === '\n') { endSegment(ch); continue; }
    if (/\s/.test(ch)) { endWord(); continue; }
    current += ch;
  }
```

(Indexed `command[i]` iterates UTF-16 units where `for…of` iterated code points; every decision here happens at ASCII, and astral characters still concatenate to identical words.)

Add above the function:

```ts
/** Inside double quotes, the characters POSIX lets a backslash escape. */
const DOUBLE_QUOTE_ESCAPABLE = new Set(['$', '`', '"', '\\', '\n']);
```

Replace `unquote` (keep its doc comment, replace the last sentence of the summary and the body):

```ts
/**
 * Remove the quoting a shell would remove before looking up a command.
 *
 * `\sudo`, `'sudo'` and `"sudo"` all execute sudo — the backslash only
 * suppresses alias expansion — but a verbatim string comparison sees three
 * different words. Without this, a one-character edit walks around the check.
 *
 * One surrounding quote pair, and nothing else: the scanner has already
 * resolved escapes by the time a word reaches this, in both the
 * quote-honouring scan and the `honorQuotes = false` fallback, so a second
 * pass here could only remove backslashes the dialect meant to keep — the
 * literal ones inside single quotes, and the POSIX-retained ones inside
 * double quotes (GHSA-972x-g47g-3922).
 */
function unquote(word: string): string {
  return word.replace(/^(['"])(.*)\1$/, '$2');
}
```

Replace `stripPath` and its doc line:

```ts
/** `/sbin/reboot`, `C:\Windows\reboot.exe` and `reboot` are the same invocation. */
function stripPath(word: string): string {
  const cut = Math.max(word.lastIndexOf('/'), word.lastIndexOf('\\'));
  return cut === -1 ? word : word.slice(cut + 1);
}
```

- [ ] **Step 4: Run the new file and the neighbours**

Run: `npm test -- test/unit/policy/backslash-readings.test.ts test/unit/policy/quote-removal.test.ts test/unit/policy/carrier-completeness.test.ts test/unit/policy/awk.test.ts test/unit/policy/proven-read.test.ts`
Expected: all PASS. (The awk suite pins "no second unquote" and is the regression contract for the `unquote` change.)

- [ ] **Step 5: Commit**

```bash
git add src/policy/classifier.ts test/unit/policy/backslash-readings.test.ts
git commit -m "fix(policy): keep POSIX double-quote backslashes and cut paths on both separators"
```

---

### Task 2: The dialect parameter, and `classifyCommand` takes the worse reading

**Files:**
- Modify: `src/policy/classifier.ts` (scanners, glob gate, normalize cache, every command-taking helper, `classifyCommand`/`classifyOuter`, `FORBIDDEN_RULES` rule shape, `findForbiddenMatch`/`isForbidden` split)
- Modify: `test/unit/policy/backslash-readings.test.ts` (append suites)

**Interfaces:**
- Consumes: `DOUBLE_QUOTE_ESCAPABLE` from Task 1.
- Produces:
  - `type ShellDialect = 'posix' | 'windows'` (module scope, not exported)
  - `classifyCommand(command: string, depth?: number): ParsedCommand` — unchanged public signature; now worst-of-both-readings
  - `findForbiddenMatchInDialect(command: string, depth: number, dialect: ShellDialect): string | null` (module-private; Task 3's dual wrapper builds on it)
  - Every helper below gains a trailing `dialect: ShellDialect = 'posix'` parameter (defaults keep `src/guard/sanitizer.ts`'s `extractBinary` call and any other external caller compiling unchanged)

- [ ] **Step 1: Write the failing tests**

Append to `test/unit/policy/backslash-readings.test.ts`:

```ts
describe('both dialects are read; the stricter one decides (GHSA-972x-g47g-3922)', () => {
  it.each([
    // The advisory's table: every spelling of the interpreter resolves and
    // decodes, quoted or not. The backslash column was `safe` before.
    [`C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -EncodedCommand ${encoded('rm -rf /etc')}`, 'destructive'],
    [`"${PS_PATH}" -NoProfile -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`C:\\Windows\\pwsh.exe -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`\\\\server\\share\\pwsh.exe -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    [`powershell -EncodedCommand ${encoded('sudo id')}`, 'privileged'],
    // Worst case in the other direction: the POSIX reading is the worse one
    // (`\r` is an escape to POSIX, a literal to cmd.exe) and must survive.
    ['re\\boot', 'destructive'],
    ['r\\m -rf /etc', 'destructive'],
    ['\\sudo id', 'privileged'],
  ])('%s is %s', (command, expected) => {
    expect(classifyCommand(command).class, command).toBe(expected);
  });

  it('a carrier nested in a command the dialects read differently still resolves', () => {
    expect(classifyCommand(`echo $(C:\\Windows\\pwsh.exe -EncodedCommand ${encoded('sudo id')})`).class)
      .toBe('privileged');
  });

  it('an unterminated quote still falls back and still resolves under the windows reading', () => {
    expect(classifyCommand(`echo "hi; C:\\Windows\\pwsh.exe -EncodedCommand ${encoded('sudo id')}`).class)
      .toBe('privileged');
  });

  it('a grant requires every reading to qualify', () => {
    // POSIX reads one operand (`a b`); the windows reading reads two (`a\`,
    // `b`), and uniq's second positional operand is its OUTFILE — a write.
    // One reading refusing the grammar keeps the command off `read-only`.
    expect(classifyCommand('uniq a\\ b').class).toBe('safe');
  });

  it('benign windows-native paths are not punished', () => {
    expect(classifyCommand('cat C:\\logs\\app.log').class).toBe('read-only');
  });
});

describe('the engine decision the advisory measured (GHSA-972x-g47g-3922)', () => {
  // Copied from engine.test.ts so this file stands alone.
  function makeProfile(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      name: 'prod', group: 'prod', host: 'localhost', port: 22, user: 'test',
      auth: 'agent', tty: false, timeout: 60000, maxChars: 5000,
      maxOutputBytes: 1048576, role: 'operator', readOnly: false,
      announceAgent: true, approvalPolicy: 'ask-destructive', cert: false,
      sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 600000,
      sessionBackgroundMaxMs: 3600000, commandQuotaPerDay: 0,
      transferMaxBytes: 268_435_456, transferTimeoutMs: 300_000,
      ...overrides,
    };
  }

  it('operator on prod is refused for the backslash spelling, as for the others', async () => {
    const { PolicyEngine, DEFAULT_RULES } = await import('../../../src/policy/engine.js');
    const engine = new PolicyEngine(DEFAULT_RULES);
    const profile = makeProfile();
    const result = engine.evaluate(
      `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -EncodedCommand ${encoded('sudo id')}`,
      profile as never,
      'read-command',
    );
    expect(result.decision).toBe('deny');
  });
});
```

- [ ] **Step 2: Run to verify the new cases fail**

Run: `npm test -- test/unit/policy/backslash-readings.test.ts`
Expected: the first `it.each` block's backslash rows, the `$()` case, the fallback case and the engine case FAIL (currently `safe`/`allow`); `re\boot`, `r\m`, `\sudo id`, the forward-slash and bare rows, and `uniq a\ b` (currently read-only → now expected `safe`) FAIL for the new expectations. `cat C:\logs\app.log` passes only after the dialect lands (before it, the glued operand still reads `read-only`, so it passes either way — it is an over-fire guard, not a fix witness).

- [ ] **Step 3: Implement the dialect**

3a. Module type, above `firstUnquotedGlobWord`:

```ts
/**
 * How a host shell reads a backslash.
 *
 * `posix`: a backslash escapes the next character — inside double quotes,
 * only `` $ ` " \ `` or a newline. `windows`: a backslash is an ordinary
 * character everywhere, which is cmd.exe's rule; it has no backslash escapes
 * at the shell level at all.
 *
 * The classifier cannot know which shell sits at the far end of the
 * connection, so a command containing a backslash is read under both
 * dialects and held to the stricter reading (GHSA-972x-g47g-3922).
 */
type ShellDialect = 'posix' | 'windows';
```

3b. `firstUnquotedGlobWord(command: string, honorQuotes = true, dialect: ShellDialect = 'posix')` — same two edits as the scanner: gate both escape sites on `dialect === 'posix'`, and pass `dialect` through the fallback recursion (`firstUnquotedGlobWord(command, false, dialect)`):

```ts
    if (quote) {
      // Backslash is literal inside single quotes; inside double quotes it
      // escapes — the same distinction the tokeniser makes.
      if (dialect === 'posix' && ch === '\\' && quote === '"') { escaped = true; continue; }
      if (ch === quote) quote = null;
      else word += ch;
      continue;
    }
    if (dialect === 'posix' && ch === '\\') { escaped = true; continue; }
```

(In this helper the double-quote escape is not narrowed to `DOUBLE_QUOTE_ESCAPABLE`: its only job inside quotes is finding the real closing quote, and a glob character inside quotes never expands in either dialect, so the judgement cannot differ.)

3c. `tokenizeSegments(command: string, dialect: ShellDialect = 'posix')` delegating to `tokenizeSegmentsDetailed(command, true, dialect)`; `tokenizeSegmentsDetailed(command, honorQuotes = true, dialect: ShellDialect = 'posix')` — gate the two escape sites on `dialect === 'posix'` (the double-quote site keeps Task 1's `DOUBLE_QUOTE_ESCAPABLE` narrowing inside the gate) and pass `dialect` to the fallback rescan:

```ts
  if (quote !== null) return tokenizeSegmentsDetailed(command, false, dialect);
```

3d. Normalize cache, dialect-keyed — replace `lastNormalizedInput`/`lastNormalizedOutput`:

```ts
const normalizedCache = new Map<string, string>();

function normalizeCommand(command: string, dialect: ShellDialect): string {
  // One evaluate asks for this about nineteen times, once per regex rule, and each ask
  // re-ran the tokeniser over the whole command. The asks arrive in a row on the same
  // input, so a small LRU removes almost all of it. The key carries the dialect
  // because both readings of one command are asked about in the same row.
  const key = `${dialect}\u0000${command}`;
  const hit = normalizedCache.get(key);
  if (hit !== undefined) return hit;
  const value = normalizeUncached(command, dialect);
  normalizedCache.set(key, value);
  if (normalizedCache.size > 8) {
    normalizedCache.delete(normalizedCache.keys().next().value as string);
  }
  return value;
}

function normalizeUncached(command: string, dialect: ShellDialect): string {
  return tokenizeSegments(command, dialect)
    .map((words) => words.map((w) => (QUOTED_CONTENT.test(w) ? PLACEHOLDER : w)).join(' '))
    .join('; ');
}
```

and `matchesEitherForm(command: string, test: (form: string) => boolean, dialect: ShellDialect)` passing it through.

3e. `FORBIDDEN_RULES` rule shape:

```ts
interface ForbiddenRule {
  label: string;
  test: (command: string, dialect: ShellDialect) => boolean;
}
```

entries become `test: (c, dialect) => matchesEitherForm(c, (form) => re.test(form), dialect)`, `test: (command, dialect) => invokedWords(command, dialect).some((w) => FORBIDDEN_INVOCATIONS.has(w))`, `test: (c, dialect) => pipesDownloadIntoShell(c, dialect)`, and likewise `writesToDevice`/`chownsRoot`.

3f. Split `findForbiddenMatch` (behaviour-identical in this task; Task 3 dualises the wrapper):

```ts
export function findForbiddenMatch(command: string, depth = 0): string | null {
  return findForbiddenMatchInDialect(command, depth, 'posix');
}

function findForbiddenMatchInDialect(command: string, depth: number, dialect: ShellDialect): string | null {
  for (const rule of FORBIDDEN_RULES) {
    if (rule.test(command, dialect)) return rule.label;
  }
  // …the existing block comment and recursion, with
  // `rule.test` above, `nestedCommands(command, false, dialect)`, and
  // `findForbiddenMatchInDialect(inner, depth + 1, dialect)` in the loop…
}
```

`isForbidden(command: string, dialect: ShellDialect = 'posix')` delegates to `findForbiddenMatchInDialect(command, 0, dialect)` (exported signature keeps its optional-arg compatibility; there are no callers outside this file).

3g. Thread the parameter through every remaining command-taking helper — mechanical, one signature and one or two call-site edits each; the compiler finds any missed site:

| function (current line) | calls to update inside it |
|---|---|
| `nestedCommands` (1045) | `tokenizeSegmentsDetailed(command, true, dialect)` |
| `parseSegments` (1358) | `tokenizeSegments(command, dialect)` |
| `elevatedBinaryOf` (1451) | `tokenizeSegments(command, dialect)` |
| `hasDisqualifyingArgs` (1482) | `tokenizeSegments(command, dialect)` |
| `invokedWords` (1491) | `parseSegments(command, dialect)` |
| `pipesDownloadIntoShell` (1520) | `tokenizeSegmentsDetailed(command, true, dialect)` |
| `writesToDevice` (1534) | `parseSegments(command, dialect)` |
| `chownsRoot` (1546) | `parseSegments(command, dialect)` |
| `isDestructive` (1635) | `isForbidden(command, dialect)`; `matchesEitherForm(command, …, dialect)` |
| `extractBinary` (1649, exported) | `tokenizeSegments(command, dialect)` — keep the `= 'posix'` default so `src/guard/sanitizer.ts` is untouched |
| `hasDangerousAwk` (2024) | both `tokenizeSegmentsDetailed(…, true, dialect)` calls (segment loop and piped-stage rescan) |
| `hasUnreadableProgram` (2042) | `tokenizeSegmentsDetailed(command, true, dialect)` |
| `hasUnnameableCommand` (2082) | `tokenizeSegments(command, dialect)` |
| `syntheticVerb` (2133) | `tokenizeSegments(command, dialect)` |

Word-based helpers (`parseWords`, `elevatedBinary`, `effectiveCommandIndex`, `effectiveCommandWord`, `operandsAreData`, `awkFindings`, `programAfterFlag`, `readsProgramFromStdin`, `resolveInterpreter`, `stripPath`, `unquote`) take no parameter: they already consume one reading's words.

3h. `classifyOuter(trimmed: string, dialect: ShellDialect)` — pass `dialect` to `extractBinary`, `elevatedBinaryOf`, `hasUnreadableProgram`, `hasDangerousAwk`, `isDestructive`, `hasDisqualifyingArgs`, `hasUnnameableCommand`, `tokenizeSegments`, `firstUnquotedGlobWord(fullCommand, true, dialect)`.

3i. `classifyCommand` split:

```ts
export function classifyCommand(command: string, depth = 0): ParsedCommand {
  // One string, two dialects, and the class is the worse of the two readings:
  // the classifier cannot know whether the host shell reads a backslash as an
  // escape or as a path separator, so policy must hold on whichever host
  // receives the command (GHSA-972x-g47g-3922). A command without a backslash
  // is byte-identical under both dialects, so it keeps the single pass.
  if (!command.includes('\\')) return classifyCommandInDialect(command, depth, 'posix');
  const posix = classifyCommandInDialect(command, depth, 'posix');
  const windows = classifyCommandInDialect(command, depth, 'windows');
  return CLASS_RANK[windows.class] > CLASS_RANK[posix.class] ? windows : posix;
}

function classifyCommandInDialect(command: string, depth: number, dialect: ShellDialect): ParsedCommand {
  // …the entire existing body, with:
  //   classifyOuter(trimmed, dialect)
  //   syntheticVerb(trimmed, dialect)
  //   nestedCommands(trimmed, true, dialect)
  // and the recursion staying in-dialect:
  //   classifyCommandInDialect(inner, depth + 1, dialect)
```

The recursion deliberately does not re-enter the dual wrapper: the wrapper has already run both dialects over the whole string, and a substring of a backslash-free command cannot contain a backslash, so the gate is safe at every depth while the work stays linear.

- [ ] **Step 4: Run the classification suites**

Run: `npm test -- test/unit/policy/`
Expected: all PASS, including `quote-removal`, `carrier-completeness`, `elevation-hiding`, `variable-command-word`, `readonly-guarantee`, `engine`. One **intended** pin change in `proven-read`: `sort /var/log/\*` falls `read-only` → `safe` — the windows reading sees a literal backslash before an unquoted glob character, and a grant must qualify in every reading (the spec's glob-gate rule). Update that pin in the same commit with a one-line rationale comment.

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: no errors (this is the checklist that every call site got the parameter).

- [ ] **Step 6: Commit**

```bash
git add src/policy/classifier.ts test/unit/policy/backslash-readings.test.ts
git commit -m "fix(policy): classify both shell dialects' reading of a backslash"
```

---

### Task 3: The denylist reads both dialects too

**Files:**
- Modify: `src/policy/classifier.ts` (`findForbiddenMatch` wrapper only)
- Modify: `test/unit/policy/backslash-readings.test.ts` (append suite)

**Interfaces:**
- Consumes: `findForbiddenMatchInDialect` from Task 2.
- Produces: `findForbiddenMatch(command, depth)` public behaviour — a refusal under either dialect's reading.

- [ ] **Step 1: Write the failing tests**

Append:

```ts
describe('the never-allowed list reads both dialects (GHSA-972x-g47g-3922)', () => {
  it('an encoded forbidden invocation behind a backslash path is refused', () => {
    const command = `echo $(C:\\Windows\\pwsh.exe -EncodedCommand ${encoded('shutdown -r')})`;
    expect(findForbiddenMatch(command)).not.toBeNull();
  });

  it('the POSIX reading of an escaped name still refuses', () => {
    expect(findForbiddenMatch('sh\\utdown -h now')).not.toBeNull();
  });

  it('an ordinary windows path does not trip the list', () => {
    expect(findForbiddenMatch('cat C:\\Users\\anne\\notes.txt')).toBeNull();
  });
});
```

Add `findForbiddenMatch` to the import from `../../../src/policy/classifier.js`.

- [ ] **Step 2: Run to verify the first case fails**

Run: `npm test -- test/unit/policy/backslash-readings.test.ts`
Expected: the `$()` case FAILS (returns null today: `speculativeOperands: false`, and the POSIX-glued interpreter word resolves nothing). The other two PASS already — they pin no-regression.

- [ ] **Step 3: Dualise the wrapper**

```ts
export function findForbiddenMatch(command: string, depth = 0): string | null {
  // The engine calls this directly, so it is a decision point of its own and
  // reads both dialects like `classifyCommand` does: a refusal under either
  // reading is a refusal. The destructive-class consultation *inside* a
  // dialect pass (`isDestructive`) stays in-dialect — that pass is already one
  // reading of the whole string.
  if (command.includes('\\')) {
    const windows = findForbiddenMatchInDialect(command, depth, 'windows');
    if (windows !== null) return windows;
  }
  return findForbiddenMatchInDialect(command, depth, 'posix');
}
```

- [ ] **Step 4: Run the policy suites and typecheck**

Run: `npm test -- test/unit/policy/ && npm run typecheck`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/policy/classifier.ts test/unit/policy/backslash-readings.test.ts
git commit -m "fix(policy): the denylist reads both dialects too"
```

---

### Task 4: Differential run against the branch base — no class may drop

**Files:**
- Create: `scripts/extract-corpus.mjs`
- Create: `test/differential/runner.test.ts`
- Create: `test/differential/corpus.json` (generated, committed)
- Create: `scripts/differential-compare.mjs`
- Create: `scripts/differential-run.sh` (executable)

**Interfaces:**
- Consumes: `classifyCommand` (head) and base `1ccee48`'s `classifyCommand` (via a temporary worktree).
- Produces: `test/differential/corpus.json`; printed differential report. Success = exit 0 from `scripts/differential-run.sh` (zero rank drops). The report's deltas (rises) are quoted in the final summary; drops are bugs to fix before Task 5.

- [ ] **Step 1: Write the corpus extractor**

`scripts/extract-corpus.mjs`:

```js
#!/usr/bin/env node
// Builds the differential corpus: every quoted literal in the policy suites
// (each is a valid classification probe, whatever it was written for), plus
// deterministic backslash rewrites of each, so the run covers inputs the
// suites never wrote on purpose. Output is sorted and de-duplicated so the
// same corpus can be classified by two revisions of the tree.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dir = new URL('../test/unit/policy/', import.meta.url);
const entries = new Set();

for (const file of readdirSync(dir)) {
  if (!file.endsWith('.test.ts')) continue;
  const text = readFileSync(join(dir.pathname, file), 'utf8');
  for (const m of text.matchAll(/'((?:[^'\\\n]|\\.)*)'/g)) entries.add(m[1]);
  for (const m of text.matchAll(/"((?:[^"\\\n]|\\.)*)"/g)) entries.add(m[1]);
}

const probes = new Set();
for (const literal of entries) {
  probes.add(literal);
  if (literal.length === 0 || literal.length > 100) continue;
  if (/['"\\\n]/.test(literal)) continue;   // variants stay single-token-simple
  probes.add(literal.replaceAll('/', '\\'));
  const firstSpace = literal.indexOf(' ');
  const first = firstSpace === -1 ? literal : literal.slice(0, firstSpace);
  const rest = firstSpace === -1 ? '' : literal.slice(firstSpace);
  if (!first.includes('/')) {
    const exe = first.includes('.') ? first : `${first}.exe`;
    probes.add(`C:\\Windows\\System32\\${exe}${rest}`);
    probes.add(`"${first}"${rest}`);
    if (first.length > 1) probes.add(`${first.slice(0, 1)}\\${first.slice(1)}${rest}`);
  }
}

const corpus = [...probes].sort();
writeFileSync(new URL('../test/differential/corpus.json', import.meta.url), `${JSON.stringify(corpus, null, 1)}\n`);
console.log(`corpus: ${corpus.length} probes from ${entries.size} literals`);
```

- [ ] **Step 2: Generate the corpus**

Run: `mkdir -p test/differential && node scripts/extract-corpus.mjs`
Expected: prints a probe count in the thousands; `test/differential/corpus.json` exists.

- [ ] **Step 3: Write the runner, comparator and driver**

`test/differential/runner.test.ts`:

```ts
import { readFileSync, writeFileSync } from 'node:fs';
import { describe, it } from 'vitest';
import { classifyCommand } from '../../src/policy/classifier.js';

// Not part of any test run: the differential driver points
// SSH_MCP_DIFFERENTIAL_OUT at a file and this classifies the corpus into it,
// so the same corpus can be classified by two revisions of the tree and
// compared (scripts/differential-run.sh).
const suite = describe.skipIf(!process.env.SSH_MCP_DIFFERENTIAL_OUT);

suite('differential corpus', () => {
  it('classifies every probe', () => {
    const corpus: string[] = JSON.parse(
      readFileSync(new URL('./corpus.json', import.meta.url), 'utf8'),
    );
    const out: Record<string, string> = Object.create(null);
    for (const command of corpus) out[command] = classifyCommand(command).class;
    if (Object.keys(out).length !== corpus.length) {
      throw new Error(`differential runner lost entries: ${corpus.length} probes, ${Object.keys(out).length} recorded`);
    }
    writeFileSync(process.env.SSH_MCP_DIFFERENTIAL_OUT!, JSON.stringify(out, null, 1));
  });
});
```

`scripts/differential-compare.mjs`:

```js
#!/usr/bin/env node
// Compares two differential runs. The invariant of this branch: a command's
// class either stays or rises — nothing drops (a stricter reading may cost an
// approval; it may never cost a refusal).
import { readFileSync } from 'node:fs';

const RANK = { 'read-only': 0, safe: 1, destructive: 2, privileged: 3 };
const [baseFile, headFile] = process.argv.slice(2);
if (!baseFile || !headFile) {
  console.error('usage: differential-compare.mjs <base.json> <head.json>');
  process.exit(2);
}
const base = JSON.parse(readFileSync(baseFile, 'utf8'));
const head = JSON.parse(readFileSync(headFile, 'utf8'));

let same = 0;
const rises = [];
const drops = [];
for (const command of Object.keys(base)) {
  const before = base[command];
  const after = head[command];
  if (after === undefined) { drops.push([command, before, '(absent)']); continue; }
  if (RANK[after] === RANK[before]) { same++; continue; }
  (RANK[after] > RANK[before] ? rises : drops).push([command, before, after]);
}

for (const [command, before, after] of rises) console.log(`RISE  ${before} -> ${after}  ${command}`);
for (const [command, before, after] of drops) console.log(`DROP  ${before} -> ${after}  ${command}`);
console.log(`\n${same} unchanged, ${rises.length} risen, ${drops.length} dropped`);
process.exit(drops.length === 0 ? 0 : 1);
```

`scripts/differential-run.sh`:

```bash
#!/usr/bin/env bash
# Differential classification run: the branch base vs the working tree.
# Usage: scripts/differential-run.sh [base-ref]   (default 1ccee48)
set -euo pipefail
BASE_REF="${1:-1ccee48}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ssh-mcp-diff.XXXXXX")"
git -C "$ROOT" worktree add --detach "$WORK/base" "$BASE_REF"
trap 'git -C "$ROOT" worktree remove --force "$WORK/base" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

# The base tree classifies the SAME corpus with its own sources and this
# tree's dependencies: same runner, same corpus, one symlink.
mkdir -p "$WORK/base/test/differential"
cp "$ROOT/test/differential/corpus.json" "$WORK/base/test/differential/"
cp "$ROOT/test/differential/runner.test.ts" "$WORK/base/test/differential/"
ln -s "$ROOT/node_modules" "$WORK/base/node_modules"

(cd "$ROOT" && SSH_MCP_DISABLE_MAIN=1 SSH_MCP_DIFFERENTIAL_OUT="$WORK/out-head.json" \
  npx vitest --run test/differential/runner.test.ts >/dev/null)
(cd "$WORK/base" && SSH_MCP_DISABLE_MAIN=1 SSH_MCP_DIFFERENTIAL_OUT="$WORK/out-base.json" \
  npx vitest --run test/differential/runner.test.ts >/dev/null)

node "$ROOT/scripts/differential-compare.mjs" "$WORK/out-base.json" "$WORK/out-head.json"
```

- [ ] **Step 4: Run the differential**

Run: `chmod +x scripts/differential-run.sh && ./scripts/differential-run.sh 1ccee48`
Expected: exit 0; `N unchanged, M risen, 0 dropped`. The risen set is the fix working (backslash interpreter spellings and their variants). If any DROP appears: investigate before proceeding — a drop is either a defect in this branch or an intended, defensible exception that must be recorded in the changeset (the qmx6 precedent) and justified in the commit message of the fix that caused it.

- [ ] **Step 5: Verify the runner is inert in normal runs**

Run: `npm test -- test/differential/`
Expected: no tests collected / skipped (skipIf gate), suite green overall.

- [ ] **Step 6: Commit**

```bash
git add scripts/extract-corpus.mjs scripts/differential-compare.mjs scripts/differential-run.sh \
        test/differential/corpus.json test/differential/runner.test.ts
git commit -m "test(policy): differential harness holding class rank against the branch base"
```

---

### Task 5: Changeset and full verification

**Files:**
- Create: `.changeset/backslash-readings.md`

**Interfaces:** none (release metadata).

- [ ] **Step 1: Write the changeset**

`.changeset/backslash-readings.md`:

```md
---
"ssh-mcp": minor
---

Policy: command classification reads a command under both shell dialects a target host may run — POSIX and cmd.exe — and holds it to the stricter reading when they disagree, instead of assuming the POSIX one. Path stripping now accepts backslash-separated command words, and quote removal inside double quotes follows POSIX byte for byte (a backslash before an ordinary character is kept). Commands without a backslash classify exactly as before.
```

(Discreet by constraint: mechanics only, no impact narrative.)

- [ ] **Step 2: Full verification**

Run: `npm run typecheck && npm test`
Expected: typecheck clean; full suite green.

- [ ] **Step 3: Commit**

```bash
git add .changeset/backslash-readings.md
git commit -m "chore(changeset): backslash dialect readings"
```

---

### Task 6: Final whole-branch review and push

**Files:** none created (review; fixes if the review finds defects, then re-verify).

- [ ] **Step 1: Whole-branch review with the strongest available model**

Review `1ccee48..HEAD` against the spec: correctness of both dialects' semantics, every tokenizer consumer covered, the no-drop invariant, discreet public texts, test quality. Dispatch the reviewer with the strongest model available (`ListModels`); fix what it finds and re-run Task 4's differential plus the full suite.

- [ ] **Step 2: Push**

```bash
git push origin advisory-fix-1
```

Only `origin` — the private fork. Never the public repository.
