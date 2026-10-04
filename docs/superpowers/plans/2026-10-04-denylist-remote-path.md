# Denylist sees the SFTP remote path — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `[policy].denylist` patterns are also tested against the remote path of the five SFTP tools, as given and lexically normalized, so an operator's path rule stops depending on the string this server composes (#230).

**Architecture:** A pure `normalizeRemotePath` in a new module; `PolicyEngine.evaluate`/`evaluateWithOpa` take an optional `{ remotePath }` subject that `findDenyMatch` tests operator patterns against and OPA receives as `resource.remotePath`; the tool pipeline carries `remotePath` from each SFTP tool to the engine.

**Tech Stack:** TypeScript (ESM, `.js` import suffixes), vitest, zod. Node ≥ 20.

**Spec:** `docs/superpowers/specs/2026-10-04-denylist-remote-path-design.md`

## Global Constraints

- Work in worktree `/Users/tufantunc/Desktop/Projects/Personal/ssh-mcp/.claude/worktrees/issue-230`, branch `worktree-issue-230-denylist-remote-path`. `node_modules` there is an untracked symlink: never `git add` it.
- Scope is the operator `[policy].denylist`. In `findDenyMatch`, only the operator-pattern loop changes; the block above it stays byte for byte.
- Every test is written first and seen to fail for the stated reason; a test counts only once it fails with its production line removed (mutation check on a backup copy, then restore). No wall-clock waits.
- Unit tests run with `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run <file>`. Typecheck: `npm run typecheck`. Full suite: `COMPOSE_PROJECT_NAME=ssh-mcp npm test` (needs Docker; the integration servers must be up). E2E: `npm run build && npx vitest --run test/e2e`.
- Matching is case-sensitive; nothing is resolved on the target; local paths are never tested.
- Release is **minor** (a previously allowed call can now be refused).
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. A path that is already normal — the refusal must not say "read as", and the normalized form is not tested twice. Pinned in Task 2.
2. A Windows backslash path (`C:\Users\a\.ssh\authorized_keys`) with the README's advised rule `\.ssh/authorized_keys$` — must deny through the normalized form. Pinned in Task 2.
3. A relative path (`.ssh/authorized_keys`) with the advised trailing-segment rule — must deny, because that is what the README tells operators to rely on. Pinned in Task 2.
4. A call whose command string and path both match — the message stays the command form, so an existing operator sees the same refusal text as before. Pinned in Task 2.
5. A configured denylist that matches nothing and a remote path present — the call is not refused. Pinned in Task 2.

---

### Task 1: `normalizeRemotePath`

**Files:**
- Create: `src/policy/remote-path.ts`
- Test: `test/unit/policy/remote-path.test.ts` (new)

**Interfaces:**
- Produces: `export function normalizeRemotePath(path: string): string` — pure, no I/O.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { normalizeRemotePath } from '../../../src/policy/remote-path.js';

describe('normalizeRemotePath', () => {
  it.each([
    ['/root//.ssh/authorized_keys', '/root/.ssh/authorized_keys'],
    ['/root/./.ssh/x', '/root/.ssh/x'],
    ['/srv/x/../../root/.ssh/authorized_keys', '/root/.ssh/authorized_keys'],
    ['/../etc/passwd', '/etc/passwd'],
    ['../../x', '../../x'],
    ['a/../../x', '../x'],
    ['/srv/data/', '/srv/data'],
    ['/', '/'],
    ['C:\\Users\\a\\.ssh\\authorized_keys', 'C:/Users/a/.ssh/authorized_keys'],
    ['C:\\Users\\a/.ssh\\..\\x', 'C:/Users/a/x'],
    ['C:/../x', 'C:/x'],
  ])('reads %s as %s', (input, expected) => {
    expect(normalizeRemotePath(input)).toBe(expected);
  });

  it.each(['/srv/backup.tar', '.ssh/authorized_keys', 'C:/Users/a', 'x'])(
    'returns an already-normal path unchanged: %s',
    (path) => {
      expect(normalizeRemotePath(path)).toBe(path);
    },
  );
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/remote-path.test.ts`
Expected: FAIL — cannot resolve `../../../src/policy/remote-path.js`.

- [ ] **Step 3: Write the implementation**

```ts
/**
 * A remote path as a `[policy].denylist` pattern should also see it (#230).
 *
 * Lexical only: nothing is asked of the target, so a relative path stays relative and a
 * symlink is not followed. What it removes is the spelling that keeps a rule from seeing
 * a path it was written for — `//`, `/./`, `..`, a trailing separator — and it reads `\`
 * as a separator too, so a Windows target's `C:\Users\a\.ssh\authorized_keys` is also
 * seen as `C:/Users/a/.ssh/authorized_keys`. On a POSIX target a filename containing `\`
 * can then match where it did not before; that only ever widens a refusal.
 *
 * An absolute path — `/…`, or one starting with a drive letter — cannot climb above its
 * root. A relative path keeps a leading `..` it has nothing to resolve against.
 */
const DRIVE_LETTER = /^[A-Za-z]:$/;

export function normalizeRemotePath(path: string): string {
  const segments = path.replace(/\\/g, '/').split('/');
  let root: string | null = null;
  if (segments[0] === '') {
    root = '';
    segments.shift();
  } else if (DRIVE_LETTER.test(segments[0])) {
    root = segments.shift()!;
  }

  const kept: string[] = [];
  for (const segment of segments) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (kept.length > 0 && kept[kept.length - 1] !== '..') kept.pop();
      else if (root === null) kept.push('..');
      continue;
    }
    kept.push(segment);
  }

  if (root === null) return kept.length > 0 ? kept.join('/') : '.';
  return `${root}/${kept.join('/')}`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/remote-path.test.ts`
Expected: PASS (15 tests).

- [ ] **Step 5: Mutation check**

On a backup copy of `src/policy/remote-path.ts`, one at a time, confirm at least one test fails, then restore:
- drop `.replace(/\\/g, '/')`
- drop the `DRIVE_LETTER` branch
- `if (segment === '' || segment === '.') continue;` → `if (segment === '') continue;`
- `else if (root === null) kept.push('..');` → delete the line
- `kept[kept.length - 1] !== '..'` → `true`

- [ ] **Step 6: Commit**

```bash
git add src/policy/remote-path.ts test/unit/policy/remote-path.test.ts
git commit -m "feat(policy): read a remote path the way a denylist rule should see it (#230)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: The engine tests operator patterns against the remote path, and OPA receives it

**Files:**
- Modify: `src/policy/engine.ts` — `evaluate` (≈ line 278), `evaluateWithOpa` (≈ line 352), `findDenyMatch` (≈ line 566), imports
- Test: `test/unit/policy/engine.test.ts`, `test/unit/policy/opa.test.ts`

**Interfaces:**
- Consumes: `normalizeRemotePath(path: string): string` from Task 1.
- Produces:
  - `export interface PolicySubject { remotePath?: string }` in `src/policy/engine.ts`
  - `evaluate(command: string, profile: Profile, _toolName: string, subject: PolicySubject = {}): PolicyEvaluation`
  - `evaluateWithOpa(command: string, profile: Profile, toolName: string, subject: PolicySubject = {}): Promise<PolicyEvaluation>`
  - OPA `input.resource.remotePath` present only when `subject.remotePath` is defined.

- [ ] **Step 1: Write the failing engine tests**

Append inside `describe('PolicyEngine', …)` in `test/unit/policy/engine.test.ts`, after the `describe('denylist refusals say what matched', …)` block:

```ts
  /**
   * #230: the SFTP tools' command string is one this server composes, so a rule written
   * for the path stopped matching whenever the path was not where the rule expected it.
   * The pattern now also sees the path itself.
   */
  describe('denylist sees the remote path', () => {
    const profile = makeProfile({ role: 'admin', name: 'dev', group: 'dev', approvalPolicy: 'auto' });
    const withDeny = (...denylist: string[]) => new PolicyEngine({ ...DEFAULT_RULES, denylist });
    const uploadFile = (remote: string) => `sftp:upload-file ${remote} --overwrite <- ./k`;

    it('refuses when the path matches, wherever the composed string puts it', () => {
      const path = '/root/.ssh/authorized_keys';
      const result = withDeny('authorized_keys$').evaluate(uploadFile(path), profile, 'sftp-upload-file', { remotePath: path });
      expect(result.decision).toBe('deny');
      expect(result.ruleId).toBe('denylist');
      expect(result.reason).toContain('Remote path "/root/.ssh/authorized_keys" matches /authorized_keys$/');
      expect(result.reason).toMatch(/\[policy\]\.denylist/);
      // Already normal, so there is no second reading to report.
      expect(result.reason).not.toContain('read as');
    });

    it('refuses when only the normalized path matches, and shows that reading', () => {
      const path = '/srv/x/../../root/.ssh/authorized_keys';
      const result = withDeny('^/root/\\.ssh/').evaluate(uploadFile(path), profile, 'sftp-upload-file', { remotePath: path });
      expect(result.decision).toBe('deny');
      expect(result.reason).toContain(`Remote path "${path}" (read as "/root/.ssh/authorized_keys")`);
    });

    it('catches a Windows path with the trailing-segment rule the README advises', () => {
      const path = 'C:\\Users\\a\\.ssh\\authorized_keys';
      const result = withDeny('\\.ssh/authorized_keys$').evaluate(uploadFile(path), profile, 'sftp-upload-file', { remotePath: path });
      expect(result.decision).toBe('deny');
      expect(result.reason).toContain('read as "C:/Users/a/.ssh/authorized_keys"');
    });

    it('catches a relative path with the trailing-segment rule the README advises', () => {
      const path = '.ssh/authorized_keys';
      const result = withDeny('\\.ssh/authorized_keys$').evaluate(uploadFile(path), profile, 'sftp-upload-file', { remotePath: path });
      expect(result.decision).toBe('deny');
    });

    it('keeps the command wording when the command string matches too', () => {
      const path = '/root/.ssh/authorized_keys';
      const result = withDeny('authorized_keys').evaluate(`sftp:list ${path}`, profile, 'sftp-list', { remotePath: path });
      expect(result.reason).toMatch(/^Command matches \/authorized_keys\//);
    });

    it('still honours a rule anchored on the whole composed string', () => {
      const path = '/srv/data';
      const result = withDeny('^sftp:upload-file ').evaluate(uploadFile(path), profile, 'sftp-upload-file', { remotePath: path });
      expect(result.decision).toBe('deny');
      expect(result.reason).toMatch(/^Command matches/);
    });

    it('tests nothing beyond the command string when no path is passed', () => {
      const result = withDeny('^/root/').evaluate('sftp:list /root/x', profile, 'sftp-list');
      expect(result.decision).toBe('allow');
    });

    it('does not refuse a path no pattern matches', () => {
      const path = '/srv/backup.tar';
      const result = withDeny('authorized_keys$', '^/root/').evaluate(`sftp:list ${path}`, profile, 'sftp-list', { remotePath: path });
      expect(result.decision).toBe('allow');
    });
  });
```

- [ ] **Step 2: Write the failing OPA test**

In `test/unit/policy/opa.test.ts`, after `it('sends the subject, action, resource and context the policy is written against', …)`:

```ts
  // #230: a rego rule can match the path of an SFTP tool without parsing our string.
  it('sends the remote path as its own field when there is one, and omits it otherwise', async () => {
    await startOpa(() => ({ body: { result: true } }));
    const engine = new PolicyEngine(DEFAULT_RULES);
    engine.setOpaUrl(url);

    await engine.evaluateWithOpa('sftp:list /srv/data', makeProfile(), 'sftp-list', { remotePath: '/srv/data' });
    await engine.evaluateWithOpa('ls -la', makeProfile(), 'read-command');

    expect(requests).toHaveLength(2);
    expect(requests[0].input.resource.remotePath).toBe('/srv/data');
    expect(requests[1].input.resource).not.toHaveProperty('remotePath');
  });
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/engine.test.ts test/unit/policy/opa.test.ts`
Expected: the path-only tests FAIL (`expected 'allow' to be 'deny'`), the OPA test FAILS (`remotePath` undefined). `tests nothing beyond…`, `still honours…`, `keeps the command wording…` and `does not refuse…` pass already — they are guards, not REDs. Typecheck may also flag the fourth argument; that is expected.

- [ ] **Step 4: Implement**

In `src/policy/engine.ts`:

Add the import next to the classifier import:

```ts
import { normalizeRemotePath } from './remote-path.js';
```

Add, above `export class PolicyEngine`:

```ts
/**
 * What a call acts on, beyond its command string. Only the SFTP tools pass anything:
 * their command string is one this server composes, so a `[policy].denylist` rule
 * written for the path is also tested against the path itself (#230).
 */
export interface PolicySubject {
  remotePath?: string;
}
```

Change `evaluate`'s signature and its deny lookup:

```ts
  evaluate(
    command: string,
    profile: Profile,
    _toolName: string,
    subject: PolicySubject = {},
  ): PolicyEvaluation {
```

```ts
    const denied = this.findDenyMatch(command, subject.remotePath);
```

Change `evaluateWithOpa`:

```ts
  async evaluateWithOpa(
    command: string,
    profile: Profile,
    toolName: string,
    subject: PolicySubject = {},
  ): Promise<PolicyEvaluation> {
    const local = this.evaluate(command, profile, toolName, subject);
```

and its `resource` line:

```ts
        resource: {
          command: parsed.fullCommand,
          binary: parsed.binary,
          host: profile.host,
          ...(subject.remotePath !== undefined ? { remotePath: subject.remotePath } : {}),
        },
```

Replace the operator-pattern loop in `findDenyMatch` (the built-in block above it is untouched):

```ts
  private findDenyMatch(command: string, remotePath?: string): string | null {
    const builtIn = findForbiddenMatch(command);
    if (builtIn) {
      return `Command matches a built-in never-allowed rule: ${builtIn}. ` +
        `This list cannot be switched off — the [policy].denylist key adds patterns, it does not remove these.`;
    }

    // The path is tested on its own as well as inside the command string, because for the
    // SFTP tools that string is ours to lay out and a rule written for the path should not
    // depend on where we put it (#230).
    const normalized = remotePath === undefined ? undefined : normalizeRemotePath(remotePath);
    const fromConfig = 'a pattern from [policy].denylist in your config file. Remove or narrow it there to allow this command.';
    for (const pattern of this.userPatterns) {
      if (pattern.test(command)) {
        return `Command matches /${pattern.source}/, ${fromConfig}`;
      }
      if (remotePath === undefined) continue;
      if (pattern.test(remotePath)) {
        return `Remote path ${JSON.stringify(remotePath)} matches /${pattern.source}/, ${fromConfig}`;
      }
      if (normalized !== remotePath && pattern.test(normalized!)) {
        return `Remote path ${JSON.stringify(remotePath)} (read as ${JSON.stringify(normalized)}) ` +
          `matches /${pattern.source}/, ${fromConfig}`;
      }
    }

    return null;
  }
```

The command-form message text is unchanged from today (`Command matches /p/, a pattern from [policy].denylist in your config file. Remove or narrow it there to allow this command.`); check it byte for byte against the old line before committing.

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/policy/engine.test.ts test/unit/policy/opa.test.ts && npm run typecheck`
Expected: PASS, typecheck clean.

- [ ] **Step 6: Mutation check**

On a backup of `src/policy/engine.ts`, one at a time, confirm a test fails, then restore:
- `this.findDenyMatch(command, subject.remotePath)` → `this.findDenyMatch(command)`
- delete the `if (pattern.test(remotePath))` block
- delete the `normalized !== remotePath && pattern.test(normalized!)` block
- `normalized !== remotePath &&` removed is an **equivalent mutant**: when the two forms are equal the raw test has already decided, so the guard only saves a regex run. Record it as such rather than writing a test for it.
- in `evaluateWithOpa`, `this.evaluate(command, profile, toolName, subject)` → `this.evaluate(command, profile, toolName)`
- delete the `...(subject.remotePath !== undefined ? …)` spread
- spread condition → always include (`remotePath: subject.remotePath`)

- [ ] **Step 7: Commit**

```bash
git add src/policy/engine.ts test/unit/policy/engine.test.ts test/unit/policy/opa.test.ts
git commit -m "feat(policy): test denylist patterns against the remote path too, and send it to OPA (#230)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: The pipeline carries the remote path from the five SFTP tools

**Files:**
- Modify: `src/tools/pipeline.ts` — `AuditedOpts` (≈ line 237), `checkPolicyAndApprove` (≈ line 80), the call in `runAudited` (≈ line 299), imports
- Modify: `src/tools/transfer-tools.ts` — `sftp-list` (≈ 232), `sftp-upload-file` (≈ 293), `sftp-download-file` (≈ 362)
- Modify: `src/tools/file-tools.ts` — `sftp-upload` (≈ 69), `sftp-download` (≈ 101)
- Modify: `test/unit/tools/harness.ts` — `createHarness` gains a third parameter
- Test: `test/unit/tools/denylist-remote-path.test.ts` (new)

**Interfaces:**
- Consumes: `PolicySubject`, `evaluateWithOpa(command, profile, toolName, subject)` from Task 2.
- Produces: `AuditedOpts.remotePath?: string`; `createHarness(overrides?: Partial<Profile>, toolOpts?: ToolOpts, rules?: PolicyRules)`.

- [ ] **Step 1: Give the harness a policy-rules parameter**

In `test/unit/tools/harness.ts`, change the engine import and `createHarness`:

```ts
import { PolicyEngine, DEFAULT_RULES, type PolicyRules } from '../../../src/policy/engine.js';
```

```ts
export async function createHarness(
  overrides: Partial<Profile> = {},
  toolOpts: ToolOpts = {},
  rules: PolicyRules = DEFAULT_RULES,
): Promise<Harness> {
```

```ts
  registerTools(server, registry, new PolicyEngine(rules), audit, toolOpts);
```

(`createUnconfiguredHarness` is unchanged.)

- [ ] **Step 2: Write the failing tool-level test**

Create `test/unit/tools/denylist-remote-path.test.ts`:

```ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHarness, textOf, type Harness } from './harness.js';
import { DEFAULT_RULES } from '../../../src/policy/engine.js';

/**
 * #230 through the real tool handlers: every SFTP tool hands its remote path to the
 * engine, so a denylist rule written for the path refuses it whatever the composed
 * string looks like. A tool that stops passing its path fails its own row.
 */
const IS_WINDOWS = process.platform === 'win32';
const ADMIN_AUTO = { role: 'admin' as const, approvalPolicy: 'auto' as const };

let h: Harness;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'ssh-mcp-deny-path-'));
  await chmod(root, 0o700);
});

afterEach(async () => {
  await h?.close();
  await rm(root, { recursive: true, force: true });
});

const TOOLS: Array<{ name: string; args: (remotePath: string) => Record<string, unknown> }> = [
  { name: 'sftp-list', args: (remotePath) => ({ remotePath }) },
  { name: 'sftp-download', args: (remotePath) => ({ remotePath }) },
  { name: 'sftp-upload', args: (remotePath) => ({ remotePath, content: 'k' }) },
  { name: 'sftp-upload-file', args: (remotePath) => ({ remotePath, localPath: 'k' }) },
  { name: 'sftp-download-file', args: (remotePath) => ({ remotePath, localPath: 'k' }) },
];

async function callWith(denylist: string[], tool: (typeof TOOLS)[number], remotePath: string) {
  h = await createHarness(ADMIN_AUTO, { localPath: { transferRoot: root } }, { ...DEFAULT_RULES, denylist });
  return h.client.callTool({ name: tool.name, arguments: tool.args(remotePath) }) as Promise<any>;
}

describe('a denylist rule written for the path refuses every SFTP tool', () => {
  // sftp-list, sftp-download and sftp-upload end their string with the path, so the
  // command string matches first and keeps its wording; the two streaming tools end
  // with the local path, which is the #230 gap.
  it.each(TOOLS)('$name: refused when the path as given matches', async (tool) => {
    const result = await callWith(['authorized_keys$'], tool, '/root/.ssh/authorized_keys');
    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toMatch(/matches \/authorized_keys\$\//);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  it.each(TOOLS.filter((t) => t.name.endsWith('-file')))(
    '$name: the refusal names the remote path, since the composed string ends with the local one',
    async (tool) => {
      const result = await callWith(['authorized_keys$'], tool, '/root/.ssh/authorized_keys');
      expect(textOf(result)).toContain('Remote path "/root/.ssh/authorized_keys" matches /authorized_keys$/');
    },
  );

  it.each(TOOLS)('$name: refused when only the normalized path matches', async (tool) => {
    const result = await callWith(['^/root/\\.ssh/'], tool, '/srv/x/../../root/.ssh/authorized_keys');
    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toContain('read as "/root/.ssh/authorized_keys"');
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  // Skipped on Windows like the other transfer-root tests: the call gets past the policy
  // and into the local-path layer, whose permission checks differ there.
  it.skipIf(IS_WINDOWS)('does not test the local path', async () => {
    h = await createHarness(ADMIN_AUTO, { localPath: { transferRoot: root } }, { ...DEFAULT_RULES, denylist: ['authorized_keys$'] });
    const result = await h.client.callTool({
      name: 'sftp-download-file',
      arguments: { remotePath: '/srv/backup.tar', localPath: 'authorized_keys' },
    }) as any;
    // The stubbed connection has no SFTP channel, so the transfer itself fails; what
    // matters is that the policy did not refuse it.
    expect(textOf(result)).not.toContain('POLICY_DENIED');
    expect(h.auditRecords.at(-1)?.ruleId).not.toBe('denylist');
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/tools/denylist-remote-path.test.ts`
Expected RED, and only this:
- `refused when the path as given matches` fails for `sftp-upload-file` and `sftp-download-file` (today's #230 gap) and passes for the other three (guards);
- `the refusal names the remote path` fails for both streaming tools;
- `refused when only the normalized path matches` fails for all five;
- `does not test the local path` passes (guard).

If any row fails for another reason (for example the stub erroring before the policy runs), fix the test, not the code.

- [ ] **Step 4: Implement**

`src/tools/pipeline.ts` — import the type:

```ts
import type { PolicySubject } from '../policy/engine.js';
```

(add to the existing engine import if there is one).

Add to `AuditedOpts`:

```ts
    /**
     * The remote path an SFTP tool acts on. `[policy].denylist` is tested against it as
     * well as against the command string, which for these tools is one we compose (#230).
     */
    remotePath?: string;
```

`checkPolicyAndApprove`:

```ts
  async function checkPolicyAndApprove(
    command: string,
    profileName: string,
    toolName: string,
    subject: PolicySubject = {},
  ) {
```

```ts
      const evaluation = await policy.evaluateWithOpa(command, conn.profile, toolName, subject);
```

In `runAudited`:

```ts
      const { conn, evaluation, approver } = await checkPolicyAndApprove(
        effective, profileName, opts.toolName, { remotePath: opts.remotePath },
      );
```

In each of the five tools' `runAudited` options object, add `remotePath,` after `synthetic: true,`. `preCheck` already runs `sanitizeRemotePath(remotePath)` before the policy check, so the engine only sees a path that passed it.

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit/tools/ && npm run typecheck`
Expected: PASS, typecheck clean.

- [ ] **Step 6: Mutation check**

One at a time on backups, confirm a test fails, then restore:
- each of the five `remotePath,` lines removed (five mutants; each must fail its own tool's normalized row)
- `{ remotePath: opts.remotePath }` → `{}`
- `policy.evaluateWithOpa(command, conn.profile, toolName, subject)` → drop `subject`

- [ ] **Step 7: Commit**

```bash
git add src/tools/pipeline.ts src/tools/transfer-tools.ts src/tools/file-tools.ts test/unit/tools/harness.ts test/unit/tools/denylist-remote-path.test.ts
git commit -m "fix(tools): hand each SFTP tool's remote path to the denylist (#230)

A rule written for the path, such as authorized_keys\$, never matched
sftp-upload-file or sftp-download-file, whose composed strings end with the
local path, and a spelling like /root//.ssh/ slipped past a substring rule on
every tool.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: Documentation and changeset

**Files:**
- Modify: `README.md` — `sftp-upload` paragraph "The path comes last…" (≈ lines 183–188); config example `[policy]` (≈ line 333); "Extra deny patterns…" (≈ lines 489–494); OPA input example (≈ line 643)
- Modify: `src/tools/file-tools.ts` — the comment above the `sftp:upload` string (≈ lines 56–66)
- Create: `.changeset/quiet-paths-match.md`

**Interfaces:** none.

- [ ] **Step 1: README, the `sftp-upload` paragraph**

Replace the paragraph that begins "The path comes last in that string on purpose." with:

```md
`[policy].denylist` patterns are tested against that whole string and, for every
SFTP tool, against the remote path on its own — as given and lexically
normalized (see "Policy Engine"). A rule written for the path, such as
`authorized_keys$`, therefore does not depend on where the string puts it. A rule
anchored on the *whole* string (`^sftp:upload /root/.*$`) still does: that layout
is ours to change, so anchor on the path instead.
```

- [ ] **Step 2: README, the config example**

```toml
[policy]
denylist = ["^terraform\\s+destroy", "\\.ssh/authorized_keys$"]
```

- [ ] **Step 3: README, "Extra deny patterns"**

Replace the block from "Extra deny patterns live in the same section" through its toml fence with:

````md
Extra deny patterns live in the same section, and are applied on top of the
never-allowed list rather than replacing it:

```toml
[policy]
denylist = ["^terraform\\s+destroy", "\\.ssh/authorized_keys$"]
```

Each pattern is a regular expression tested against the command string of every
call. For the five SFTP tools it is also tested against the remote path on its
own, both as given and in a normalized reading: `//` and `/./` collapse, `..`
resolves against the segment before it, a trailing `/` is dropped, and `\` is
read as `/`. The refusal says which of the three matched. What the normalized
reading does not do:

- **resolve anything on the target.** A relative path stays relative, so a rule
  anchored on `/root/` does not see `.ssh/authorized_keys`; symlinks are not
  followed.
- **test the local path** of `sftp-upload-file` or `sftp-download-file`. That
  side is confined by `transferRoot`.
- **ignore case**, Windows paths included.

So anchor a path rule on its trailing segments: `\.ssh/authorized_keys$` matches
the absolute, relative and Windows spellings alike. A pattern written for a
command is tested against SFTP paths too — `^rm` refuses an `sftp-download` of a
file called `rmlist.txt`.
````

- [ ] **Step 4: README, the OPA input example**

In the `input` JSON under "External Policy Engine (OPA)", leave the `run-command` example as it is and add, right after the JSON block:

```md
For the five SFTP tools, `resource` also carries `remotePath`, the path the tool
acts on, so a rule can match it without parsing `command`. Other tools omit the
key.
```

- [ ] **Step 5: `file-tools.ts` comment**

Replace the comment above `` `sftp:upload${OVERWRITE_FLAG}…` `` (from "Verb, then what the operation does" through "need no change.") with:

```ts
        // Verb, then what the operation does, then the path it does it to. The path
        // ends the line so the string reads naturally in a prompt and an audit record;
        // `[policy].denylist` no longer depends on that, since every SFTP tool hands
        // its remote path to the engine on its own (#230). A rule anchored on the whole
        // string (`^sftp:upload /root.*$`) is still coupled to this layout.
```

- [ ] **Step 6: Changeset**

Create `.changeset/quiet-paths-match.md`:

```md
---
"ssh-mcp": minor
---

`[policy].denylist` patterns are now also tested against the remote path of the five SFTP tools, as given and lexically normalized (`//`, `/./` and `..` resolved, `\` read as `/`), not only against the command string this server composes for them (#230). A rule written for the path, such as `authorized_keys$`, used to miss `sftp-upload-file` and `sftp-download-file`, whose strings end with the local path, and a spelling like `/root//.ssh/` slipped past a substring rule on every tool. OPA's input gains `resource.remotePath` for these tools.

**Upgrade note — minor, not patch, because a call that was allowed can now be refused.** A pattern written for commands is now also tested against SFTP paths, so `^rm` refuses an `sftp-download` of `rmlist.txt`. The refusal says whether the command or the remote path matched. Nothing is resolved on the target: relative paths stay relative and symlinks are not followed, so anchor a path rule on its trailing segments.
```

- [ ] **Step 7: Verify and commit**

Run: `npm run typecheck && npx cross-env SSH_MCP_DISABLE_MAIN=1 npx vitest --run test/unit`
Expected: PASS.

```bash
git add README.md src/tools/file-tools.ts .changeset/quiet-paths-match.md
git commit -m "docs(policy): say what a denylist pattern is tested against, and what it does not resolve (#230)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: Whole-branch verification

- [ ] **Step 1:** `npm run typecheck` — clean.
- [ ] **Step 2:** `COMPOSE_PROJECT_NAME=ssh-mcp npm test` — all pass; report the counts.
- [ ] **Step 3:** `npm run build && npx vitest --run test/e2e` — all pass.
- [ ] **Step 4:** `git diff --stat origin/main...HEAD` — only the files named in Tasks 1–4 (plus the spec and this plan) changed.
