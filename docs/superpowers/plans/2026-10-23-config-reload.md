# Config Reload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply an edited `config.toml` to a running server through a `reload-config` tool (and SIGHUP on non-Windows). The new file is fully validated first; the swap is all or nothing.

**Architecture:**
- **Validation** runs exactly what startup runs, into fresh objects.
- **The swap** is one synchronous step. It mutates the long-lived `ConnectionRegistry` (which keeps the TOFU pins), `PolicyEngine` (which keeps OPA) and `localPath` in place, so every captured reference sees the new config.
- **Staleness** is caught by a config generation counter: an in-flight connect, an approval wait and approval grants created under an older generation are discarded or re-checked.

**Tech Stack:** TypeScript (Node ≥18.19), MCP SDK, ssh2, zod, vitest, docker-compose test servers.

**Spec:** `docs/superpowers/specs/2026-10-23-config-reload-design.md`

## Global Constraints

- **Reloadable:** config-file content only. Argv flags (HTTP, OPA, host key mode, audit, OTEL, `--config`) are never reloaded.
- **Any validation failure leaves everything as it was:** config, policy, registry, connections, grants and `transferRoot`.
- **`transferRoot`:**
  - changing it (some → other) is refused;
  - removing it (some → none) is refused;
  - adding it (none → some) is allowed.
- **Starting source:**
  - a server started from flags (quick start) refuses with `started from command-line flags; restart to use a config file`;
  - a server started unconfigured may reload into a configured one;
  - zero profiles is refused.
- **Open connections:**
  - **Policy fields** apply immediately, through a profile swap.
  - **Connection fields** close the connection and its sessions: `host`, `port`, `user`, `auth`, `keyRef`, `keychainEntry`, `cert`, `via`, `trustedHostKey`.
  - **Removed profile:** its connection and sessions close.
  - **Bastion closed:** dependents close too.
  - **Session-fixed fields** keep the connection and are reported by name: `workdir`, `tty`, `timeout`, `maxOutputBytes`, `announceAgent`, `sessionMaxPerConnection`, `sessionIdleTimeoutMs`, `sessionBackgroundMaxMs`.
- **Approval grants** from older generations stop counting. The grant TTL is read live.
  - The spec asked for "the number of approval grants cleared". Grants live in one store per pipeline (per MCP session under HTTP), and invalidating them by generation needs no registry of those stores, so the report says `grantsInvalidated: true` instead of a count. The PR body states this deviation.
- **Not in this PR:** the extra cross-checks the spec leaves to the builder (unique profile names, `via` targets, `defaultProfile` existence). They are startup behaviour too, and get their own change.
- **Audit:**
  - one `config:reload` record per attempt: `binary: 'config:reload'`, `commandClass: 'safe'`, `profile: '-'`, `decision` = `allow` or `deny`, `ruleId: 'config-reload'`, `error` set on refusal;
  - plus one `session:close` record, reason `reload`, per session a reload closes.
- **Never print** file contents, credentials or values from the file anywhere. Field names and the config path are fine.
- **The tool is not approval-gated.**
- **Release:** a minor changeset.

## Review Focus

1. **A reload while a command is waiting on approval.** It must re-evaluate when the wait returns, refuse if the decision changed, and record no grant. Test owner: Task 5.
2. **A reload during an in-flight connect for the same profile.** The connect resolves after the swap, and the stale connection must be closed, not stored. Test owner: Task 4 (integration).
3. **Two reloads at once** (a tool call and SIGHUP together) must serialize: the second sees the first's result, and there is never an interleaved swap. Test owner: Task 6.
4. **A Windows ACL check that cannot run during reload.** It must behave exactly as at startup: with `--allowUncheckedConfigAcl` it warns and continues; without it, the reload is refused. Test owner: Task 6, with the ACL check stubbed the way existing loader tests do it.
5. **Removing a profile that is the bastion of a live connection, while that connection has a running background session.** Both close, and both sessions get `session:close` records. Test owner: Task 4 (unit, with fake connections).

---

### Task 0: Branch for this PR

- [ ] **Step 1:** Create the branch from `origin/main`. If the classifier-properties PR has merged, branch after it.

```bash
git fetch origin
git switch -c feat/config-reload origin/main
git checkout worktree-config-reload-and-classifier-invariants -- docs/superpowers/specs/2026-10-23-config-reload-design.md docs/superpowers/plans/2026-10-23-config-reload.md
git commit -m "docs: design and plan for config reload (#288)"
npm ci
```

- [ ] **Step 2:** Bring up the test servers (`docker compose --profile test up -d --build --wait`), then run `SSH_MCP_REQUIRE_SERVERS=1 npm test`. Expected: green baseline.

### Task 1: Reaper survives a missing profile

**Files:**
- Create: `src/ssh/reaper.ts`
- Modify: `src/index.ts` (the reaper `setInterval` body)
- Modify: `src/ssh/connection-registry.ts`: add `liveConnections()`
- Test: `test/unit/ssh/reaper.test.ts`

**Interfaces:**
- Produces:
  - `ConnectionRegistry.liveConnections(): SSHConnection[]`: every stored connection, with no profile lookup.
  - `reapOnce(registry: ConnectionRegistry): Promise<void>`: awaits `reapExpiredSessions()` on each live connection (errors swallowed per connection, as today), then `registry.reapIdleConnections()`.

- [ ] **Step 1: Failing test.** Build a registry over config `{profiles: [a]}` and plant a connection for `a` using the existing test seam that integration tests use (`concurrent-sessions.test.ts` casts). Swap the registry config so `a` is gone (use Task 4's `applyConfig` if it exists already, or a cast). Then `await reapOnce(registry)` resolves, and `reapIdleConnections` does not throw.
- [ ] **Step 2:** Run `npx vitest --run test/unit/ssh/reaper.test.ts`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement.** `reapIdleConnections` must also tolerate a connection whose profile is gone: `via` lookups read the live `profiles` array and skip missing names. Replace the `index.ts` loop body with `void reapOnce(registry).catch((err) => console.error(...))`.
- [ ] **Step 4:** Run it again. Expected: PASS.
- [ ] **Step 5:** Commit, with the message `fix: the reaper no longer exits the process when a connection's profile is gone`.

### Task 2: Config source and ACL options are reusable

**Files:**
- Modify: `src/cli.ts`
- Test: `test/unit/cli/config-source.test.ts`, or extend the existing `buildAppConfig` tests (find them with `grep -rln buildAppConfig test/unit`)

**Interfaces:**
- Produces:
  - `type ConfigSource = 'file' | 'unconfigured' | 'flags'`.
  - `interface LoadedConfig { config: AppConfig; source: ConfigSource; path: string }`. `path` is the file that was read, or the default path for `unconfigured` and `flags`.
  - `aclOptionsFromArgv(argv): AclOptions`: extracted verbatim from `buildAppConfig`.
  - `loadAppConfig(argv): Promise<LoadedConfig>`: the current `buildAppConfig` branches, each tagged with its source.
  - `buildAppConfig(argv)`: unchanged signature, returns `(await loadAppConfig(argv)).config`.
  - `loadConfigFile(path: string, argv): Promise<AppConfig>`: `loadConfig(path, aclOptionsFromArgv(argv))`. Reload uses this.

- [ ] **Step 1: Failing tests.** For `--config=<tmp file>`, source is `'file'`. For an absent default path with `--host`/`--user`, source is `'flags'`. With neither, source is `'unconfigured'` and `profiles` is `[]`. In each case, `path` equals the expected path.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. `index.ts` switches to `loadAppConfig` and keeps `source` and `path`.
- [ ] **Step 4:** Run them, then all existing cli tests. Expected: PASS.
- [ ] **Step 5:** Commit, with the message `refactor: tag the loaded config with its source`.

### Task 3: Profile diff and field classification (pure)

**Files:**
- Create: `src/config/reload-diff.ts`
- Test: `test/unit/config/reload-diff.test.ts`

**Interfaces:**
- Produces:
  - `CONNECTION_FIELDS`, `SESSION_FIXED_FIELDS`, `POLICY_FIELDS`: each `readonly (keyof Profile)[]`.
    - `CONNECTION_FIELDS`: as in Global Constraints.
    - `SESSION_FIXED_FIELDS`: as in Global Constraints.
    - `POLICY_FIELDS`: `role`, `group`, `approvalPolicy`, `readOnly`, `commandQuotaPerDay`, `maxChars`, `transferMaxBytes`, `transferTimeoutMs`.
  - `interface ProfileChange { name: string; fields: (keyof Profile)[] }`.
  - `interface ProfileDiff { added: string[]; removed: string[]; changed: ProfileChange[] }`.
  - `diffProfiles(prev: Profile[], next: Profile[]): ProfileDiff`. Comparison is by name, field by field, with structural equality.
  - `disposition(change: ProfileChange): 'close' | 'swap'`. It returns `'close'` iff any field is in `CONNECTION_FIELDS`.
  - `policyRulesChanged(prev: AppConfig, next: AppConfig): boolean`. It compares `resolvePolicyRules` outputs structurally.

- [ ] **Step 1: Failing tests:**
  - **Coverage table:** every key of a fully populated `Profile` (built with every optional field set) is in exactly one of the three lists, or is `name`. This fails when someone adds a `Profile` field without classifying it.
  - added, removed and changed are detected; `fields` lists only the keys that differ;
  - `disposition`: `{fields: ['role']}` gives `'swap'`, `{fields: ['user']}` gives `'close'`, and `{fields: ['workdir']}` gives `'swap'`.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit, with the message `feat(config): classify profile changes for reload`.

### Task 4: Registry swap, connection profile seam, generation

**Files:**
- Modify: `src/ssh/connection.ts`: `profile` becomes a private field behind `get profile(): Profile`, plus `replaceProfile(p: Profile): void`.
- Modify: `src/ssh/connection-registry.ts`
- Modify: `src/policy/engine.ts`: add `replaceRules(rules: PolicyRules): void`.
- Test: `test/unit/ssh/registry-apply-config.test.ts`, `test/unit/policy/engine-replace-rules.test.ts`
- Test (integration): `test/integration/config-reload.test.ts` (created here, extended in Task 7)

**Interfaces:**
- Consumes: Task 3 (`diffProfiles`, `disposition`).
- Produces:
  - `ConnectionRegistry.generation: number` (getter; starts at 0).
  - `ConnectionRegistry.applyConfig(next: AppConfig): ApplyResult`. It is synchronous: it swaps `config`, increments `generation`, calls `replaceProfile` on every `'swap'` connection, and removes every `'close'` connection from the maps (plus their dependents through `via`, transitively). It does **not** await any close.
  - `interface ApplyResult { diff: ProfileDiff; toClose: { conn: SSHConnection; profile: string; reason: 'removed' | 'connection-field' | 'bastion-closed' }[]; sessionFieldsChanged: ProfileChange[] }`.
  - `PolicyEngine.replaceRules(rules)`: compiles the denylist into locals first (throws without mutating if invalid), then assigns the new rules and patterns. OPA state is untouched.
  - In `getOrCreate`: capture `const gen = this.generation` before connecting. Before storing the connection, if `this.generation !== gen`, close it and throw `OperatorError('The configuration was reloaded while connecting; retry the call.')`.

- [ ] **Step 1: Failing unit tests.** Plant real `SSHConnection` objects (never connected) in the registry, using the same cast pattern as Task 1.
  - **Policy-only change:** the same `SSHConnection` instance stays in `listConnections()`; `conn.profile.role` is the new value; `toClose` is empty.
  - **`user` changed:** the connection is in `toClose` with reason `connection-field` and is gone from the registry.
  - **Profile removed:** reason `removed`.
  - **The bastion's `host` changed, with a dependent `via` connection planted:** both are in `toClose`; the dependent's reason is `bastion-closed`.
  - **`workdir` changed:** the connection stays, and `sessionFieldsChanged` names `workdir`.
  - `generation` goes 0 → 1.
  - **`replaceRules`** with an invalid denylist regex throws, and `evaluate` still uses the old rules. With a valid one, a newly denylisted command is now denied, and `setOpaUrl` state is preserved (check the `opaUrl` field through a cast).
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement. Fix every compile error the `profile` getter change surfaces. Test casts that assigned `profile` must now use `replaceProfile`.
- [ ] **Step 4:** Run the unit tests, then `npm run typecheck`. Expected: PASS.
- [ ] **Step 5: Integration test (in-flight connect, Review Focus 2).** Against `ssh-admin` (2222): start `registry.getOrCreate('admin')` without awaiting, call `registry.applyConfig(sameConfigWithAdminUserChangedToOperator)`, then await. It rejects with the retry message, and `registry.get('admin')` is undefined. Run `SSH_MCP_REQUIRE_SERVERS=1 npx vitest --run test/integration/config-reload.test.ts`. Expected: PASS.
- [ ] **Step 6:** Commit, with the message `feat(ssh): swap profiles in place on reload and discard stale connects`.

### Task 5: Grants by generation, live TTL, approval re-check

**Files:**
- Modify: `src/guard/approval-grants.ts`
- Modify: `src/tools/pipeline.ts` (approval path, around the `requestApproval` call and `grants.record`)
- Modify: `src/tools/registry.ts` / `ToolDeps`, if TTL or generation must be threaded through
- Test: `test/unit/guard/approval-grants.test.ts` (extend), plus the existing pipeline/approval unit tests (extend; find them with `grep -rln requestApproval test/unit`)

**Interfaces:**
- Consumes: `ConnectionRegistry.generation`.
- Produces:
  - `new ApprovalGrants(ttlMs: number | (() => number), generation: () => number = () => 0)`.
    - Each grant stores the generation it was recorded under.
    - `has()` returns false for a grant from an older generation.
    - `clear()` stays.
  - `createPipeline`:
    - builds grants with `() => registry.currentDefaults().approvalGrantTtlMs` and `() => registry.generation`;
    - `ConnectionRegistry.currentDefaults(): Defaults` returns the live config's defaults.

- [ ] **Step 1: Failing tests:**
  - **grants:**
    - a grant recorded at generation 0 is not honoured once the generation fn returns 1;
    - a TTL fn that changes from 0 to 1000 between two records applies to the second record;
  - **pipeline:**
    - a fake `requestApproval` resolves "approved" after the test calls `registry.applyConfig` with that profile's `approvalPolicy` changed to `deny`;
    - the call is refused (the audit decision is `deny` with `ruleId` `config-reloaded`);
    - no grant is recorded;
  - and with an unchanged posture across a reload, the approved call proceeds.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - After the approval wait, if `registry.generation` differs from the value captured before evaluation, re-read the connection's current profile and re-evaluate with `policy.evaluateWithOpa`.
  - Proceed only if the **new** evaluation's decision is `require-approval` or `allow` **and** the **new** evaluation's `commandClass` equals the class of the evaluation the human approved.
    - The new evaluation runs against the post-swap profile and rules.
    - The comparison is new-vs-approved, never the old evaluation against itself.
  - Otherwise refuse with `ruleId: 'config-reloaded'`.
  - Record the grant only when the call proceeds.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit, with the message `feat(guard): approvals and grants do not outlive a config reload`.

### Task 6: The reloader

**Files:**
- Create: `src/config/reload.ts`
- Test: `test/unit/config/reload.test.ts`

**Interfaces:**
- Consumes: Tasks 2–5.
- Produces:
  - `interface ReloadDeps { argv; registry: ConnectionRegistry; policy: PolicyEngine; audit: AuditStore; localPath: { transferRoot?: string }; startup: LoadedConfig }`.
  - `interface ReloadStatus { path: string; source: ConfigSource; loadedAt: string; sha256: string | null; last: ReloadOutcome | null }`.
  - `interface ReloadOutcome { ok: boolean; at: string; trigger: 'tool' | 'sighup'; error?: { name: string; message: string }; diff?: ProfileDiff; policyChanged?: boolean; closed?: { profile: string; reason: string; sessions: string[] }[]; sessionFieldsChanged?: ProfileChange[]; grantsInvalidated?: boolean; sha256?: string }`.
  - `class ConfigReloader`:
    - `constructor(deps: ReloadDeps)`;
    - `status(): ReloadStatus`;
    - `reload(trigger: 'tool' | 'sighup', requestId: string | number): Promise<ReloadOutcome>`;
    - `formatOutcome(o: ReloadOutcome): string`: the one human-readable summary, used for both the tool text and stderr.

  Behaviour of `reload`:
  - It is serialized: each call chains on the previous promise.
  - **Validate**, in order:
    1. Refuse if `startup.source === 'flags'`.
    2. Read the bytes and hash them (sha256).
    3. `loadConfigFile(path, argv)`.
    4. `resolvePolicyRules`.
    5. `new PolicyEngine(rules)` as a throwaway validator.
    6. Apply the `transferRoot` rule.
  - **Swap**, synchronously:
    - `registry.applyConfig`;
    - `policy.replaceRules`;
    - set `localPath.transferRoot` (none → some only).
  - **Then:**
    - close each `toClose` connection, after collecting `conn.listSessions()` names first;
    - write one `session:close` audit record per session (reason `reload`, `ruleId: 'session-release'`, the `RELEASE` constant from `session-tools.ts`, exported for reuse);
    - write the `config:reload` record;
    - print `formatOutcome` to stderr.
  - On any validation error, write the `config:reload` record with `decision: 'deny'` and `error`, and change nothing else.

- [ ] **Step 1: Failing tests.** Use temp config files under a `mkdtemp` directory with mode 700 and the file at 600 (POSIX). Skip the permission-specific cases on Windows the way existing loader tests do.
  - **Each validation failure leaves the registry config, policy rules, `localPath` and `registry.generation` identical** (check by reference). An unchanged generation means a failed reload does not invalidate grants:
    - malformed TOML;
    - a schema violation;
    - a bad denylist regex;
    - a cross-check failure;
    - a world-readable file;
    - a `transferRoot` change;
    - zero profiles;
    - `source: 'flags'`.
  - **Success:** `diff`, `policyChanged`, `closed` and `sessionFieldsChanged` are correct; `sha256` matches `createHash('sha256')` of the bytes; `status().last` is the outcome.
  - **`transferRoot`:** none → some is allowed and sets `localPath.transferRoot`.
  - **Unconfigured startup:** reload from a newly written file succeeds.
  - **Audit:** with an `AuditStore` on a temp path, after a success there is one `config:reload` `allow` record and one `session:close` per closed session; after a failure, one `config:reload` `deny` record with `error`.
  - **Concurrency (Review Focus 3):** two `reload()` calls started together both resolve, and their `at` timestamps are ordered.
  - **ACL (Review Focus 4):** with the ACL check stubbed to fail-open-with-finding, `--allowUncheckedConfigAcl` passes and its absence refuses. Mirror how `test/unit/config/` stubs `assertPrivateOnWindows`.
  - **No leak:** `formatOutcome` never contains a value from the file. Assert that a canary host string such as `canary-host-9f3a` from the file does not appear in the output.
  - **Quota counters survive:**
    1. spend 2 of a profile's `commandQuotaPerDay = 3` through a `CommandQuota` instance keyed by name;
    2. reload with the limit unchanged;
    3. the third call is allowed and the fourth is refused.

    Raising the limit to 5 in the reload allows two more calls. Exercise this through the same `CommandQuota` API the pipeline uses.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit, with the message `feat(config): reload config.toml with full validation and an atomic swap`.

### Task 7: The `reload-config` tool, SIGHUP and end-to-end tests

**Files:**
- Create: `src/tools/config-tools.ts`
- Modify:
  - `src/tools/registry.ts`: register the new tool. `ToolDeps` gains `reloader`.
  - `src/tools/descriptions.ts`: add the `reload-config` description.
  - `src/index.ts`: build the `ConfigReloader`, pass it to `createMcpServer`, and add `process.on('SIGHUP', …)` only when `process.platform !== 'win32'`.
- Test:
  - `test/unit/tools/config-tools.test.ts`;
  - extend `test/integration/config-reload.test.ts`;
  - `test/e2e/config-reload.e2e.test.ts`;
  - update whatever pins the tool list or hashes. Find it with `grep -rln "getToolHashes\|tools/list" test`.

**Interfaces:**
- Consumes: `ConfigReloader`.
- Produces: tool `reload-config` with input `{ action?: 'status' | 'reload' }`, defaulting to `'status'`.
  - `status` returns `status()` as text.
  - `reload` returns `formatOutcome(await reload('tool', requestId))`, and sets `isError: true` when `!ok`.
  - The tool is not approval-gated and not quota-counted.

- [ ] **Step 1: Failing unit tests.**
  - The tool is registered.
  - The status shape contains path, loadedAt and sha256, and no file contents.
  - `reload` on a refused config returns `isError` and the message.
  - The description hash is present in `getToolHashes()`.
- [ ] **Step 2: Failing integration tests**, against the compose servers:
  - **Policy change on an open connection:** open a connection on the `operator` profile and run `ls`. Rewrite the config with `approvalPolicy = "deny"` and a destructive command, then reload. The next destructive command is refused without reconnecting (the connection object is the same instance).
  - **User change closes the connection:** run `id -un` on profile `admin` (user `admin`). Change that profile's `user` to `operator`, with credentials for `operator`, and reload. The connection was closed, and the next `id -un` prints `operator`.
  - **Removed profile:** open a background session on a profile, remove that profile, reload. The session is gone, and the audit log has its `session:close` record.
  - **SIGHUP:** skip on win32. Spawn the built server over stdio with a temp config, rewrite the config to add a profile, send `SIGHUP` to the child, and `list-connections` shows the new profile. This can live in e2e if the integration harness cannot spawn.
- [ ] **Step 3: Failing e2e test:** over stdio through the built server (`test/e2e/harness.ts`), `reload-config` with `status` then `reload` after editing the config file.
- [ ] **Step 4:** Implement until Steps 1–3 pass. Run `SSH_MCP_REQUIRE_SERVERS=1 npm test` and `npm run test:e2e`. Expected: PASS.
- [ ] **Step 5:** Commit, with the message `feat: reload-config tool and SIGHUP reload (#288)`.

### Task 8: Docs and changeset

**Files:**
- Modify:
  - `README.md`: a new "### Reloading" subsection inside "## Configuration", with the content from the spec's Docs section. Update "## Tools (14)" to 15, add the tool entry, and add one sentence that running commands finish under the posture they started with.
  - `SECURITY.md`: one paragraph under "Safe Deployment Guidelines". A reload trusts the file's ownership and permissions exactly as startup does, so the same chmod/ACL guidance applies.
- Create: `.changeset/config-reload.md` (`"ssh-mcp": minor`). It describes the tool, SIGHUP, the refusals and the grant invalidation in plain terms, and credits issue #288.

- [ ] **Step 1:** Write the docs. Check every sentence against the code from Tasks 1–7: names, refusals, fields.
- [ ] **Step 2:** Run `npm run typecheck`, `npm run build`, `SSH_MCP_REQUIRE_SERVERS=1 npm test` and `npm run test:e2e`. Expected: all green.
- [ ] **Step 3: Review.** Run the `review-pro` skill on the branch. Fix confirmed findings and re-run Step 2.
- [ ] **Step 4:** Commit, push, and open the PR. Title: `feat: reload config.toml without restarting (reload-config, SIGHUP)`. The body links #288 and lists the refusals, what closes, the generation behaviour and the tests.
