# Reloading config.toml without restarting the server

**Issue:** [#288](https://github.com/tufantunc/ssh-mcp/issues/288) (feature request).
**Status:** design approved in chat (questions answered by the maintainer's delegate).
**Work happens in:** worktree `config-reload-and-classifier-invariants`; this piece ships as
its own PR, after the classifier-invariants PR.
**Release:** minor, with a changeset.

## Why

`config.toml` is read once, in `main()` (`src/index.ts`, `buildAppConfig`). Most of the
security posture lives in that file: profiles, roles, host groups, `approvalPolicy`,
`readOnly`, the denylist and the role bindings. An edit has no effect until the process is
restarted, and under stdio, which is the common deployment, the MCP client owns the process,
so "restart" means "restart the client".

The worse half is silent: an operator who tightens a profile (`auto` → `ask-all`, adds a
denylist rule, sets `readOnly`) on a running server reasonably believes it applies. It does
not. Nothing says so, and the README never says either way.

## Goals

- An operator can apply an edited `config.toml` to a running server, on every platform and
  transport.
- A reload is **all or nothing**: it validates the new file completely, exactly as startup
  does, then swaps. Any failure leaves the previous config fully in effect.
- After a successful reload, nothing keeps running under the old posture. Policy fields
  apply to open connections immediately. A connection whose connection-relevant fields
  changed, or whose profile was removed, is closed.
- Every reload attempt, successful or not, is visible: in the tool result, on stderr and in
  the audit log.
- The README states what is read when, and what a reload does and does not change.

## Non-goals

- Reloading anything that comes from argv: HTTP options, OPA flags, host key mode, audit
  flags, OTEL, `--config` itself. Those are fixed for the process lifetime.
- Watching the file for changes. A half-written file must never become live policy, so the
  reload is always an explicit act.
- An HTTP admin route. It would be new surface behind the bearer token.
- A proper non-command `AuditRecord` variant. That is its own change (see Audit).

## Anti-goals

- Any state where some of the new config applies and some of the old does. A reload that
  can half-apply is worse than no reload.
- A reload that echoes file contents, credentials or secrets anywhere.
- Rebuilding the `ConnectionRegistry`. That would wipe the in-memory TOFU host-key pins
  (README "Host key verification"), so the registry object stays and its config is swapped.

## How it is triggered

1. **An MCP tool, `reload-config`.** It is available to the caller with no approval gate.
   The file is the operator's consent; a caller, even a prompt-injected one, can only make
   the server re-read what the operator wrote. The tool result shows exactly what changed,
   which keeps the act visible.
   - Called with no arguments (or `{ "dryRun": true }`, the builder's choice of shape), it
     reports status only: config path, when it was loaded, the sha256 of the file bytes,
     and the result of the last reload attempt. Never the contents.
   - Called to apply, it reloads and reports the outcome (below).
2. **SIGHUP, on non-Windows platforms only**, calls the same reload function. Today SIGHUP
   kills the process without flushing the audit log, so this is an improvement, with one
   consequence the changeset and README state: an HTTP-transport server started from a
   terminal is no longer stopped by the hangup when that terminal closes, and is stopped
   with SIGTERM/SIGINT or run under a supervisor instead.
   On Windows, SIGHUP means "console closing" and is not wired. Under stdio the operator
   often lacks the PID, so the tool is the primary path and the signal is a convenience.

Concurrent reloads are serialized and never interleave: a second call while one is running
waits for it, and further calls while that one is still waiting join it and share its
outcome (see "Work already in flight").

## What a reload does

### Validate (no side effects on the running server)

Run the same pipeline startup runs, into fresh objects:

- read the file;
- the permission check (POSIX mode bits; the Windows ACL check, with the same flags and
  waivers as startup, e.g. `--allowUncheckedConfigAcl`, `--strictConfigAcl`);
- TOML parse, strict schema, unique profile names, normalize;
- `resolvePolicyRules` (the cross-check);
- `PolicyEngine.compile(rules)` (compiles the denylist, once; the swap installs that result,
  so it cannot throw). Whether the policy changed is the new rules compared with the rules
  the engine runs on now, not with a copy of the old config kept beside it.

Then the reload-only checks:

- **`transferRoot` changed → refuse the whole reload**, with a reason saying it needs a
  restart. `transferRoot` is the operator's consent to touch local disk, and in-flight
  transfers hold the old root, so an honest atomic swap is not possible. This covers
  *some → other* and *some → none*. **None → some is allowed**: with no root there can
  be no in-flight transfer, and the file is the consent. The captured `localPath` object
  needs a seam for that one case.
- **Unconfigured ↔ configured.** A server that started unconfigured (no config file,
  `profiles: []`) may reload into a configured one: that is a valid use, since the
  operator wrote the file after starting. A reload that would leave zero profiles is
  refused, because the schema already requires at least one.
- **Started from flags (quick start, `--host`/`--user`, no file) → refuse**, with the
  message "started from command-line flags; restart to use a config file". Swapping the
  argv-built admin profile for whatever file appeared at the default path would change
  the trust source behind the operator's back.

If anything fails, stop. The running config, policy, registry, connections and grants are
untouched.

### Swap (only after every check passed)

In one synchronous step, so no tool call can observe a mix:

- the registry's config;
- the policy rules, already compiled, with the argv OPA settings preserved;
- for each **open connection**, by profile name:
  - **profile removed** → close the connection and its sessions;
  - **connection-relevant field changed** (`host`, `port`, `user`, `auth`, `keyRef`,
    `cert`, `keychainEntry`, password/env source, `via`/ProxyJump target, `trustedHostKey`,
    or anything else that feeds `resolveCredentials` or the connect) → close the
    connection and its sessions; the next call reconnects with the new profile;
  - **otherwise** → replace the connection's profile object with the new one, so `role`,
    `group`, `approvalPolicy`, `readOnly`, quotas and limits apply on the next call.
    `conn.profile` is `readonly` today and is what policy is evaluated against
    (`pipeline.ts`), so this needs a deliberate seam. `SessionManager` already reads the
    profile through a getter written for this case.
  - **Fields an open session or channel fixed when it opened** (`workdir`, `tty`,
    `timeout`, `maxOutputBytes`, `announceAgent`, the session limits): the connection is
    kept. The new values apply to new sessions and commands, and the report names these
    fields. None of them is identity, credentials or policy.
  - A connection that is the **bastion of another connection** is subject to the same
    rules, and closing it closes what runs through it.
- **approval grants**: every one stops counting, in every pipeline (one per MCP session
  under HTTP). A grant is tagged with the config generation it was checked under and
  counts only while that is the current one, so the generation the swap bumps is the
  only invalidation; nothing clears them. If the grant TTL changed, new grants use the
  new TTL.
- **quota counters** are kept: they are keyed by profile name and read their limit live,
  so a new limit applies immediately.

Closing happens after the swap is committed, and a failure to close one connection is
reported, not rolled back: by then the new policy is already in effect.

Each session closed by a reload gets a `session:close` audit record with reason `reload`,
like the `close-session` tool writes, as well as the single `config:reload` record. A plain
connection close stays unaudited, as today.

### Work already in flight when the swap commits

A **config generation** counter increments on every applied reload. Connections and
approval grants are tagged with the generation they were created under.

- **A connect in progress** captures the generation it started from. If the generation
  moved by the time it would store the connection, and a reload since then closed its
  profile (removed, a connection field changed, or its bastion closing), it closes that
  connection instead and the call fails with "config reloaded, retry". A stale-credential
  connection stored after the swap is exactly the half-applied state this design forbids.
  Any other new connection is stored with the profile as the reload left it, as the swap
  would have updated it in place; failing it too let a client reloading in a loop fail
  every other session's first connect. A stored connection being reconnected is kept if
  the swap updated it in place, and refused if the swap took it out of the registry.
  Waiting for connects to drain is rejected, because one hung connect could block a
  security reload.
- **Reloads are serialized and coalesced.** One asked for while another runs waits for
  it; any asked for while that one is still waiting join it and share its outcome. A
  running reload is never joined, since it may have read the file before the change.
- **A call waiting on a human approval prompt** re-evaluates against the current profile
  and rules when the wait returns, if the generation changed. It proceeds only if its
  connection is still in the registry and the new rules allow the command or still ask for
  it, in the same command class: the new rules would still have put this same decision to
  the human. Otherwise the call is refused with `config-reloaded` and no grant is
  recorded. A human approved a command under rules that no longer exist, and a grant from
  before the reload must not outlive them. A grant the call does record is tagged with the
  generation its re-check ran under.
- **A decision made without a prompt** (an allow, or a reused grant) while a reload landed,
  during the connection resolve or an OPA round-trip, is re-checked the same way, but
  proceeds only if the new rules allow the command outright, in the same class: nobody was
  asked, so nothing carries over to rules that would now ask or refuse. The command quota
  is charged against the connection's live profile, read after every await.
- **A connection a reload closes is retired** in the swap: a call that resolved it before
  the swap cannot redial it (with the old profile, outside the registry) or open a channel
  on it; it fails with "This connection was closed by a configuration reload; retry the
  call."
- **A command or transfer already running** is left to finish. Interrupting a remote
  command midway is itself a half-applied action on the remote host. The next call is
  evaluated under the new rules. Removing the profile closes the connection, but that is
  not a hard stop for everything on it: a background session's command is signalled INT,
  then TERM, then KILL, while a one-shot command (or one in an interactive session) is not
  signalled (ending the client drops its channel, and dropping a channel was measured not
  to stop a command, #146) and may keep running on the host. An operator stops such a
  command with `signal-process` while the profile still reaches the host. The README says
  this.

### Report

The tool result, on both success and failure, includes:

- `ok` / refused, with the error class and message on failure. A message may name the
  config path and the field involved, never a value from the file.
- profiles added, removed and changed, and for a change, which field names changed (names
  only);
- whether the policy rules changed;
- connections closed and sessions closed, with the reason (removed / connection field
  changed);
- that approval grants were retired;
- the new sha256 and loadedAt.

The same summary goes to stderr.

## Audit

Every reload that runs is audited with one synthetic record, following the existing
`session:close` precedent (`src/audit/session-release.ts`); a call that joined a waiting
reload shares its record:

- `command: 'config:reload'`, `binary: 'config:reload'`, `commandClass: 'safe'`;
- `profile: '-'`, `user: '-'`;
- `mcpRequestId`: the tool call's request id, or `'sighup'` for a SIGHUP-triggered reload;
- applied: `decision: 'allow'`, `ruleId: 'config-reload'`;
- refused (a check failed, nothing changed): `decision: 'deny'`, `ruleId: 'config-reload'`,
  with the refusal in `error`;
- failed after the swap began (possibly part applied): `decision: 'deny'`,
  `ruleId: 'config-reload-partial'`, with the error class in `error`.

The code comment says this is the second user of the workaround, which is the case for a
proper non-command `AuditRecord` variant later. Tamper-evident chaining applies as for any
other record.

## A bug this makes reachable

The idle-connection reaper (`src/index.ts`, around the `reapIdleConnections` loop) calls
`registry.get(info.profile)` for each live connection. For a profile that no longer exists,
that throws inside a floating `async` with no `unhandledRejection` handler, which exits the
process. Removing a profile can only happen once reload exists, so this PR fixes it. The
reaper must tolerate a missing profile, and the reload closes such connections anyway.

## Config validation gaps the reload should not inherit

The loader does not check that `via` names an existing profile (or has no cycle), or that
`defaultProfile` exists. These fail at call time today. The builder decides whether to add
these checks to the shared validation (startup and reload alike) in this PR. If added, they
are cross-checks that refuse, consistent with `findPolicyProblems`, and the README's list of
startup checks is updated.

Unique profile names are checked, by the loader, so startup and reload alike. Without it the
name meant two profiles at once: a live connection resolved the first entry (`getProfile`
uses `find`) while the reload's diff and swap took the last (they key a Map by name). The
refusal names the two entries by index (`profiles[i].name`), never the name. This changes
startup for such a config from "the first one wins" to a refusal; the changeset and README
say so.

## Docs

- **README, Configuration:** a "Reloading" subsection:
  - the file is read at startup and on `reload-config` / SIGHUP;
  - what applies to open connections immediately;
  - what closes connections;
  - what applies only to new sessions and commands;
  - what is refused: a changed or removed `transferRoot`, and a server started from
    flags;
  - what is never reloadable (argv);
  - that approval grants are cleared;
  - that commands already running finish under the posture they started with;
  - that a failed reload changes nothing.
- **README, Tools:** add `reload-config` to the tool list and update the "Tools (14)"
  count.
- **SECURITY.md, Safe Deployment Guidelines:** a reload trusts the file's ownership and
  permissions exactly as startup does, so the same chmod/ACL guidance applies.
- **Changeset:** minor. It states the feature in plain terms and credits the issue.

## Tests

Following CONTRIBUTING.md, every behaviour gets a test that fails without it:

- **Unit tests:**
  - validate-then-swap atomicity: a failure at each validation step leaves the old config,
    policy and grants in place;
  - `transferRoot` refusal;
  - zero-profile refusal and unconfigured → configured;
  - the diff report;
  - grants cleared;
  - a connect in flight across a reload is discarded when the reload closes its profile,
    and stored with the new profile otherwise;
  - an approval that completes across a reload is re-checked, and records no grant when
    refused;
  - quick-start refusal; `transferRoot` none → some allowed;
  - a `session:close` record per session a reload closes;
  - quota counters kept;
  - the audit record on success and failure;
  - the reaper with a removed profile;
  - concurrent reload serialization;
  - the tool's status shape.
- **Integration tests**, against the docker-compose test servers:
  - a role or `approvalPolicy` change applies to an already-open connection on its next
    command;
  - a `user`/credential change closes the connection and the next call reconnects as the
    new user;
  - a removed profile's connection and sessions are closed;
  - SIGHUP triggers a reload (non-Windows; skipped on Windows).
- **e2e**: `reload-config` over stdio through the built server.

## Left to the builder

- The tool's exact input schema and output text format, within the content above.
- Where the reload logic lives (a new module is expected; `index.ts` is already the
  composition root).
- How the per-pipeline grant stores are reached for clearing (e.g. a registry of
  pipelines, or an event).
- The exact list of connection-relevant fields, derived from what `connect` and
  `resolveCredentials` read. The test for it is a table, so a field added later is not
  silently missed.
- Whether to add the extra cross-checks above.
