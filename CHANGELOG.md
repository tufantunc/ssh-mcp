# ssh-mcp

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
