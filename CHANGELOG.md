# ssh-mcp

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
