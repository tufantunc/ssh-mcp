# ssh-mcp

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
