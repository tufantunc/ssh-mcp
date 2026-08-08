---
"ssh-mcp": major
---

v2: policy-gated, auditable SSH access

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

- Command injection through unsanitized metadata (#44).
- Secret exposure in server logs (#42, #43).
- PTY/channel accumulation exhausting the connection (#34).
- zod / SDK version incompatibility (#47, #51, #37).
- Encrypted private keys via passphrase (#25).
- Sudo passwords no longer appear in the remote process list — the password is
  piped over stdin rather than embedded in the command line.
