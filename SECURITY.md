# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SSH MCP Server, please report it responsibly:

1. **DO NOT** open a public GitHub issue.
2. Report it privately, either way:
   - [Open a private security advisory](https://github.com/tufantunc/ssh-mcp/security/advisories/new) — preferred, since it keeps the report, the fix and the CVE in one thread; or
   - email <tufan.tunc.91@gmail.com>.
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact

### Disclosure timeline

| When | What |
|---|---|
| Within 72 hours | Acknowledgement that the report arrived, and whether it is reproducible |
| Within 7 days | An assessment: affected versions, severity, and whether a fix is planned |
| Within 90 days | Coordinated public disclosure, or sooner once a fixed release is published |

Please keep the vulnerability private until a fixed release is out, or until the 90 days
elapse — whichever comes first. Reporters are credited in the advisory unless they ask not
to be.

## Threat Model

SSH MCP Server gives LLM agents the ability to execute shell commands on remote hosts via SSH. This creates a **"Lethal Trifecta"** risk (Simon Willison's framework):

1. **Access to private data** — the SSH session reaches the target host's filesystem
2. **Exposure to untrusted content** — the LLM may have ingested prompt-injected data via tool results
3. **Ability to communicate outward** — the SSH session has network access for data exfiltration

### v2 Mitigations

| Risk | Mitigation |
|------|------------|
| Prompt injection via tool output | Command classifier + policy engine + human-in-the-loop approval for commands classified `destructive` or `privileged` — a narrower set than it sounds, see the `ask-destructive` note below |
| Credential leakage via CLI args (CWE-214) | Credentials loaded from env vars / config files / SSH agent — never CLI args |
| Sudo password in process list (CWE-522) | Sudo password piped via SSH channel stdin, not command-line `printf` |
| Command injection via metadata | Sanitizer strips CR/LF/NUL from all metadata; `description` feature removed |
| MITM attacks | TOFU host key verification by default, **for the life of one process** — see "Host key trust does not survive a restart" below. `trustedHostKey` on the profile is the only control here that outlives a restart |
| Weak SSH algorithms | Frozen algorithm allow-list per RFC 9142 (no SHA-1, no CBC, no ssh-rsa) |
| PTY session leaks (MaxSessions) | Interactive sessions are bounded, not absent: `sessionMaxPerConnection` (default 5), `sessionIdleTimeoutMs` (10 min), `sessionBackgroundMaxMs` (1 h), and a reaper that sweeps expired sessions every 60s. One-shot commands use `exec()` and hold no channel. No persistent `su` shells |
| Unbounded agent actions | Per-profile RBAC, rate limits, denylist, approval modes |

## Stopping a Command

Six things stop a command, and they all escalate the same way on the exec channel —
`SIGINT` immediately, `SIGTERM` after 1s, `SIGKILL` after 2s, then the channel is closed:

| trigger | policy check | audit record |
|---|---|---|
| the command's timeout | no | the failed command's own record |
| an MCP client cancelling the request | no | the failed command's own record |
| a channel that arrives after the request already timed out | no | trace only (`ssh.exec.lateStop`) |
| `close-session` on a background session | **no** | yes (`session:close …`, `ruleId session-release`) |
| the session reaper (idle TTL, or `sessionBackgroundMaxMs`, 1h by default) | no | **no** |
| connection teardown — shutdown, or the idle-connection reaper | no | **no** |

**Nothing on that list is policy-gated, and two of them leave no record.** The first four
are the server stopping something policy already authorised when it started, which is
strictly less authority than starting it. `close-session` is audited because it is
caller-initiated, but it is deliberately *not* refusable: routing it through the policy
engine meant a `readOnly` profile could open a background session and then be denied
permission to close it, with no other way to stop the command for an hour. A control whose
refusal mode is "the thing you asked me to stop keeps running" is worse than no control.

The last two rows are the ones to weigh before pointing this at something that matters: a
background `tail -f` that passes its TTL is `SIGKILL`ed by a timer, with no tool call, no
policy check and no audit row. Set `sessionBackgroundMaxMs` and the idle TTL accordingly.

### Host key trust does not survive a restart

TOFU is real while the process lives and gone when it exits. The store behind it is a
`Map` created per `ConnectionRegistry` (`src/ssh/connection-registry.ts`); nothing reads or
writes it to disk, and nothing consults `~/.ssh/known_hosts`. So "accept on first connect,
verify after" means verify *within this process*.

That matters most in the deployment this server is usually in. A stdio MCP server starts
and exits with the client, so a fresh accept happens every session, and an attacker
positioned to intercept has to win once per start rather than once ever. The mismatch error
that makes a swapped key visible only fires against a key this process already saw.

**`trustedHostKey` on the profile is the only control here that survives a restart.** Pin
the fingerprint you expect; it is checked in `connection.ts` before the store is consulted
at all, so an empty store does not weaken it. Use it for anything that matters.

**`--hostKeyMode=strict` refuses every host, and pinning does not rescue it.** Strict rejects
any host whose key is not already in the store, and the only write to that store is the TOFU
accept further down the same function — unreachable once the strict branch has thrown.
`trustedHostKey` never writes to it either. So under strict the store starts empty and stays
empty: measured, two consecutive connections both throw `HOST_KEY_UNKNOWN` with the store
still at zero entries, and a matching `trustedHostKey` does not change that. The mode is only
satisfiable by a key accepted earlier in the same process under `tofu`, and the mode is fixed
at startup, so that cannot happen. Treat strict as unusable until the code changes; use
`trustedHostKey`.

**`ask-destructive` gates less than the name suggests, and `kill` is one example rather
than the exception.** Outside the never-allowed list, six things produce the `destructive`
class: the pattern `/rm\s+-rf?\s+\//`, a disqualifying argument on an otherwise allowlisted
binary (`find … -delete`, `find … -exec`), a command word this process cannot resolve
statically (`$VAR` as the command), a program handed to an interpreter this process cannot
read (`python3 -c`, `perl -e`, `awk -f`, and a program arriving on a pipe), an awk program
that can start a process or write a file (`system()`, a command pipe, `print > "file"`,
gawk's `--load`), and the two commands this server synthesises that act on the target
(`sftp:upload`, `session:open`).
Elevation classifies `privileged` rather than `destructive`; this mode gates both. Ordinary write verbs are in none of these. Measured against the shipped classifier, all of these are `safe`,
and `safe` raises no prompt in this mode:

```
rm -f /etc/passwd          mv /etc/passwd /tmp/x       truncate -s0 /etc/passwd
rm -r -f /                 rm --recursive --force /    rm -rf ~
shred /dev/sda             systemctl stop nginx        kill -9 <pid>
```

So `ask-destructive` buys a prompt on elevation and on `rm -rf /path`. It does not buy one
on writes, deletions spelled another way, service control, or signals. **`ask-all` is the
mode that gates writes**, and it is the right default for a profile pointed at anything that
matters. A `readOnly` profile, or a role whose bindings exclude `safe`, are the other two
controls that actually cover this set — the command set, that is, not the threat-model rows
near the top of this file.

**The blast radius is the process group, not one process.** OpenSSH answers a `signal`
channel request with `killpg()` on the command's group (`session.c`,
`session_signal_req`), so an ordinary process tree does die — measured against 10.3p1, a
shell and its child share one process group and both are gone after a single `SIGKILL`
request. This is the server's behaviour rather than a protocol guarantee: RFC 4254 §6.9
does not specify delivery semantics, sshd refuses signal requests for forced-command and
subsystem sessions, and another server (this project also tests Dropbear) may differ.

**Nothing acknowledges a signal request.** For `exec`, the absence of a warning in the
error means the request was dispatched, not that the process died; when it could not be
dispatched at all the error says so ("could not be signalled, so it may still be running on
the host"). The `ssh.unstopped` span attribute carries the same fact for every `exec` stop
that had a channel to signal — a timeout that fires before the channel exists records
`ssh.stopDeferred` instead, and the outcome then lands on a separate `ssh.exec.lateStop`
span. `close-session` reports its own outcome in the tool result and in the audit record's
exit code rather than on a span: it distinguishes a confirmed close from a signal that was
dispatched but never took, and from one that could not be dispatched at all.

## Safe Deployment Guidelines

1. **Never run as root.** Create a dedicated low-privilege service account.
2. **Use command-specific sudoers** instead of blanket `NOPASSWD: ALL`.
3. **Enable `ask-all` approval mode** for production profiles. `ask-destructive` is the
   shipped default but gates far less than its name suggests — see the note on it below
   before choosing it for anything that matters.
4. **Restrict network egress** on the target host (iptables/Cilium) to prevent data exfiltration.
5. **Use read-only profiles** (`readOnly = true`) for monitoring/observer access.
6. **Review audit logs** regularly — all commands are logged with redaction.
7. **Restrict your config file** — `chmod 700` the directory and `chmod 600` the file; on
   Linux and macOS the server refuses to start otherwise, and `chmod 600` alone does not
   satisfy the directory check. On Windows there are no mode bits: the ACL should grant only
   your account, `SYSTEM` and `Administrators`, which a config under `%APPDATA%` inherits
   automatically. There the finding is reported rather than enforced — `--strictConfigAcl`
   enforces it if you want that.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | No (EOL)  |

## Security Checklist for Contributors

- [ ] No secrets in CLI args, error messages, or logs
- [ ] All user input sanitized (no CR/LF/NUL in shell-interfaced data)
- [ ] Sudo passwords piped via stdin, not argv
- [ ] Error messages use fixed strings, not `${buffer}` interpolations
- [ ] New tools declare MCP annotations (`readOnlyHint`, `destructiveHint`)
- [ ] Tests cover the security boundary (property tests for sanitizers)

## Compliance Mapping

SSH MCP Server v2 implements controls that map to common security frameworks. This mapping documents which features support specific control requirements — it does **not** constitute formal certification. The **deployer** is responsible for the full deployment's compliance posture.

### Independent assessment

Everything in the tables below is **self-assessed**. The one continuous outside reading is
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/tufantunc/ssh-mcp), which
re-grades the repository weekly and on every change to `main` or to branch protection, and
publishes the result. Findings also land in the repository's Security tab alongside CodeQL's.

Read it for what it measures: the **supply chain and development process** — is there a
security policy, are dependencies pinned and updated, is code scanning on, are releases
signed, can history be rewritten. It says nothing about the runtime controls the tables
below describe; no automated grader executes the policy engine. A high score means this
project is built in a way that makes tampering hard to hide, not that a deployment of it
is secure.

### SOC 2 (AICPA Trust Services Criteria)

| Control | Description | SSH MCP v2 Feature |
|---------|-------------|-------------------|
| CC6.1 | Logical and physical access controls | Policy engine with RBAC (viewer/operator/admin), per-profile `readOnly` flag, denylist enforcement |
| CC6.6 | Network access security | TOFU host key verification (per process; `trustedHostKey` to pin — see "Host key trust does not survive a restart"), RFC 9142 algorithm allow-list, `via` ProxyJump without agent forwarding |
| CC7.1 | System monitoring | Audit log (JSONL + ECS fields), 3-layer output redaction (field/regex/entropy) |
| CC7.2 | Detection of security events | Command classification (read-only/safe/destructive/privileged), policy denial logging |
| CC8.1 | Change management | `approvalPolicy` modes (auto/ask-destructive/ask-all/deny), MCP elicitation for commands classified `destructive` or `privileged`; `ask-all` for every command |
| CC9.1 | Risk mitigation | Credential cascade (agent > keychain > env, never CLI args), config file and directory permission checks (0600/0700), ACL check on Windows |

### PCI-DSS v4.0

| Requirement | Description | SSH MCP v2 Feature |
|-------------|-------------|-------------------|
| Req. 6.5 | Secure coding | Command sanitizer (CR/LF/NUL stripping), error message hygiene (no secret leakage), property tests |
| Req. 7.2 | Least privilege | Per-profile RBAC, `readOnly` profiles, command-specific denylist |
| Req. 8.3 | Authentication | SSH agent / key / keychain auth, SSH CA certificate support, no plaintext CLI credentials |
| Req. 10.2 | Audit trails | Append-only JSONL audit log, MCP requestId correlation, optional tamper-evident hash-chain |
| Req. 10.4 | Audit log protection | 3-layer redaction (field/regex/entropy), log rotation, audit file 0600 permissions |

### ISO/IEC 27001:2022

| Annex A Control | Description | SSH MCP v2 Feature |
|-----------------|-------------|-------------------|
| A.8.2 | Privileged access rights | RBAC roles, policy engine, approval modes, denylist |
| A.8.5 | Secure authentication | Credential cascade, no CLI-arg secrets, keychain + SSH agent + CA cert support |
| A.8.23 | Web filtering | `--transport http` requires bearer auth, `--rateLimit` token bucket, `--allowedHosts` Host-header allow-list |
| A.12.4 | Logging and monitoring | Audit log with ECS fields, hash-chain option, redaction |
| A.13.1 | Network security controls | Host key verification, frozen algorithms, ProxyJump tunnel |
| A.14.2 | Security in development | Property tests (fast-check), SAST (Semgrep), secret scanning (gitleaks), npm provenance |

### HIPAA (45 CFR §164.312)

| Requirement | Description | SSH MCP v2 Feature |
|-------------|-------------|-------------------|
| §164.312(a)(1) | Access control | Policy engine RBAC, per-profile readOnly, session limits |
| §164.312(b) | Audit controls | JSONL audit log with command/user/host/decision, hash-chain tamper-evidence |
| §164.312(c)(1) | Integrity | Redaction pipeline prevents PHI leakage in logs, error hygiene |
| §164.312(d) | Person or entity authentication | Credential cascade (agent/keychain/key/CA cert), host key verification |
| §164.312(e)(1) | Transmission security | SSH with RFC 9142 algorithms, TOFU host key verification (per process; `trustedHostKey` to pin), no agent forwarding |
