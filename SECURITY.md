# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SSH MCP Server, please report it responsibly:

1. **DO NOT** open a public GitHub issue.
2. Email: **security [at] tufantunc [dot] com** (or use [GitHub Security Advisories](https://github.com/tufantunc/ssh-mcp/security/advisories/new)).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact

You will receive a response within 72 hours. Please do not disclose the vulnerability publicly until a fix is released.

## Threat Model

SSH MCP Server gives LLM agents the ability to execute shell commands on remote hosts via SSH. This creates a **"Lethal Trifecta"** risk (Simon Willison's framework):

1. **Access to private data** — the SSH session reaches the target host's filesystem
2. **Exposure to untrusted content** — the LLM may have ingested prompt-injected data via tool results
3. **Ability to communicate outward** — the SSH session has network access for data exfiltration

### v2 Mitigations

| Risk | Mitigation |
|------|------------|
| Prompt injection via tool output | Command classifier + policy engine + human-in-the-loop approval for destructive commands |
| Credential leakage via CLI args (CWE-214) | Credentials loaded from env vars / config files / SSH agent — never CLI args |
| Sudo password in process list (CWE-522) | Sudo password piped via SSH channel stdin, not command-line `printf` |
| Command injection via metadata | Sanitizer strips CR/LF/NUL from all metadata; `description` feature removed |
| MITM attacks | TOFU host key verification by default; strict mode available |
| Weak SSH algorithms | Frozen algorithm allow-list per RFC 9142 (no SHA-1, no CBC, no ssh-rsa) |
| PTY session leaks (MaxSessions) | Interactive sessions are bounded, not absent: `sessionMaxPerConnection` (default 5), `sessionIdleTimeoutMs` (10 min), `sessionBackgroundMaxMs` (1 h), and a reaper that sweeps expired sessions every 60s. One-shot commands use `exec()` and hold no channel. No persistent `su` shells |
| Unbounded agent actions | Per-profile RBAC, rate limits, denylist, approval modes |

## Safe Deployment Guidelines

1. **Never run as root.** Create a dedicated low-privilege service account.
2. **Use command-specific sudoers** instead of blanket `NOPASSWD: ALL`.
3. **Enable `ask-destructive` or `ask-all` approval mode** for production profiles.
4. **Restrict network egress** on the target host (iptables/Cilium) to prevent data exfiltration.
5. **Use read-only profiles** (`readOnly = true`) for monitoring/observer access.
6. **Review audit logs** regularly — all commands are logged with redaction.
7. **Restrict your config file** — `chmod 700` the directory and `chmod 600` the file; the
   server refuses to start otherwise, and `chmod 600` alone does not satisfy the directory
   check. On Windows there are no mode bits: the ACL must grant only your account, `SYSTEM`
   and `Administrators`, which a config under `%APPDATA%` inherits automatically.

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

### SOC 2 (AICPA Trust Services Criteria)

| Control | Description | SSH MCP v2 Feature |
|---------|-------------|-------------------|
| CC6.1 | Logical and physical access controls | Policy engine with RBAC (viewer/operator/admin), per-profile `readOnly` flag, denylist enforcement |
| CC6.6 | Network access security | TOFU host key verification, RFC 9142 algorithm allow-list, `via` ProxyJump without agent forwarding |
| CC7.1 | System monitoring | Audit log (JSONL + ECS fields), 3-layer output redaction (field/regex/entropy) |
| CC7.2 | Detection of security events | Command classification (read-only/safe/destructive/privileged), policy denial logging |
| CC8.1 | Change management | `approvalPolicy` modes (auto/ask-destructive/ask-all/deny), MCP elicitation for destructive commands |
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
| §164.312(e)(1) | Transmission security | SSH with RFC 9142 algorithms, TOFU host key verification, no agent forwarding |
