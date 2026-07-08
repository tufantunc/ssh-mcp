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
| PTY session leaks (MaxSessions) | `exec()`-only architecture; no persistent su shells |
| Unbounded agent actions | Per-profile RBAC, rate limits, denylist, approval modes |

## Safe Deployment Guidelines

1. **Never run as root.** Create a dedicated low-privilege service account.
2. **Use command-specific sudoers** instead of blanket `NOPASSWD: ALL`.
3. **Enable `ask-destructive` or `ask-all` approval mode** for production profiles.
4. **Restrict network egress** on the target host (iptables/Cilium) to prevent data exfiltration.
5. **Use read-only profiles** (`readOnly = true`) for monitoring/observer access.
6. **Review audit logs** regularly — all commands are logged with redaction.
7. **Encrypt your config file** — set permissions to `0600` (`chmod 600 config.toml`).

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
