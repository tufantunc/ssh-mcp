# Research Task: SSH MCP Server v2 — Security, Standards & Best Practices Deep Dive

## Context

You are researching best practices, published academic papers, industry standards, and reference architectures for a **major v2 rewrite** of an open-source **SSH MCP Server** (`tufantunc/ssh-mcp`).

**What the project does today:** It is a local Model Context Protocol (MCP) server (TypeScript/Node.js, stdio transport) that exposes SSH remote command execution as MCP tools (`exec`, `sudo-exec`) so that LLM agents (Claude, Cursor, etc.) can run shell commands on Linux/Windows servers. It uses the `ssh2` Node.js library, supports password and private-key auth, sudo/su elevation, persistent connections, configurable timeouts, and a max-command-length guard.

**Why v2:** The current design has critical security vulnerabilities (reported via GitHub issues) and is missing major features that users have requested (multi-host, HTTP transport, approval workflows, config files, SFTP, audit logging, etc.). The maintainer wants v2 to be a **security-first, standards-compliant, production-grade** rewrite.

**Your role:** You are a **research agent**. You will NOT write code. Your job is to produce a **structured research report** that the maintainer will use to plan and implement v2. The report must be actionable, cite sources (papers, specs, RFCs, blog posts, existing tools), and include concrete recommendations.

---

## Known Issues & Requested Features (from GitHub Issues & PRs)

These are the real-world problems and requests driving the v2 rewrite. Research each area thoroughly.

### A. Critical Security Vulnerabilities (must-fix in v2)

1. **Command Injection via `description` field** (Issue #44): The optional `description` parameter is appended to the command as a shell comment (`# description`), but only `#` is escaped — newlines are not. When the persistent `su` shell is active, a description like `"foo\nuseradd hacker"` injects arbitrary commands that execute as **root**. This is a critical privilege-escalation vector.

2. **Sudo Password Exposed in Remote Process List** (Issue #43, CWE-522): The sudo password is embedded in the command string (`printf '%s\n' '<password>' | sudo -S ...`) sent via `conn.exec()`, so any user on the **remote** server can read it via `ps aux` or `/proc/<pid>/cmdline`.

3. **Credentials Exposed via Command-Line Arguments** (Issue #42, CWE-214/CWE-522): `--password`, `--sudoPassword`, `--suPassword` are passed as CLI args (the *only* way today). Any local user can read them via `ps aux` or `/proc/<pid>/cmdline`.

4. **"Lethal Trifecta" Security Concern** (Issue #33): The project gives an LLM (which may be influenced by untrusted data via prompt injection) arbitrary SSH/root access to a system. This combines: (1) access to private data, (2) network egress, (3) privileged execution. Simon Willison's "Lethal Trifecta" framework applies. Research mitigations.

5. **PTY Session Leak** (Issue #34): The `--suPassword` feature uses persistent interactive PTY shells (`conn.shell()`) that are never released, causing `MaxSessions` exhaustion after ~10 commands. The su-shell architecture is fundamentally broken.

6. **No Host Key Verification** (PR #65): The server does not verify the remote host's SSH key (no `hostVerifier`, no `known_hosts` check), making it vulnerable to MITM attacks.

### B. Requested Features (from open Issues & PRs)

7. **Multi-host / multi-profile support** (Issues #41, #28, PRs #55, #54): Support multiple SSH targets via a config file (TOML proposed), with a `connectionName` selector per tool call. Dynamic connections.

8. **HTTP/SSE MCP transport** (Issues #41, #29): Move beyond stdio-only to support remote/dynamic MCP clients. Requires OAuth, authentication, rate limiting.

9. **Approval / human-in-the-loop workflows** (PRs #58, #59, #61, #62, #63): Add approval modes for SSH commands (auto-approve, manual-approve, deny). Per-profile approval settings. Possibly a WebUI for interactive approval.

10. **Audit logging with secret redaction** (PR #56): Log all executed commands with credentials/passwords/redacted output.

11. **SFTP file transfer tools** (Issue #38, PR #38): `upload-file`, `download-file` as MCP tools.

12. **Read-only vs. read-write command differentiation** (Issues #23, #36): Separate tools or annotations so MCP clients can auto-approve read-only operations. `readOnlyHint` MCP annotation support.

13. **Encrypted private key (passphrase) support** (Issue #25, PRs #35, #49): Support passphrase-protected keys, SSH agent (`SSH_AUTH_SOCK`), and env-var-based configuration.

14. **Environment variable configuration** (Issue #32): Allow all config via env vars (e.g., `SSH_MCP_KEY`, `SSH_MCP_PASSWORD`) to avoid CLI arg credential exposure.

15. **Working directory support** (PR #45): `--workdir` parameter for default CWD.

16. **Docker support & connection pooling** (Issue #28).

17. **TTY / pseudo-terminal issues** (Issue #31): Some commands fail with "input device is not a TTY".

18. **Signal handling** (Issue #3): Send Ctrl+C / kill signals to remote processes.

19. **Dependency hygiene** (Issues #47, #37, PRs #52, #51): zod/SDK version conflicts breaking fresh installs.

---

## Research Areas

For each area below, research: **(a)** the problem/threat model, **(b)** published standards/specs/RFCs/papers, **(c)** how existing production tools solve it, **(d)** concrete recommendations for this project.

### 1. MCP Protocol Security & Compliance

Research the **Model Context Protocol specification** in depth:
- Current MCP specification (authorization, transport security, tool annotations, sampling, elicitation, roots, resource templates).
- The `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` tool annotations — how should they be applied to SSH tools?
- **MCP Authorization spec** (OAuth 2.1 for HTTP transports) — PKCE, scopes, dynamic client registration.
- **Transport security**: stdio vs. Streamable HTTP vs. SSE — security implications of each for an SSH-gateway server.
- **Elicitation** (MCP 2025-06-18 spec): Can the server ask the client/user for confirmation before executing? How does this map to human-in-the-loop approval for dangerous commands?
- MCP **sampling**: Should the server use the client's LLM to classify/risk-assess commands before execution?
- Emerging **MCP security best-practices** guides from Anthropic, modelcontextprotocol.io, and community.
- The **"MCP Safety"** discussion: tool poisoning, prompt injection via tool results, confused deputy attacks.
- Research the `armorer` / MCP proxy / guard patterns (referenced in PR #48) — how do external guard proxies work?

**Deliverable:** How should the server declare tool annotations? Should it split `exec` into multiple tools (e.g., `read-file`, `list-dir`, `exec-safe`, `exec-privileged`)? Should it use elicitation for dangerous commands? What OAuth/scopes are needed for HTTP transport?

### 2. SSH Security Standards & Hardening

Research production-grade SSH client hardening:
- **Host key verification** (TOFU vs. `known_hosts` vs. CA-based): How should the server verify host keys? What APIs does `ssh2` expose? What do tools like `ansible`, `terraform`, `paramiko`, `golang.org/x/crypto/ssh` do?
- **Key exchange algorithms, ciphers, MACs, host key algorithms**: NIST/NSA recommendations (CNSSP 15, NIST SP 800-131A Rev2), IETF RFC 9142 (KEX recommendations), RFC 8308 (ext-info), SSH protocol weaknesses. How to enforce strong crypto in `ssh2`.
- **SSH certificates** (OpenSSH CA): `ssh-keygen -s`, cert auth vs. raw keys. Should v2 support cert-based auth?
- **SSH agent forwarding** and `SSH_AUTH_SOCK`: Security implications, agent hijacking risks.
- **`ProxyJump` / bastion hosts**: Multi-hop SSH for reaching private hosts.
- **Connection multiplexing** (`ControlMaster` equivalent) and `MaxSessions` management.
- **PTY vs. non-PTY exec**: When to use `shell()` vs `exec()`, the "input device is not a TTY" problem (Issue #31), and how to properly allocate PTYs without leaking sessions (Issue #34).
- **SFTP subsystem**: Secure file transfer via the SFTP channel instead of `scp`/`cat`.

**Deliverable:** A hardening checklist for the SSH layer. Which host-key-verification UX is best (strict, permissive, TOFU with prompt)? How to architect command execution to avoid the PTY-leak bug?

### 3. Credential & Secret Management

Research secure credential handling for a CLI/daemon that authenticates to SSH:
- **Why CLI args are dangerous** (CWE-214, `/proc/<pid>/cmdline`): How do production tools avoid passing secrets on the command line? (Ansible vault, env vars, config files, secret managers.)
- **Secret management options ranked by security**:
  1. OS-native secret stores (macOS Keychain, Windows Credential Manager, Linux libsecret/Secret Service, `keyring`).
  2. HashiCorp Vault / cloud secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault).
  3. Encrypted config files at rest (TOML/JSON + passphrase, like Ansible Vault, SOPS, age).
  4. Environment variables (still visible in `/proc/<pid>/environ` — less risky than args but not safe).
  5. SSH agent (`SSH_AUTH_SOCK`) for key material — avoids the passphrase problem entirely.
- **Password-to-ssh-agent bridges**: tools like `sshpass`, `expect`, or `keychain`.
- **Sudo/su password handling**: How to pass sudo passwords **without** leaking to process list? The `sudo -S` stdin approach vs. `sudo -A` (askpass) vs. temporary `sudoers` rules vs. Polkit/pkexec.
- **In-memory secret handling**: zeroization, avoiding logs, redacting secrets from error messages and audit logs.
- **Config file security**: file permissions (0600), directory permissions, validation, schema (TOML vs JSON vs YAML).

**Deliverable:** A recommended credential-loading priority order. How should `sudoPassword` be piped to avoid `/proc` exposure? Should v2 deprecate `--suPassword` entirely (per Issue #34)?

### 4. LLM-Agent Security: Prompt Injection, Sandboxing & Guardrails

Research the security of giving an **LLM agent** control of an SSH session:
- **The "Lethal Trifecta"** (Simon Willison): data exfiltration + tool access + untrusted data. How does it apply here? Mitigations.
- **Prompt injection** in tool results: A malicious file content (read via `cat`) could contain instructions that hijack the agent into running destructive commands. Research:
  - OWASP Top 10 for LLM Applications (2025) — especially LLM01 (Prompt Injection), LLM06 (Sensitive Information Disclosure), LLM08 (Excessive Agency).
  - **"Ignoring prompt injections" and defense-in-depth** for agentic systems.
  - Papers: "Not what you've signed up for: Compromising Real-World LLM-Integrated Apps" (Greshake et al.); "InjectAgent"; "Prompt Injection attack against LLM-integrated Apps"; "Sandwich Attack"; "Many-shot Jailbreaking"; "Skeleton Key"; "Indirect Prompt Injection" surveys.
  - **"Computer Use" / agentic security**: Anthropic's Computer Use safety research, OpenAI's agentic safety guidelines.
- **Tool-poisoning attacks**: How malicious MCP servers/tools can compromise clients.
- **Sandboxing & least privilege**:
  - Restricting the agent to a **command allowlist** or **denylist** (e.g., block `rm -rf /`, `dd`, `mkfs`, `shutdown`).
  - Restricting the agent to specific **directories** (chroot/jail).
  - Running as a **low-privilege user** with minimal sudo rules (`/etc/sudoers` command-specific).
  - **Linux namespaces / containers / Firejail / nsjail / bubblewrap** for sandboxing the SSH target session.
  - **Network egress controls** (iptables/nftables, eBPF) to prevent data exfiltration.
- **Rate limiting & quotas**: Per-agent, per-host command rate limits; daily command budgets; circuit breakers.
- **Destructive command detection**: Regex/heuristic/LLM-based classification of commands as safe/read-only/destructive.
- **Confirmation/approval patterns**: How do tools like Claude Code, Cursor, Aider, Devin, etc. handle human-in-the-loop for dangerous commands?

**Deliverable:** A defense-in-depth recommendation. Should v2 include a command allowlist/denylist engine? A risk-classifier? Mandatory human approval for destructive commands? How to mitigate indirect prompt injection via tool results?

### 5. Authorization, Policy & RBAC

Research authorization models for an SSH gateway:
- **RBAC for SSH**: Who can run what on which host? Role definitions, host groups, command groups.
- **Policy engines**: Open Policy Agent (OPA/Rego), Cedar (AWS), Cedarling, Casbin, AuthZEN. Should v2 embed a policy engine for command-level authorization?
- **Per-profile / per-host policy**: Different trust levels for different hosts (prod vs. dev).
- **Just-in-time (JIT) access**: Teleport, Boundary, infrastructure access patterns — can any ideas be borrowed?
- **Session recording**: Teleport's `tsh` records all SSH sessions. Should v2 support session recording/replay?

**Deliverable:** Should v2 embed OPA/Cedar for command authorization? What policy model fits an MCP-driven SSH gateway?

### 6. Auditing, Logging & Observability

Research audit-logging standards:
- **What to log**: command, timestamp, host, user, agent/client identity, exit code, duration, result. What to redact (passwords, private keys, secrets in output).
- **Audit log formats**: JSON Lines, CEF (Common Event Format), ECS (Elastic Common Schema), OTEL.
- **Tamper-evidence**: append-only logs, WORM storage, signed logs, hash-chaining.
- **Compliance frameworks**: SOC 2, PCI-DSS, ISO 27001, HIPAA — what do they require for SSH command logging? Is this relevant for the project?
- **Correlation IDs**: Linking an MCP tool call to the executed command and its result.
- **Redaction techniques**: Regex-based, structured (mask known secret fields), Shannon-entropy-based secret scanning in command output (truffleHog-style).
- **Structured logging**: `pino` / `winston` for Node.js, OTEL traces.

**Deliverable:** A recommended audit-log schema and redaction strategy. How to redact secrets that appear in command *output* (e.g., a config file printed by the agent)?

### 7. Multi-Host, Multi-Profile & Configuration Management

Research configuration management for multi-host SSH gateways:
- **Config file formats**: TOML vs YAML vs JSON for server profiles. Schema validation (zod). `~/.config/ssh-mcp/config.toml` (XDG).
- **Profile selection in MCP tools**: How does the client specify which host? Extra tool param? Separate tool per host? A `connections` resource?
- **Connection pooling & lifecycle**: Pool vs. on-demand vs. persistent. Health checks, reconnect logic, idle timeout.
- **Dynamic connections** (Issue #41): Client provides connection details at call time. Security implications.
- **Ansible-style inventory**: Host groups, variables, group_vars/host_vars.

**Deliverable:** Recommended config schema and profile-selection UX. How to balance security (predefined profiles) vs. flexibility (dynamic connections)?

### 8. HTTP/SSE Transport & Remote Deployment

Research running the MCP server over HTTP for remote/web clients:
- **MCP Streamable HTTP transport** (2025-03-26 / 2025-06-18 specs): How it works, session management, resumability.
- **Authentication**: OAuth 2.1 + PKCE, bearer tokens, API keys. Which fits a developer tool?
- **Transport security**: TLS termination, reverse proxy (nginx/Caddy), self-hosted vs. hosted.
- **Multi-tenancy**: Per-user isolation if the server is shared.
- **Rate limiting & abuse prevention**: Token buckets, per-client limits, DDoS protection.
- **WebUI**: A minimal dashboard for status, approval, session management (PRs #60–#63). Framework choice (Hono, Fastify, Express) and security.
- **Docker deployment** (Issue #28): Container image, secrets via Docker secrets / env files, health checks.

**Deliverable:** Is HTTP transport worth the complexity for v2, or should it remain stdio-first? If HTTP, what auth model? What WebUI scope?

### 9. Testing, CI/CD & Dependency Hygiene

Research best practices for a published npm CLI:
- **Dependency pinning & compatibility**: The zod/SDK conflict (Issue #47). npm `overrides`, lockfile handling, `npm audit`, automated dependency updates (Dependabot/Renovate).
- **Test architecture**: Current tests use Vitest + testcontainers (real SSH server in Docker). Research integration-test patterns for SSH, snapshot testing for command sanitization, fuzz testing for command injection, property-based testing (fast-check) for the sanitizer.
- **Security testing**: SAST (SonarQube, Semgrep, CodeQL), secret scanning (gitleaks), SCA (npm audit, Snyk). Fuzzing the command parser with injection payloads.
- **Release process**: npm provenance (Sigstore), SBOM (CycloneDX), semantic-release / changesets, conventional commits.

**Deliverable:** Recommended test matrix (unit/integration/fuzz/e2e). Which SAST/SAST tools to add to CI? How to prevent the next zod-style breakage?

### 10. UX & Developer Experience

Research UX patterns for agent-driven SSH tools:
- **Tool naming & descriptions**: How to write MCP tool descriptions that guide the LLM safely (e.g., description says "read-only" vs "destructive"). The Claude Code permission-prompt UX (Issue #24).
- **Error messages**: Safe error messages that don't leak secrets.
- **README & docs**: Security disclaimers, safe-by-default configuration, quick start that does NOT use root (address Issue #33).
- **Progress notifications**: MCP progress notifications for long-running commands.
- **Cancellation**: MCP `notifications/cancelled` mapping to SSH signal sending (Issue #3).

**Deliverable:** Recommended tool taxonomy (one `exec` vs. split tools). Tool description templates. Safe-by-default config.

---

## Output Format

Produce a **single Markdown research report** with the following structure:

```markdown
# SSH MCP Server v2 — Security & Standards Research Report

## Executive Summary
<!-- 1-page TL;DR: top 10 findings, recommended architecture, priority roadmap -->

## 1. MCP Protocol Security
### 1.1 Threat Model
### 1.2 Relevant Specs & Standards
### 1.3 How Others Solve It
### 1.4 Recommendations for ssh-mcp v2

## 2. SSH Hardening
<!-- same subsections -->

## 3. Credential Management
<!-- same -->

## 4. LLM-Agent Security (Prompt Injection & Guardrails)
<!-- same -->

## 5. Authorization & Policy (RBAC, OPA/Cedar)
<!-- same -->

## 6. Auditing & Logging
<!-- same -->

## 7. Multi-Host & Configuration
<!-- same -->

## 8. HTTP Transport & Remote Deployment
<!-- same -->

## 9. Testing, CI/CD & Dependencies
<!-- same -->

## 10. UX & Developer Experience
<!-- same -->

## Appendix A: Reference Architecture (Proposed)
<!-- Module decomposition, data flow, security boundaries -->

## Appendix B: Prioritized Roadmap
<!-- P0 (security blockers) → P1 (core features) → P2 (nice-to-have), with rationale -->

## Appendix C: Bibliography
<!-- Numbered list of all sources: papers (with title, authors, year, venue, link), RFCs, specs, blog posts, tools/repos, talks. Minimum 40-60 quality sources across all sections. -->
```

---

## Research Guidelines

- **Be thorough and evidence-based.** Cite specific papers, RFCs, specs, CVEs, blog posts, and reference implementations. Prefer primary sources.
- **Search broadly**: Use web search for recent (2024-2026) content on MCP security, LLM agent security, SSH hardening. Search arXiv, USENIX Security, IEEE S&P, ACM CCS, NDSS for academic papers on prompt injection and agentic security.
- **Study reference implementations**: Look at how these projects solve similar problems — annotate your findings:
  - **Teleport** (`gravitational/teleport`) — SSH gateway with RBAC, session recording, JIT access.
  - **Tailscale SSH** — identity-based SSH, ACLs, session recording.
  - **Boundary** (HashiCorp) — privileged access management.
  - **Ansible** — config-driven multi-host SSH, vault, inventory.
  - **OpenSSH** itself — `authorized_keys` command restrictions, `Match` blocks, `ForceCommand`.
  - **claude-code, cursor, aider, devin** — how they handle tool-call approval and sandboxing.
  - **Other MCP security tools**: `armorer`, MCP guard proxies, `mcp-shield`, etc.
- **Be opinionated.** The maintainer needs recommendations, not just options. For each area, state "we recommend X because Y" with tradeoffs noted.
- **Focus on this project's specifics.** Don't give generic security advice — tie everything back to the known issues (#42, #43, #44, #33, #34) and requested features listed above.
- **Cover the "Lethal Trifecta" deeply.** This is the core philosophical security challenge of the project. How do you safely give an LLM root SSH access? What guardrails make this acceptable?
- **Quantify where possible.** E.g., "OWASP LLM01 ranks prompt injection as #1 risk in 2025", "RFC 9142 recommends curve25519-sha256", etc.
- **Flag unknowns.** If an area is under-researched or rapidly evolving (e.g., MCP spec is still changing), say so and note the latest spec version date.

---

## Deliverable

Write the full report to a file at `research/v2-security-research-report.md` in the workspace. Make it comprehensive (aim for 15,000-30,000 words). Include the bibliography. Then provide a concise summary message back with:
1. The top 10 highest-impact findings.
2. The proposed reference architecture (1 paragraph).
3. The P0 (must-fix-before-v2-release) security items.
4. Any areas where you need the maintainer's input before the report is fully actionable.
