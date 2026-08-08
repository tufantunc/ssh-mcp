# SSH MCP Server v2

[![NPM Version](https://img.shields.io/npm/v/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Downloads](https://img.shields.io/npm/dm/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![License](https://img.shields.io/github/license/tufantunc/ssh-mcp)](./LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/tufantunc/ssh-mcp)](https://github.com/tufantunc/ssh-mcp/issues)

**SSH MCP Server** is a security-first Model Context Protocol server that gives LLM agents controlled SSH access to remote hosts — with command classification, policy-based authorization, human-in-the-loop approval, and full audit logging.

> **WARNING — Lethal Trifecta Risk.** Giving an LLM SSH access creates a ["Lethal Trifecta"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) (private data + untrusted input + network egress). **Never run as root. Never enable `auto` approval on production.** See [SECURITY.md](./SECURITY.md) for the full threat model and mitigation checklist.

---

## Quick Start

### 1. Install

```bash
npm install -g ssh-mcp
```

### 2. Configure

Create `~/.config/ssh-mcp/config.toml` (Linux/macOS) or `%APPDATA%\ssh-mcp\config.toml` (Windows):

```toml
[defaults]
defaultProfile = "dev"
approvalMode = "ask-destructive"

[[profiles]]
name = "dev"
host = "192.168.1.100"
port = 22
user = "deploy"           # NOT root!
auth = "key"
keyRef = "~/.ssh/id_ed25519"
role = "admin"
approvalPolicy = "auto"    # dev is permissive
```

```bash
chmod 600 ~/.config/ssh-mcp/config.toml
```

### 3. Set credentials via environment variables

```bash
export SSH_MCP_PASSWORD="your-password"        # if using auth=password
# OR use SSH agent (recommended):
export SSH_AUTH_SOCK="$SSH_AUTH_SOCK"           # already set if agent running
```

### 4. Connect from your MCP client

**Claude Code:**
```bash
claude mcp add --transport stdio ssh-mcp -- ssh-mcp
```

**Claude Desktop / Cursor / Windsurf:**
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "ssh-mcp",
      "env": {
        "SSH_MCP_PASSWORD": "your-password"
      }
    }
  }
}
```

**Never pass passwords as CLI arguments** — they're visible via `ps aux`. Use env vars, config files, SSH agent, or OS keychain.

---

## Tools (11)

| Tool | Purpose | readOnly | destructive |
|------|---------|:--------:|:----------:|
| `list-connections` | Discover available hosts and connection status | ✅ | — |
| `list-sessions` | List active sessions per host | ✅ | — |
| `open-session` | Create a named interactive (stateful) or background session | — | — |
| `close-session` | Close a session, releasing resources | — | ✅ |
| `read-session-output` | Read output from background sessions (e.g., `tail -f`) | ✅ | — |
| `read-command` | Execute allowlisted read-only commands (`ls`, `cat`, `grep`, ...) | ✅ | — |
| `run-command` | Execute arbitrary commands (destructive ones need approval) | — | — |
| `privileged-command` | Execute with sudo (always requires approval) | — | ✅ |
| `sftp-upload` | Upload a file via SFTP | — | ✅ |
| `sftp-download` | Download a file via SFTP | ✅ | — |
| `signal-process` | Send INT/TERM/KILL to a remote PID | — | ✅ |

### Interactive Sessions

Sessions maintain state (CWD, environment variables) between commands:

```
Agent: open-session(name="deploy", type="interactive")
Agent: run-command(session="deploy", command="cd /opt/myapp")
Agent: run-command(session="deploy", command="git pull")    # runs in /opt/myapp
Agent: run-command(session="deploy", command="npm ci")      # CWD persists
Agent: close-session(name="deploy")
```

### Background Sessions

Long-running processes (logs, builds):

```
Agent: open-session(name="logs", type="background", command="tail -f /var/log/syslog")
Agent: read-session-output(name="logs", lines=20)   # poll
Agent: close-session(name="logs")
```

---

## Configuration

### Profile options

```toml
[defaults]
defaultProfile = "dev"
sessionMaxPerConnection = 5
sessionIdleTimeoutMs = 600000       # 10min
sessionBackgroundMaxMs = 3600000    # 1hr
commandTimeoutMs = 60000
commandMaxChars = 5000
commandMaxOutputBytes = 1048576     # 1MB
connectionIdleReapMs = 900000       # 15min
commandQuotaPerDay = 0              # 0 = unlimited; circuit breaker for runaway agents
approvalMode = "ask-destructive"    # auto | ask-destructive | ask-all | deny

[[profiles]]
name = "prod-web-1"
host = "10.0.1.50"
port = 22
user = "deploy"
auth = "agent"                      # agent | key | password | keychain
keyRef = "~/.ssh/id_ed25519"        # for auth=key
keychainEntry = "ssh-mcp/prod"      # for auth=keychain (requires @napi-rs/keyring)
via = "bastion"                     # ProxyJump — route through bastion profile
group = "prod"                      # Policy tier: prod | staging | dev
workdir = "/var/www"
trustedHostKey = "SHA256:..."       # Pin host key (optional)
tty = false
role = "operator"                   # viewer | operator | admin
readOnly = false
approvalPolicy = "ask-all"
cert = false                        # SSH CA cert auth — auto-detects keyRef-cert.pub
sessionMaxPerConnection = 3         # per-profile override
sessionIdleTimeoutMs = 300000       # stricter for prod
commandQuotaPerDay = 200            # per-profile override
```

### ProxyJump (Bastion)

Reach internal hosts behind a bastion/jump server. The `via` field specifies a profile name to tunnel through:

```toml
[[profiles]]
name = "bastion"
host = "bastion.example.com"
user = "deploy"
auth = "agent"

[[profiles]]
name = "internal-db"
host = "10.0.1.50"                 # private IP — not directly reachable
user = "dbadmin"
auth = "key"
keyRef = "~/.ssh/db_key"
via = "bastion"                     # tunnel through bastion
```

No agent forwarding — only a TCP tunnel via `forwardOut`. The bastion stays connected and reusable for multiple internal hosts.

### SSH CA Certificates

For enterprise setups with a central SSH Certificate Authority:

```toml
[[profiles]]
name = "prod-db"
host = "db.internal"
user = "admin"
auth = "key"
keyRef = "~/.ssh/id_ed25519"
cert = true                         # enable CA cert auth
```

The certificate file is auto-detected using OpenSSH convention (`keyRef` + `-cert.pub`, e.g. `~/.ssh/id_ed25519-cert.pub`). You can override the path with `SSH_MCP_<NAME>_CERT` env var. The cert is concatenated with the private key per ssh2 convention.

### Credential Resolution Order

1. **SSH agent** (`SSH_AUTH_SOCK`) — no key material in process memory
2. **OS keychain** (macOS Keychain / Windows Credential Manager / Linux Secret Service) — requires `auth = "keychain"` and `@napi-rs/keyring`
3. **Environment variables** — `SSH_MCP_PASSWORD`, `SSH_MCP_KEY`, `SSH_MCP_SUDO_PASSWORD`, or profile-specific `SSH_MCP_<NAME>_PASSWORD`
4. **Key file** — `keyRef` path or `SSH_MCP_KEY` env var

**Never CLI arguments.** v2 removes `--password`, `--sudoPassword`, `--suPassword` entirely.

---

## Policy Engine

### Roles

| Role | Dev | Staging | Prod |
|------|-----|---------|------|
| **viewer** | read-only | read-only | read-only |
| **operator** | read-only, safe, destructive | read-only, safe, destructive | read-only, safe |
| **admin** | all | all | read-only, safe, destructive |

Which column applies comes from the profile's `group`. Set it explicitly —
without it the tier is guessed from the profile name (`prod`/`staging`/`dev`,
`local`, `test`, `sandbox`), and **an unrecognised name resolves to `prod`**,
the strictest tier. A production host named `web-01` is therefore treated as
production rather than silently getting dev permissions.

### Command Classification

Every command is classified before execution:

- **read-only**: Allowlisted commands (`ls`, `cat`, `grep`, `df`, `stat`, `systemctl status`, ...)
- **safe**: Non-destructive mutations (`npm install`, `git pull`, ...)
- **destructive**: mutations that need approval (`rm -rf /tmp/build`, ...)
- **privileged**: `sudo`, `su`, `doas`, `pkexec`

A separate **forbidden** list is never allowed, whatever the role or approval
policy: `rm -rf /`, `mkfs`, `dd of=/dev/`, `shutdown`, `curl|sh`, fork bombs,
writes to `/etc/cron`, `/etc/systemd` or `authorized_keys`, `iptables -F`, and
recursive `chmod 777 /` / `chown /`. Add your own patterns via the policy
denylist; an invalid pattern fails at startup rather than degrading silently.

### Approval Modes

- `auto` — no prompts (dev only!)
- `ask-destructive` — prompt for destructive/privileged (default)
- `ask-all` — prompt for every command
- `deny` — reject destructive/privileged commands outright (no prompt)

### Command Quota

`commandQuotaPerDay` bounds how many commands a profile may run in a rolling
24-hour window (0 = unlimited). The approval gate stops *destructive* commands
and the HTTP rate limiter caps request rate, but neither bounds total work — a
prompt-injected agent looping over allowed commands stays under both. The quota
is the circuit breaker for that case.

Counted after policy allows a command and before it runs, so a denied command
does not spend budget. The window slides rather than resetting at midnight,
which would let an agent spend a full quota just before the reset and another
immediately after.

### External Policy Engine (OPA)

For organizations that standardize on Open Policy Agent / Rego:

```bash
ssh-mcp --opaUrl=http://localhost:8181
```

When `--opaUrl` is set, every command is additionally evaluated by OPA after the built-in policy engine. The request shape follows the AuthZEN Access Evaluation contract:

```json
{
  "input": {
    "subject": { "role": "operator", "profile": "prod-web-1" },
    "action": { "tool": "run-command", "commandClass": "destructive" },
    "resource": { "command": "rm -rf /tmp/cache", "binary": "rm", "host": "10.0.1.50" },
    "context": { "readOnly": false }
  }
}
```

OPA responds with `{ "result": true/false }`. If OPA denies (`result: false`), the command is blocked even if the built-in engine allows it. If OPA is unreachable, the built-in engine's decision stands (fail-open to avoid locking out access).

Example Rego policy (`ssh-mcp.rego`):
```rego
package ssh.mcp

default allow := false

# Admins can run anything on dev hosts
allow if {
  input.subject.role == "admin"
  startswith(input.subject.profile, "dev")
}

# Deny all destructive commands on prod
deny if {
  input.action.commandClass == "destructive"
  startswith(input.subject.profile, "prod")
}
```

---

## Security

### Threat Model

See [SECURITY.md](./SECURITY.md) for the full threat model, vulnerability reporting policy, and deployment checklist.

### Safe Defaults

- **Non-root** user in all examples
- **TOFU** host key verification (accept on first connect, verify after)
- **RFC 9142** algorithm allow-list (no SHA-1, no CBC, no ssh-rsa)
- **exec()-only** (no persistent su shells — fixes PTY leak)
- **Sudo via stdin** (not argv — fixes process list leak)
- **Sanitizer** strips CR/LF/NUL from all metadata
- **3-layer redaction** (field → regex → entropy) on audit logs
- **No CLI-arg secrets** (use env vars, keychain, or config)

### Hardening Checklist

- [ ] Create dedicated low-privilege service account on target hosts
- [ ] Use command-specific `sudoers` instead of `NOPASSWD: ALL`
- [ ] Enable `ask-all` approval for production profiles
- [ ] Restrict network egress on target hosts
- [ ] Use `readOnly = true` for monitoring profiles
- [ ] Review audit logs regularly
- [ ] Run `chmod 600 config.toml`

---

## Transports

### stdio (default)

For local MCP clients (Claude Code, Cursor, Windsurf). No network exposure.

```bash
ssh-mcp                          # reads config from XDG path
ssh-mcp --config=/path/to.toml   # custom config path
```

### HTTP (optional)

For remote/web clients behind a reverse proxy with TLS:

```bash
ssh-mcp --transport=http --httpPort=3000 --bearerToken=secret
ssh-mcp --transport=http --httpPort=3000 --bearerToken=secret --rateLimit=60
```

| Flag | Default | Description |
|------|---------|-------------|
| `--bearerToken` | required | Bearer token for authentication (all routes except `GET /health`) |
| `--httpPort` | 3000 | HTTP listen port |
| `--httpHost` | 127.0.0.1 | Bind address |
| `--rateLimit` | 0 (off) | Max requests per minute (0 = unlimited) |

Endpoints: `POST /` (MCP Streamable HTTP), `GET /status`, `GET /health`

When rate limit is exceeded, the server returns HTTP 429 with `Retry-After` header and a JSON-RPC error body so MCP clients can handle it gracefully.

**Always terminate TLS at a reverse proxy** (Caddy/nginx). The server listens on `127.0.0.1` only.

---

## Docker

```bash
# Build
docker build -t ssh-mcp .

# Run (config file + env vars for credentials)
docker run -i \
  -v ./config.toml:/home/appuser/.config/ssh-mcp/config.toml:ro \
  -e SSH_MCP_PASSWORD=secret \
  ssh-mcp
```

Or with docker-compose:

```bash
docker-compose --profile app up
```

The Docker image runs as non-root UID 65532, with a minimal `node:22-slim` base.

---

## CLI Flags (v2)

Secrets are **never** passed as CLI arguments.

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | XDG path | Path to TOML config file |
| `--host` | — | Quick start: SSH host (creates single-profile config) |
| `--user` | — | Quick start: SSH username |
| `--port` | 22 | Quick start: SSH port |
| `--key` | — | Quick start: Path to private key |
| `--workdir` | — | Quick start: Working directory for commands and sessions |
| `--timeout` | 60000 | Command timeout in ms |
| `--maxChars` | 5000 | Max command length (`none` or `0` disables the limit) |
| `--sessionMax` | 5 | Max concurrent sessions per connection |
| `--sessionTtl` | 600000 | Session idle timeout in ms |
| `--transport` | stdio | `stdio` or `http` |
| `--httpPort` | 3000 | HTTP transport port |
| `--httpHost` | 127.0.0.1 | HTTP bind address |
| `--bearerToken` | — | Bearer token for HTTP transport auth (required for `--transport=http`) |
| `--rateLimit` | 0 | HTTP requests per minute on the MCP route (0 = unlimited) |
| `--insecureHostKey` | false | Disable host key verification (test only!) |
| `--disableApproval` | false | Skip the approval gate (quick start profile only) |
| `--opaUrl` | — | OPA sidecar URL for external policy |
| `--commandQuota` | 0 (off) | Max commands per rolling 24h per profile |
| `--auditEntropyScan` | false | Enable entropy-based secret scanning in audit |
| `--auditTamperEvident` | false | Enable hash-chained tamper-evident audit log |
| `--otelEndpoint` | — | OTLP/HTTP endpoint for OpenTelemetry traces |
| `--otelServiceName` | ssh-mcp | Service name reported on trace spans |
| `--dumpToolHashes` | — | Print SHA-256 hashes of the tool descriptions and exit |

---

## Migrating from v1

v2 is a breaking release. Passing a removed flag now fails at startup with the
replacement, rather than failing later as a confusing auth error.

### Tools

| v1 | v2 | Notes |
|----|----|-------|
| `exec` | `read-command` | Allowlisted read-only commands. Prefer this for reads. |
| `exec` | `run-command` | Arbitrary commands. Destructive ones go through the approval gate. |
| `sudo-exec` | `privileged-command` | Always requires approval. Password is piped via stdin. |
| `description` parameter | — | Removed. It was an injection vector (#44) and never reached the host. |

**Command results now carry status.** In v1 a failed command rejected with
`Error (code N)`. In v2 a non-zero exit comes back as an error result including
the exit code and stderr — so an empty response no longer means "it worked".

### Flags

| v1 flag | Replacement |
|---------|-------------|
| `--password` | `SSH_MCP_PASSWORD` env var (or `SSH_MCP_<PROFILE>_PASSWORD`) |
| `--suPassword` | `SSH_MCP_SUDO_PASSWORD` env var |
| `--sudoPassword` | `SSH_MCP_SUDO_PASSWORD` env var |
| `--disableSudo` | Use a role/policy that disallows the `privileged` class |

Credentials moved off the command line because CLI arguments are world-readable
via `/proc/<pid>/cmdline` on Linux (CWE-214). Credentials now resolve through an
SSH agent → OS keychain → env var → key file cascade.

### Example

```jsonc
// v1
{ "command": "npx", "args": ["ssh-mcp", "--host=1.2.3.4", "--user=root", "--password=hunter2"] }

// v2 — credentials via env
{
  "command": "npx",
  "args": ["ssh-mcp", "--host=1.2.3.4", "--user=root"],
  "env": { "SSH_MCP_PASSWORD": "hunter2" }
}
```

For more than one host, move to a TOML config file (see [Configuration](#configuration))
and pass `--config <path>`; profiles carry per-host roles and approval policy.

### Host key verification

v1 did not verify host keys. v2 defaults to trust-on-first-use and records the
key; a later mismatch fails the connection. Pin explicitly with `trustedHostKey`
in a profile, or pass `--insecureHostKey` to opt out (test environments only).

---

## Testing

```bash
# Start test SSH server
docker-compose --profile test up -d

# Run all tests
npm test

# Run only unit tests
npm test -- test/unit/

# Run with coverage
npm run coverage
```

## MCP Inspector

```bash
npm run inspect
```

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Please follow the [security checklist](./SECURITY.md#security-checklist-for-contributors) in all PRs.

## Support

If you find SSH MCP Server helpful, consider starring the repository or [sponsoring](https://github.com/sponsors/tufantunc)!
