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
workdir = "/var/www"
trustedHostKey = "SHA256:..."       # Pin host key (optional)
tty = false
role = "operator"                   # viewer | operator | admin
readOnly = false
approvalPolicy = "ask-all"
cert = false                        # SSH CA cert auth — auto-detects keyRef-cert.pub
sessionMaxPerConnection = 3         # per-profile override
sessionIdleTimeoutMs = 300000       # stricter for prod
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

### Command Classification

Every command is classified before execution:

- **read-only**: Allowlisted commands (`ls`, `cat`, `grep`, `df`, `stat`, `systemctl status`, ...)
- **safe**: Non-destructive mutations (`npm install`, `git pull`, ...)
- **destructive**: `rm -rf /`, `mkfs`, `dd of=/dev/`, `shutdown`, `curl|sh`, fork bombs, ...
- **privileged**: `sudo`, `su`, `doas`, `pkexec`

### Approval Modes

- `auto` — no prompts (dev only!)
- `ask-destructive` — prompt for destructive/privileged (default)
- `ask-all` — prompt for every command
- `deny` — deny all mutations

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
```

Endpoints: `POST /` (MCP Streamable HTTP), `GET /status`, `GET /health`

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
| `--timeout` | 60000 | Command timeout in ms |
| `--maxChars` | 5000 | Max command length |
| `--transport` | stdio | `stdio` or `http` |
| `--httpPort` | 3000 | HTTP transport port |
| `--httpHost` | 127.0.0.1 | HTTP bind address |
| `--bearerToken` | — | Bearer token for HTTP transport auth |
| `--insecureHostKey` | false | Disable host key verification (test only!) |
| `--opaUrl` | — | OPA sidecar URL for external policy |
| `--auditEntropyScan` | false | Enable entropy-based secret scanning in audit |
| `--auditTamperEvident` | false | Enable hash-chained tamper-evident audit log |

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
