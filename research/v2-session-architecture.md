# SSH MCP v2 — Connection & Session Architecture

## Core Design Principles

1. **Multi-host by design.** The `ConnectionRegistry` manages multiple SSH connections simultaneously — one per profile. The agent can work across N hosts in the same MCP session.
2. **Connections are persistent.** One `ssh2.Client` per profile, lives across MCP tool calls. Auto-reconnect on failure.
3. **Sessions are scoped per connection.** Each session belongs to exactly one connection (host). State (CWD, env) is per-host. The agent manages sessions across multiple hosts in parallel.
4. **Agent can discover and manage everything.** Via MCP tools (`list-connections`, `list-sessions`) and resources (`ssh://connections/*`).
5. **PTY leak is prevented by design** — one shell per session, sentinel-based completion, proper cleanup.
6. **Session limits are configurable** — per-connection max sessions, idle TTL, and concurrency caps all come from the profile config.

### Multi-Host Addressing

Sessions are identified by `name`, scoped within a `profile`. The agent addresses them in two equivalent ways:

**Option A — separate params (clearer for the model):**
```
run-command(profile="prod-web-1", session="deploy", command="git pull")
run-command(profile="prod-web-2", session="deploy", command="git pull")
```

**Option B — composite ref (shorthand):**
```
run-command(session="deploy@prod-web-1", command="git pull")
run-command(session="deploy@prod-web-2", command="git pull")
```

Both are supported. The `@` syntax is parsed as `{session}@{profile}`. When `profile` is omitted, the default profile is used.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ConnectionRegistry                               │
│                                                                     │
│  Profile lookup (TOML config)  ←→  Live connections (Map<name, SSH>)│
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ SSHConnection     │  │ SSHConnection     │  │ SSHConnection     │  │
│  │ profile: prod-web │  │ profile: staging  │  │ profile: dev      │  │
│  │                   │  │                   │  │                   │  │
│  │ ssh2.Client       │  │ ssh2.Client       │  │ ssh2.Client       │  │
│  │ (persistent,      │  │ (persistent,      │  │ (persistent,      │  │
│  │  keepalive,       │  │  keepalive)       │  │  keepalive)       │  │
│  │  reconnect)       │  │                   │  │                   │  │
│  │                   │  │ Sessions:         │  │ Sessions:         │  │
│  │ Sessions:         │  │  ┌──────────────┐ │  │  (none — stateless│  │
│  │  ┌──────────────┐ │  │  │ "deploy"     │ │  │   exec() only)    │  │
│  │  │ "main"       │ │  │  │ interactive  │ │  │                   │  │
│  │  │ interactive  │ │  │  │ CWD: /srv    │ │  │                   │  │
│  │  │ CWD: /app    │ │  │  │ ENV: PATH=.. │ │  │                   │  │
│  │  │ ENV: NODE=.. │ │  │  │ PID: 1234    │ │  │                   │  │
│  │  │ lastCmd: 2s  │ │  │  │ lastCmd: 30s │ │  │                   │  │
│  │  └──────────────┘ │  │  └──────────────┘ │  │                   │  │
│  │  ┌──────────────┐ │  │                   │  │                   │  │
│  │  │ "tail"       │ │  │ Concurrency:      │  │                   │  │
│  │  │ background   │ │  │  Semaphore(9)     │  │                   │  │
│  │  │ tail -f log  │ │  │  (MaxSessions-1)  │  │                   │  │
│  │  └──────────────┘ │  │                   │  │                   │  │
│  │                   │  │                   │  │                   │  │
│  │ Concurrency:      │  │                   │  │                   │  │
│  │  Semaphore(9)     │  │                   │  │                   │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                     │
│  Lifecycle:                                                         │
│  - idleReap: connections idle > 15min → close                       │
│  - healthCheck: keepaliveInterval=15s, countMax=3                   │
│  - reconnect: on RESOURCE_SHORTAGE or error, 1 retry                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Session Types

### 1. Interactive Session (stateful shell)

A persistent `conn.shell()` with PTY. State (CWD, env vars, background processes) persists between commands.

**How it works:**
```
Agent calls: open-session(profile="prod-web", name="main", type="interactive")

→ SSHConnection opens ONE conn.shell({ pty: { term: 'xterm-256color' } })
→ Stores the stream in InteractiveSession
→ Returns session metadata

Agent calls: run-in-session(session="main", command="cd /var/www")

→ Session writes to stream: `cd /var/www\n`
→ Session writes sentinel: `echo "__DONE_<uuid>__$?"\n`
→ Reads until sentinel matched → extracts exit code + output
→ Updates session.cwd, session.lastActivity
→ Returns { output, exitCode, cwd }

Agent calls: run-in-session(session="main", command="ls")

→ Session writes `ls\n` + sentinel
→ CWD is still /var/www (state persisted!)
→ Returns file listing
```

**Sentinel-based completion (replaces unreliable `#` prompt detection):**
```typescript
const marker = crypto.randomUUID().replace(/-/g, '');
const sentinel = `__SSHMCP_${marker}__EXIT:$?__`;
stream.write(`${command}\n`);
stream.write(`printf '\\n${sentinel}\\n'\n`);

// In data handler, look for EXACT sentinel match:
const regex = new RegExp(`__SSHMCP_${marker}__EXIT:(\\d+)__`);
const match = buffer.match(regex);
if (match) {
  const exitCode = parseInt(match[1]);
  // Extract output between command echo and sentinel
}
```

This is immune to:
- `#` appearing in command output (cd /usr/local/#)
- ANSI escape codes
- Multiline output
- Prompt variations

The UUID makes it unguessable — output can't fake completion.

### 2. Background Session (long-running process)

A command started in its own exec() channel that stays open. Agent can poll for output.

**Use cases:**
- `tail -f /var/log/nginx/access.log`
- `npm run build` (long-running, check later)
- `htop`-style monitoring

**How it works:**
```
Agent: open-session(profile="prod-web", name="tail-logs", type="background", command="tail -f /var/log/syslog")

→ exec() channel opened, command started, NOT closed
→ Output streamed to an internal ring buffer (last 100KB)
→ Session marked as "running"

Agent: read-session-output(session="tail-logs", lines=50)

→ Returns last 50 lines from ring buffer
→ Session still running

Agent: close-session(session="tail-logs")

→ channel.signal('TERM') → stream.close()
```

### 3. Stateless Exec (default, no session needed)

`read-command` and `run-command` use `exec()` directly. No state between calls. This is the safe default — each command is a fresh channel.

```bash
# This works (single command):
run-command: "cd /var/www && ls"

# This does NOT work (two separate stateless calls):
run-command: "cd /var/www"   # CWD lost after this
run-command: "ls"             # runs in home dir
```

For stateful behavior, use interactive sessions.

---

## Tool Surface (Updated — 10 tools)

| Tool | Purpose | Session? |
|------|---------|----------|
| `list-connections` | List all profiles + connection status + active sessions | — |
| `list-sessions` | List active sessions for a profile | — |
| `open-session` | Create a named session (interactive or background) | creates |
| `close-session` | Close a named session | closes |
| `read-command` | Stateless exec(), allowlisted, readOnlyHint:true | — |
| `run-command` | Stateless exec(), OR with `session` param → send to interactive | optional |
| `run-in-session` | Send command to named interactive session (CWD/env persists) | required |
| `privileged-command` | sudo via stdin exec() | — |
| `sftp-upload` | Upload file via SFTP | — |
| `sftp-download` | Download file via SFTP | readOnlyHint:true |
| `signal-process` | Send signal to PID (in a session or globally) | optional |

Alternatively, `run-command` can accept an optional `session` parameter — if provided, it runs in that session; if not, it's stateless. This avoids a separate `run-in-session` tool.

### MCP Resources (for discovery)

```
ssh://connections                    → JSON: all profiles, status, session count
ssh://connections/{profile}          → JSON: profile details + active sessions
ssh://connections/{profile}/{session}→ JSON: session metadata (cwd, env, last command, uptime)
ssh://connections/{profile}/{session}/output → last N lines of output (background sessions)
```

The agent can read these resources to discover what's available without trial-and-error tool calls.

---

## Data Structures

```typescript
// src/ssh/connection-registry.ts
class ConnectionRegistry {
  private connections: Map<string, SSHConnection>;
  private profiles: Map<string, Profile>;

  async getOrCreate(profileName: string, opts?: ConnectOpts): Promise<SSHConnection>;
  async listConnections(): ConnectionInfo[];
  async close(profileName: string): Promise<void>;
  async closeAll(): Promise<void>;
}

// src/ssh/connection.ts
class SSHConnection {
  readonly profile: Profile;
  private client: ssh2.Client;
  private sessions: Map<string, Session>;
  private concurrencySem: Semaphore;  // MaxSessions - 1

  async ensureConnected(): Promise<void>;
  async exec(command: string, opts?: ExecOpts): Promise<ExecResult>;  // stateless
  async openSession(name: string, opts: SessionOpts): Promise<Session>;
  async closeSession(name: string): Promise<void>;
  async listSessions(): SessionInfo[];
  async close(): Promise<void>;

  get isConnected(): boolean;
  get sessionCount(): number;
  get activeChannelCount(): number;  // sessions + in-flight exec() channels
}

// src/ssh/session.ts
abstract class Session {
  readonly id: string;
  readonly name: string;
  readonly connection: SSHConnection;
  readonly type: 'interactive' | 'background';
  readonly createdAt: Date;
  lastActivity: Date;
  ttlMs: number;  // idle timeout, default 10min
  cwd: string;
  env: Record<string, string>;

  abstract run(command: string): Promise<CommandResult>;
  abstract close(): Promise<void>;
  isExpired(): boolean;
}

class InteractiveSession extends Session {
  private stream: ssh2.ClientChannel;  // persistent shell PTY
  private buffer: string;

  async run(command: string): Promise<CommandResult> {
    // 1. Write command + sentinel
    // 2. Wait for sentinel match (with timeout)
    // 3. Parse output + exit code
    // 4. Update cwd/env if command was cd/export
    // 5. Update lastActivity
  }

  async close(): Promise<void> {
    this.stream.end();
  }
}

class BackgroundSession extends Session {
  private stream: ssh2.ClientChannel;
  private ringBuffer: RingBuffer<string>;  // last 100KB of output
  private exitCode: number | null;

  async run(command: string): Promise<CommandResult>;  // starts the bg command
  readOutput(lines?: number): string[];
  isRunning(): boolean;

  async close(): Promise<void> {
    this.stream.signal('TERM');
    // wait briefly, then close
  }
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  cwd?: string;  // interactive sessions only
  sessionId?: string;
}
```

---

## Security Considerations

1. **Sentinel unguessability:** UUID v4 per command → output cannot fake completion. No prompt-detection guessing.

2. **PTY leak prevention (Issue #34 fix):**
   - Each interactive session = exactly ONE `conn.shell()` call
   - PTY stays open until explicit `close-session` or TTL expiry
   - Session count capped (e.g., max 5 sessions per connection)
   - Total channels (sessions + exec) capped at `MaxSessions - 1`
   - Concurrency semaphore prevents opening more channels than the server allows

3. **Session TTL & idle reaping:**
   - Default: 10min idle timeout for interactive sessions
   - Background sessions: configurable, max 1hr
   - Expired sessions auto-closed → PTY released
   - `list-sessions` shows remaining TTL

4. **Audit logging:**
   - Every `run-in-session` command produces an audit record with `session.id`
   - Background session output is NOT logged in full (only metadata + last N lines on close)
   - Session open/close events are audited

5. **Concurrency model:**
   ```
   MaxSessions = 10 (server default)
   Reserved = 1 (for SFTP or reconnect)
   Available = 9
   
   Interactive sessions consume 1 channel each (persistent)
   Background sessions consume 1 channel each (persistent)
   Stateless exec() consumes 1 channel (transient, released on completion)
   
   Semaphore(MaxSessions - 1) gates all channel allocations
   ```

6. **Reconnection:**
   - If connection drops, all sessions are marked as `disconnected`
   - Interactive sessions cannot be restored (state lost) — agent must re-open
   - Connection auto-reconnects (1 retry), but sessions need explicit re-creation
   - `list-sessions` shows disconnected sessions with `status: "disconnected"`

7. **Shell injection via session name:**
   - Session names validated (alphanumeric + dash/underscore, max 64 chars)
   - Never interpolated into shell commands

8. **Output size limits:**
   - Interactive session: per-command output capped at `maxOutputBytes` (default 1MB)
   - Background session: ring buffer capped at 100KB
   - Prevents memory exhaustion from `yes` / `cat /dev/urandom`

---

## Example Agent Workflow

```
Agent: "I need to deploy the app on prod-web-1"

1. Agent calls list-connections
   → sees prod-web-1 is connected, 0 active sessions

2. Agent calls open-session(profile="prod-web-1", name="deploy", type="interactive")
   → session created, shell ready

3. Agent calls run-command(session="deploy", command="cd /opt/myapp")
   → cwd updated to /opt/myapp

4. Agent calls run-command(session="deploy", command="git pull origin main")
   → runs in /opt/myapp, output returned

5. Agent calls run-command(session="deploy", command="npm ci && npm run build")
   → build runs in same CWD, env vars from .nvmrc still active

6. Agent calls privileged-command(command="systemctl restart myapp")
   → sudo via stdin, separate exec channel (stateless)

7. Agent calls run-command(session="deploy", command="curl -s localhost:3000/health")
   → health check in same session

8. Agent calls close-session(session="deploy")
   → PTY released, channel freed

9. Agent calls list-connections
   → prod-web-1: 0 active sessions, connection still alive for future calls
```

---

## Why This Doesn't Reintroduce Issue #34

| Issue #34 Root Cause | v2 Fix |
|---|---|
| `ensureElevated()` opens new shell each time | Session = ONE shell, opened once |
| Data handlers accumulate (removeListener inside `#` branch only) | Sentinel-based: handler removed after EVERY command |
| `#` prompt detection unreliable | UUID sentinel — no guessing |
| No session count limit | Max sessions per connection (configurable, default 5) |
| No concurrency cap | Semaphore(MaxSessions-1) |
| No idle reaping | TTL + idle timeout (configurable, default 10min) |
| su shell + exec interleave chaotically | No su shell at all; sessions are explicit |

---

## Multi-Host Workflow Patterns

### Pattern 1: Parallel deploy across N hosts

```
Agent: "Deploy v2.3.1 to all web servers"

1. list-connections
   → prod-web-1: connected, prod-web-2: connected, prod-web-3: connected

2. open-session(profile="prod-web-1", name="deploy")
   open-session(profile="prod-web-2", name="deploy")
   open-session(profile="prod-web-3", name="deploy")

3. run-command(session="deploy@prod-web-1", "cd /opt/app && git checkout v2.3.1")
   run-command(session="deploy@prod-web-2", "cd /opt/app && git checkout v2.3.1")
   run-command(session="deploy@prod-web-3", "cd /opt/app && git checkout v2.3.1")
   (these run in parallel — different connections, no shared state)

4. privileged-command(profile="prod-web-1", "systemctl restart app")
   privileged-command(profile="prod-web-2", "systemctl restart app")
   privileged-command(profile="prod-web-3", "systemctl restart app")

5. close-session(profile="prod-web-1", name="deploy")
   close-session(profile="prod-web-2", name="deploy")
   close-session(profile="prod-web-3", name="deploy")
```

### Pattern 2: Cross-host file transfer

```
Agent: "Copy the config from staging-db to prod-web-1"

1. sftp-download(profile="staging-db", path="/etc/myapp/config.toml")
   → returns file content (or saves to local temp)

2. sftp-upload(profile="prod-web-1", path="/etc/myapp/config.toml", content=...)
   → writes to prod-web-1
```

### Pattern 3: Monitoring across hosts

```
Agent: "Show me disk usage on all database servers"

1. read-command(profile="db-1", command="df -h /")
2. read-command(profile="db-2", command="df -h /")
3. read-command(profile="db-3", command="df -h /")
   (stateless, parallelizable — readOnlyHint:true)
```

### Pattern 4: Bastion / ProxyJump

```
Config:
  [[profiles]]
  name = "bastion"
  host = "bastion.example.com"

  [[profiles]]
  name = "internal-db"
  host = "10.0.1.50"
  via = "bastion"          # SSH sock through bastion

Agent:
  run-command(profile="internal-db", "SELECT 1")
  → connection socks through bastion, no agent forwarding
```

### Pattern 5: Long-running monitoring session

```
Agent: "Start watching the nginx logs on prod-web-1"

1. open-session(profile="prod-web-1", name="nginx-logs", type="background", command="tail -f /var/log/nginx/access.log")
   → session running, ring buffer collecting output

2. (do other work...)

3. read-session-output(session="nginx-logs@prod-web-1", lines=20)
   → last 20 lines from the tail

4. (later...)
   read-session-output(session="nginx-logs@prod-web-1", lines=20)
   → fresh output since last read

5. close-session(session="nginx-logs@prod-web-1")
   → tail killed, channel released
```

---

## Connection Lifecycle States

```
                    ┌─────────┐
     getOrCreate()  │ PENDING │  (connecting, authenticating)
   ───────────────▶ │         │
                    └────┬────┘
                         │ ready
                         ▼
                    ┌─────────┐    health check fail    ┌─────────┐
                    │CONNECTED│ ─────────────────────▶ │RECONNECT│
                    │         │                        │ (1 retry)│
                    └────┬────┘                        └────┬────┘
                         │ idle > 15min                     │ fail
                         │ or explicit close                ▼
                         ▼                            ┌─────────┐
                    ┌─────────┐                      │  ERROR  │
                    │ CLOSED  │ ◀─────────────────── │         │
                    └─────────┘                      └─────────┘
```

When a connection transitions to ERROR or CLOSED:
- All its sessions are marked `disconnected`
- Interactive session state (CWD, env) is lost
- `list-sessions` shows them with `status: "disconnected"`
- Agent must explicitly `close-session` and `open-session` again

---

## Config Schema (Complete)

```toml
# ~/.config/ssh-mcp/config.toml

[defaults]
defaultProfile = "dev-local"
sessionMaxPerConnection = 5        # max interactive+bg sessions per host
sessionIdleTimeoutMs = 600000      # 10min idle → auto-close session
sessionBackgroundMaxMs = 3600000   # 1hr max for background sessions
commandTimeoutMs = 60000           # per-command timeout
commandMaxChars = 5000             # max command length
commandMaxOutputBytes = 1048576    # 1MB output cap per command
connectionIdleReapMs = 900000      # 15min → close idle connection
approvalMode = "ask-destructive"   # auto | ask-destructive | ask-all | deny

[[profiles]]
name = "prod-web-1"
host = "10.0.1.50"
port = 22
user = "deploy"
auth = "agent"                     # agent | key | password | keychain
# keyRef = "~/.ssh/id_ed25519"    # for auth=key
# keychainEntry = "ssh-mcp/prod-web-1"  # for auth=keychain
via = "bastion"                    # ProxyJump profile name
workdir = "/var/www/myapp"
trustedHostKey = "SHA256:abc123..." # or omit for TOFU
tty = false
timeout = 30000
maxChars = 5000
role = "operator"                  # maps to policy rules
readOnly = false
approvalPolicy = "manual"          # override defaults.approvalMode for this host
cert = false                       # enable SSH cert auth
sessionMaxPerConnection = 3        # override for this host (stricter)
sessionIdleTimeoutMs = 300000      # 5min for prod (stricter)

[[profiles]]
name = "dev-local"
host = "localhost"
user = "developer"
auth = "agent"
role = "admin"
readOnly = false
approvalPolicy = "auto"            # dev is permissive
```

---

## Implementation Priority

This is a **P1** feature (core for v2.0). The modules:

```
src/
  ssh/
    connection-registry.ts   # ConnectionRegistry — profile → connection
    connection.ts            # SSHConnection — persistent client + session manager
    session.ts               # Session, InteractiveSession, BackgroundSession
    exec.ts                  # stateless exec() helper
    sftp.ts                  # SFTP operations
    algorithms.ts            # frozen algorithm allow-list
    host-key.ts              # TOFU host key verifier
  config/
    loader.ts                # TOML config loader + zod validation
    credential-resolver.ts   # cascade: agent → keychain → age → env → prompt
  policy/
    engine.ts                # YAML policy engine
    classifier.ts            # command → read-only|safe|destructive|privileged
    rules.ts                 # denylist + role bindings
  guard/
    sanitizer.ts             # command + metadata sanitization
    redactor.ts              # 3-layer output redaction
    elicitation.ts           # MCP elicitation for approvals
  audit/
    store.ts                 # append-only JSONL
    redactor.ts              # field/regex/entropy redaction
    schema.ts                # ECS field names
  transport/
    stdio.ts                 # default stdio transport
    http.ts                  # optional Streamable HTTP + OAuth
  tools/
    connection-tools.ts      # list-connections, list-sessions
    session-tools.ts         # open-session, close-session
    exec-tools.ts            # read-command, run-command, privileged-command
    sftp-tools.ts            # sftp-upload, sftp-download
    signal-tools.ts          # signal-process
  index.ts                   # MCP server setup + tool registration
```
