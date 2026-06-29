# SSH MCP Server

[![NPM Version](https://img.shields.io/npm/v/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Downloads](https://img.shields.io/npm/dm/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Node Version](https://img.shields.io/node/v/ssh-mcp)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/tufantunc/ssh-mcp)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/tufantunc/ssh-mcp?style=social)](https://github.com/tufantunc/ssh-mcp/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/tufantunc/ssh-mcp?style=social)](https://github.com/tufantunc/ssh-mcp/forks)
[![Build Status](https://github.com/tufantunc/ssh-mcp/actions/workflows/publish.yml/badge.svg)](https://github.com/tufantunc/ssh-mcp/actions)
[![GitHub issues](https://img.shields.io/github/issues/tufantunc/ssh-mcp)](https://github.com/tufantunc/ssh-mcp/issues)

[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/tufantunc/ssh-mcp)](https://archestra.ai/mcp-catalog/tufantunc__ssh-mcp)

**SSH MCP Server** is a local Model Context Protocol (MCP) server that exposes SSH control for Linux and Windows systems, enabling LLMs and other MCP clients to execute shell commands securely via SSH.

## Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Client Setup](#client-setup)
- [TOML config watch / hot reload](#toml-config-watch--hot-reload)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [Support](#support)

## Quick Start

- [Install](#installation) SSH MCP Server
- [Configure](#configuration) SSH MCP Server
- [Set up](#client-setup) your MCP Client (e.g. Claude Desktop, Cursor, etc)
- Execute remote shell commands on your Linux or Windows server via natural language

## Features

- MCP-compliant server exposing SSH capabilities
- Execute shell commands on remote Linux and Windows systems
- Secure authentication via password or SSH key
- **Kerberos / GSSAPI single-sign-on** via the OpenSSH subprocess transport — opt-in; see [Kerberos / OpenSSH Transport](#kerberos--openssh-transport)
- Built with TypeScript and the official MCP SDK
- **Configurable timeout protection** with automatic process abortion
- **Graceful timeout handling** - attempts to kill hanging processes before closing connections

### Tools

- `exec`: Execute a shell command on the remote server
  - **Parameters:**
    - `command` (required): Shell command to execute on the remote SSH server
    - `description` (optional): Optional description of what this command will do (appended as a comment)
  - **Timeout Configuration:**

- `sudo-exec`: Execute a shell command with sudo elevation
  - **Parameters:**
    - `command` (required): Shell command to execute as root using sudo
    - `description` (optional): Optional description of what this command will do (appended as a comment)
  - **Notes:**
    - Requires `--sudoPassword` to be set for password-protected sudo
    - Can be disabled by passing the `--disableSudo` flag at startup if sudo access is not needed or not available
    - For persistent root access, consider using `--suPassword` instead which establishes a root shell
    - Tool will not be available at all if server is started with `--disableSudo`
  - **Timeout Configuration:**
    - Timeout is configured via command line argument `--timeout` (in milliseconds)
    - Default timeout: 60000ms (1 minute)
    - When a command times out, the server automatically attempts to abort the running process before closing the connection
  - **Max Command Length Configuration:**
    - Max command characters are configured via `--maxChars`
    - Default: `1000`
    - No-limit mode: set `--maxChars=none` or any `<= 0` value (e.g. `--maxChars=0`)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tufantunc/ssh-mcp.git
   cd ssh-mcp
   ```
2. **Install dependencies:**
   ```bash
   npm install
   ```

## Client Setup

You can configure your IDE or LLM like Cursor, Windsurf, Claude Desktop to use this MCP Server.

**Required Parameters:**
- `host`: Hostname or IP of the Linux or Windows server
- `user`: SSH username

**Optional Parameters:**
- `port`: SSH port (default: 22)
- `password`: SSH password (or use `key` for key-based auth)
- `key`: Path to private SSH key
- `sudoPassword`: Password for sudo elevation (when executing commands with sudo)
- `suPassword`: Password for su elevation (when you need a persistent root shell)
- `timeout`: Command execution timeout in milliseconds (default: 60000ms = 1 minute)
- `maxChars`: Maximum allowed characters for the `command` input (default: 1000). Use `none` or `0` to disable the limit.
- `disableSudo`: Flag to disable the `sudo-exec` tool completely. Useful when sudo access is not needed or not available.
- `transport`: Transport implementation. `ssh2` (default, unchanged) or `openssh` (spawns the system `ssh` binary — needed for Kerberos). See [Kerberos / OpenSSH Transport](#kerberos--openssh-transport).
- `kerberos`: Flag shorthand for `--transport=openssh` with `GSSAPIAuthentication=yes`. Requires an active Kerberos ticket (TGT) on the client.
- `gssapiDelegateCredentials`: `yes` or `no` (default `no`). Forwards the client TGT to the remote host for second-hop SSO. Use only against trusted hosts.
- `knownHostsFile`: Path to a pinned `known_hosts` file (openssh transport only).
- `strictHostKeyChecking`: `yes`, `no`, or `accept-new` (default `accept-new`; openssh transport only).


```commandline
{
    "mcpServers": {
        "ssh-mcp": {
            "command": "npx",
            "args": [
                "ssh-mcp",
                "-y",
                "--",
                "--host=1.2.3.4",
                "--port=22",
                "--user=root",
                "--password=pass",
                "--key=path/to/key",
                "--timeout=30000",
                "--maxChars=none"
            ]
        }
    }
}
```

### Claude Code

You can add this MCP server to Claude Code using the `claude mcp add` command. This is the recommended method for Claude Code.

**Basic Installation:**

```bash
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=YOUR_HOST --user=YOUR_USER --password=YOUR_PASSWORD
```

**Installation Examples:**

**With Password Authentication:**
```bash
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=192.168.1.100 --port=22 --user=admin --password=your_password
```

**With SSH Key Authentication:**
```bash
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=example.com --user=root --key=/path/to/private/key
```

**With Custom Timeout and No Character Limit:**
```bash
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=192.168.1.100 --user=admin --password=your_password --timeout=120000 --maxChars=none
```

**With Sudo and Su Support:**
```bash
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=192.168.1.100 --user=admin --password=your_password --sudoPassword=sudo_pass --suPassword=root_pass
```

**Installation Scopes:**

You can specify the scope when adding the server:

- **Local scope** (default): For personal use in the current project
  ```bash
  claude mcp add --transport stdio ssh-mcp --scope local -- npx -y ssh-mcp -- --host=YOUR_HOST --user=YOUR_USER --password=YOUR_PASSWORD
  ```

- **Project scope**: Share with your team via `.mcp.json` file
  ```bash
  claude mcp add --transport stdio ssh-mcp --scope project -- npx -y ssh-mcp -- --host=YOUR_HOST --user=YOUR_USER --password=YOUR_PASSWORD
  ```

- **User scope**: Available across all your projects
  ```bash
  claude mcp add --transport stdio ssh-mcp --scope user -- npx -y ssh-mcp -- --host=YOUR_HOST --user=YOUR_USER --password=YOUR_PASSWORD
  ```


**Verify Installation:**

After adding the server, restart Claude Code and ask Cascade to execute a command:
```
"Can you run 'ls -la' on the remote server?"
```

For more information about MCP in Claude Code, see the [official documentation](https://docs.claude.com/en/docs/claude-code/mcp).

## Kerberos / OpenSSH Transport

> Experimental. Backwards-compatible: unchanged when `--transport` and `--kerberos` are both omitted.

The default `ssh2`-based transport does not implement GSSAPI/Kerberos authentication (upstream issue [mscdex/ssh2#333](https://github.com/mscdex/ssh2/issues/333), open since 2015). When an **opt-in** OpenSSH subprocess transport is selected, the server delegates SSH to the operating system's `ssh` binary, which supports:

- Kerberos SSO via GSSAPI (`-o GSSAPIAuthentication=yes`)
- Public-key auth (`-i <key>`)
- Password auth (via `SSH_ASKPASS`; not recommended — prefer Kerberos or keys)

### When to use it

- Windows client (domain-joined) → Linux target (AD-joined via SSSD/realmd, `sshd_config: GSSAPIAuthentication yes`): the user's logon TGT is consumed automatically by Win32-OpenSSH via SSPI. **No password. No key file.**
- Any environment where a Kerberos KDC issues tickets and SSH is preferred over re-entering credentials.

### Prerequisites

1. The `ssh` binary must be on `PATH` (Windows: enabled by default since Windows 10 1803; Linux: `apt install openssh-client`).
2. The **remote** `sshd_config` must have `GSSAPIAuthentication yes`.
3. The user must have a valid TGT:
   - **Windows (AD-joined):** automatic on login. Verify with `klist`.
   - **Linux (MIT Kerberos):** run `kinit <user@REALM>` or use `k5start` with a keytab for service accounts.
4. For an AD-integrated Linux target, SSSD/realmd must be joined to the domain.

### Example — Claude Code / any MCP client

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "npx",
      "args": [
        "-y", "ssh-mcp", "--",
        "--host=ubuntu-dev.example.internal",
        "--user=aduser@EXAMPLE.INTERNAL",
        "--kerberos"
      ]
    }
  }
}
```

Equivalent expanded form:

```bash
npx -y ssh-mcp -- \
  --transport=openssh \
  --host=ubuntu-dev.example.internal \
  --user=aduser@EXAMPLE.INTERNAL \
  --strictHostKeyChecking=accept-new
```

### CLI flags added by this mode

| Flag | Values | Default | Notes |
|---|---|---|---|
| `--transport` | `ssh2` / `openssh` | `ssh2` | Selects implementation |
| `--kerberos` | flag | off | Implies `--transport=openssh` |
| `--gssapiDelegateCredentials` | `yes` / `no` | `no` | Forward TGT (trusted hosts only) |
| `--knownHostsFile` | path | `~/.ssh/known_hosts` | `openssh` only |
| `--strictHostKeyChecking` | `yes` / `no` / `accept-new` | `accept-new` | `openssh` only |

### Caveats and limitations

- **No connection multiplexing on Windows.** Win32-OpenSSH does not support `ControlMaster` ([issue #1328](https://github.com/PowerShell/Win32-OpenSSH/issues/1328)). Each `exec` call spawns a fresh `ssh.exe` and performs a full Kerberos AP-REQ round trip. Expect ~100–300 ms extra latency per invocation on Windows. Linux/macOS may work around this with user-provided `ssh_config` `ControlMaster` settings — the transport does not configure multiplexing itself.
- **Password mode via `SSH_ASKPASS`.** When `--password` is combined with `--transport=openssh`, the server writes a short-lived askpass helper to `%TEMP%/ssh-mcp-<pid>/` and exports the password through a per-process environment variable. The password never appears in `argv` but is briefly visible to same-user-session process inspection. Prefer Kerberos or key auth.
- **`--suPassword` over OpenSSH transport** is implemented via `ssh -tt` with a local expect-style state machine (random-nonce sentinel prompts). Works, but has more moving parts than the ssh2 path. Report issues with stderr output if you hit a regression.
- **Delegation (`GSSAPIDelegateCredentials=yes`)** is off by default. Enabling it forwards your TGT to the remote host, which can then impersonate you elsewhere — use only against fully trusted infrastructure. See Microsoft's guidance on Kerberos delegation.

## TOML config watch / hot reload

When the server is started from a TOML config file (`--config=<path>`, `$SSH_MCP_CONFIG`, or a discovered `~/.config/ssh-mcp/config.toml` / `~/.ssh-mcp/config.toml`), it **watches that file and hot-reloads on change** — no restart needed. Edit the file, save, and within ~500ms the running server picks up the new configuration. (CLI/`--ssh=<JSON>` boots are not file-backed, so there is nothing to watch — the watcher is simply not started.)

### What reloads (and what does not)

| Reloaded live | NOT reloaded |
|---|---|
| The set of named connections (`[[sources]]`) and their parameters | The **MCP tool list** (`exec` / `sudo-exec` / `list-servers`) |
| Per-source `description` | The WebUI bind host/port/auth token |
| Approval policy: `[approval].mode` + per-source `[sources.approval].mode` | The audit-log destination |

A reload re-establishes the **file** as the source of truth: any live in-memory overrides made through the WebUI (an edited description, a switched approval mode) are dropped in favour of the freshly-loaded file values. All reload mutation is in-memory — the server **never writes the config file back**, so an edit can't feedback-loop with the watcher.

### Safety: validate-before-swap with rollback

A bad edit can't take the server down. The reload is transactional:

1. **Parse + validate** the new file. If it fails to parse or validate, the server logs the error and **keeps every existing connection and the current approval policy** untouched.
2. **Swap** connections + approval policy atomically. If any step fails (e.g. a key file became unreadable, or the new policy selects an approval mode whose engine wasn't armed at boot — see below), the server **rolls both layers back together** to the last known-good state.
3. **Broadcast** a `config-reloaded` SSE event so every open WebUI dashboard re-fetches and converges on the new server truth.

Multiple rapid saves (editors often fire several change events per save) are **debounced** into a single reload (~500ms window), and a change arriving while a reload is in flight is coalesced into exactly one trailing reload.

### STDIO transport caveat

> Hot reload refreshes connections, descriptions, and approval policy — it does **not** add or remove MCP tools. ssh-mcp's tool set (`exec` / `sudo-exec` / `list-servers`) is static and registered once at startup, so a STDIO client never needs to reconnect to keep working. The WebUI receives the `config-reloaded` SSE event and updates live; STDIO MCP clients see the new connection set the next time they call `list-servers` or target a connection by name. (This mirrors dbhub's documented STDIO limitation, where the tool list *is* config-derived; here it isn't, so the caveat is narrower.)

> **Switching INTO a newly-configured `smart` or `manual` mode needs a restart.** The approval sub-engines (yolo / smart / manual) are built once at boot from the engines that are *armed* then — e.g. `smart` is only armed when `[approval.llm]` was present at startup. A hot reload can freely switch *among already-armed* modes, but a reload that newly introduces `[approval.llm]` (or first enables the WebUI for `manual`) is rejected and rolled back; restart the server to arm the new engine. The same applies when the server booted with **no `[approval]` policy at all and the WebUI disabled** (no engine is wired, so the gate is `legacy:no-engine` allow): a reload that introduces any enforcing policy — a global or per-source mode other than `yolo` — is rejected and rolled back rather than reported as applied while commands keep running unenforced. Restart to arm the engine.

## Testing

You can use the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) for visual debugging of this MCP Server.

```sh
npm run inspect
```

## Disclaimer

SSH MCP Server is provided under the [MIT License](./LICENSE). Use at your own risk. This project is not affiliated with or endorsed by any SSH or MCP provider.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](./CONTRIBUTING.md) for more information.

## Code of Conduct

This project follows a [Code of Conduct](./CODE_OF_CONDUCT.md) to ensure a welcoming environment for everyone.

## Support

If you find SSH MCP Server helpful, consider starring the repository or contributing! Pull requests and feedback are welcome. 