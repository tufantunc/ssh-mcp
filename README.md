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

**SSH MCP Server** is a local Model Context Protocol (MCP) server that exposes SSH control for Linux and Windows systems, enabling LLMs and other MCP clients to execute shell commands securely via SSH or Google IAP tunnel.

## 🔥 Dynamic Connections

**New in v2.0:** ssh-mcp now supports **dynamic connections** - specify the target server with each command instead of at server startup. One MCP server can manage connections to unlimited remote systems!

## Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Client Setup](#client-setup)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [Support](#support)

## Quick Start

- [Install](#installation) SSH MCP Server
- [Set up](#client-setup) your MCP Client (e.g. Claude Code, Claude Desktop, Cursor, etc)
- Ask Claude to execute commands on **any** remote server:
  - "List processes on vm-bastion in project prj-fgo-s-fdj" (Google IAP)
  - "Check disk space on 192.168.1.100" (Direct SSH)
  - **No server restart needed** - connections are created dynamically!

## Features

- MCP-compliant server exposing SSH capabilities
- Execute shell commands on remote Linux and Windows systems
- Secure authentication via password or SSH key
- **Google IAP (Identity-Aware Proxy) support** for secure access to GCP instances without public IPs
- Built with TypeScript and the official MCP SDK
- **Configurable timeout protection** with automatic process abortion
- **Graceful timeout handling** - attempts to kill hanging processes before closing connections

### Tools

- `exec`: Execute a shell command on the remote server
  - **Parameters:**
    - `command` (required): Shell command to execute on the remote SSH server
  - **Timeout Configuration:**

- `sudo-exec`: Execute a shell command with sudo elevation
  - **Parameters:**
    - `command` (required): Shell command to execute as root using sudo
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

### Dynamic Mode (Recommended - v2.0+)

In **dynamic mode**, you specify connection details **with each command** instead of at server startup. This allows Claude to connect to unlimited servers with a single MCP server.

**Global Parameters (optional):**
- `timeout`: Command execution timeout in milliseconds (default: 60000ms = 1 minute)
- `maxChars`: Maximum allowed characters for the `command` input (default: 1000). Use `none` or `0` to disable the limit.
- `disableSudo`: Flag to disable the `sudo-exec` tool completely

**Per-Command Parameters:**

Connection details are specified when Claude calls the `exec` or `sudo-exec` tools:

**For Direct SSH:**
- `host`: Hostname or IP address (required)
- `port`: SSH port (optional, default: 22)
- `user`: SSH username (required)
- `password`: SSH password (optional)
- `privateKey`: SSH private key content (optional)
- `privateKeyPath`: Path to SSH private key file (optional)
- `sudoPassword`: Password for sudo (optional)
- `suPassword`: Password for su elevation (optional)

**For Google IAP:**
- `iapInstance`: GCP VM instance name (required)
- `iapProject`: GCP project ID (required)
- `iapZone`: GCP zone (optional - gcloud auto-detects zone if not specified)
- `user`: SSH username (required)
- Authentication uses gcloud credentials (no password/key needed for IAP)
- `sudoPassword`: Password for sudo (optional)
- `suPassword`: Password for su elevation (optional)

**Note:** Google IAP mode uses `gcloud compute ssh --tunnel-through-iap` which handles authentication through your gcloud credentials. Make sure you're logged in with `gcloud auth login` and have the necessary IAP permissions.

### Claude Code

Add ssh-mcp to Claude Code using the `claude mcp add` command:

**Dynamic Mode (Recommended):**

```bash
# Basic setup - no connection details needed at startup!
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp

# With custom timeout and no character limit
claude mcp add --transport stdio ssh-mcp -- npx -y ssh-mcp -- --timeout=120000 --maxChars=none
```

**That's it!** Now ask Claude to connect to any server:

**Examples:**
- **"List processes on vm-fgo-s-fdj-bastion in project prj-fgo-s-fdj as user admin"**
  - Claude will use IAP to connect: `iapInstance=vm-fgo-s-fdj-bastion`, `iapProject=prj-fgo-s-fdj`, `user=admin`

- **"Check disk space on 192.168.1.100 as root with key /path/to/key"**
  - Claude will use direct SSH: `host=192.168.1.100`, `user=root`, `privateKeyPath=/path/to/key`

- **"Restart nginx on server.example.com"**
  - Claude will prompt for missing details (user, password, etc.)

**How Authentication Works:**

Claude needs to know credentials to connect. You can provide them:
1. **In your prompt:** "Connect to 192.168.1.100 as user admin with password secret123"
2. **Via environment variables** (for security - coming soon)
3. **Stored in Claude's context** (Claude remembers credentials during the conversation)

**Security Note:** Avoid hardcoding passwords in prompts. Use SSH keys when possible: `privateKeyPath=/path/to/key`

---

### Static Mode (Legacy - v1.x compatibility)

In **static mode**, you specify connection details **at server startup**. One MCP server connects to one specific remote system. This mode is for backward compatibility and simple single-server setups.

**Command-line usage:**

```bash
# Direct SSH mode
node build/index.js --host=192.168.1.100 --user=root --password=secret --timeout=60000

# Google IAP mode
node build/index.js --iapInstance=vm-name --iapProject=project-id --user=admin --iapZone=us-central1-a

# With SSH key
node build/index.js --host=server.example.com --user=deploy --key=/path/to/id_rsa
```

**Available startup parameters:**
- `--host`: SSH hostname or IP (for direct SSH)
- `--port`: SSH port (default: 22)
- `--iapInstance`: GCP VM instance name (for IAP mode)
- `--iapProject`: GCP project ID (for IAP mode)
- `--iapZone`: GCP zone (optional - auto-detected)
- `--user`: SSH username (required)
- `--password`: SSH password
- `--key`: Path to SSH private key file
- `--sudoPassword`: Password for sudo commands
- `--suPassword`: Password for su elevation
- `--timeout`: Command timeout in ms (default: 60000)
- `--maxChars`: Max command length (default: 1000)
- `--disableSudo`: Disable sudo-exec tool

**Note:** In static mode, you don't need to provide connection parameters with each command - they're pre-configured at startup.

### HTTP/SSE Mode

In **HTTP/SSE mode**, the server runs as a web service using Express, allowing MCP clients to connect via Server-Sent Events (SSE) and HTTP POST requests. This is useful for remote deployments, Docker containers, or environments where standard input/output (stdio) is not available.

**Command-line usage:**

```bash
# Start the server on port 3000
node build/index.js --port=3000
```

**Endpoints:**
- `GET /sse`: SSE endpoint for establishing the MCP connection
- `POST /message`: Endpoint for sending JSON-RPC messages from the client
- `GET /health`: Health check endpoint returning status and mode

**Client Configuration:**

To connect a client like Claude Desktop or another MCP client to the HTTP endpoint:

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "node",
      "args": ["build/index.js", "--port=3000"],
      "url": "http://localhost:3000/sse"
    }
  }
}
```

**Docker Example:**

```bash
docker run -p 3000:3000 -v ~/.ssh:/root/.ssh -v ~/.config/gcloud:/root/.config/gcloud ssh-mcp --port=3000
```

**Verify Installation:**

After adding the server, restart Claude Code and ask Cascade to execute a command:
```
"Can you run 'ls -la' on the remote server?"
```

For more information about MCP in Claude Code, see the [official documentation](https://docs.claude.com/en/docs/claude-code/mcp).

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