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
- [Docker Usage](#docker-usage)
- [Multi-Host Usage](#multi-host-usage)
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
- Built with TypeScript and the official MCP SDK
- **Multi-host support** - manage connections to multiple SSH servers simultaneously
- **Persistent connections** - connection pooling for better performance
- **Configurable timeout protection** with automatic process abortion
- **Graceful timeout handling** - attempts to kill hanging processes before closing connections

### Tools

- `exec`: Execute a shell command on the remote server
  - **Parameters:**
    - `command` (required): Shell command to execute on the remote SSH server
    - `description` (optional): Optional description of what this command will do (appended as a comment)
    - `host` (optional): Target host to execute command on (supports multiple hosts)
  - **Timeout Configuration:**
    - Timeout is configured via command line argument `--timeout` (in milliseconds)
    - Default timeout: 60000ms (1 minute)
    - When a command times out, the server automatically attempts to abort the running process before closing the connection

- `sudo-exec`: Execute a shell command with sudo elevation
  - **Parameters:**
    - `command` (required): Shell command to execute as root using sudo
    - `description` (optional): Optional description of what this command will do (appended as a comment)
    - `host` (optional): Target host to execute command on (supports multiple hosts)
  - **Notes:**
    - Requires `--sudoPassword` to be set for password-protected sudo
    - Can be disabled by passing the `--disableSudo` flag at startup if sudo access is not needed or not available
    - For persistent root access, consider using `--suPassword` instead which establishes a root shell
    - Tool will not be available at all if server is started with `--disableSudo`

- `list-hosts`: List all active SSH connections in the connection pool
  - **Parameters:** None
  - **Returns:** List of hosts with their connection status (connected/not connected)
  - **Notes:**
    - Shows which hosts are currently connected
    - Useful for managing multiple SSH connections
    - Connection key format: `user@host`

**Configuration:**
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

## Docker Usage

SSH MCP Server can be containerized and used with Docker or Docker MCP Gateway for isolated and portable deployments.

### Building the Docker Image

```bash
# Build the image
docker build -t ssh-mcp:latest .

# Or using docker compose
docker compose -f docker-compose.example.yml build
```

### Running with Docker

**Basic usage with password authentication:**
```bash
docker run -i \
  ssh-mcp:latest \
  --host=192.168.1.100 \
  --user=admin \
  --password=your_password
```

**With SSH key authentication:**
```bash
docker run -i \
  -v ~/.ssh/id_rsa:/root/.ssh/id_rsa:ro \
  ssh-mcp:latest \
  --host=example.com \
  --user=root \
  --key=/root/.ssh/id_rsa
```

**With sudo support:**
```bash
docker run -i \
  ssh-mcp:latest \
  --host=192.168.1.100 \
  --user=admin \
  --password=user_password \
  --sudoPassword=sudo_password \
  --timeout=120000
```

### Using with Docker MCP Gateway

Docker MCP Gateway allows you to run MCP servers in containers and connect them to Claude Desktop or other MCP clients.

**1. Build and publish the image (optional):**
```bash
# Tag for your registry
docker build -t your-registry/ssh-mcp:latest .
docker push your-registry/ssh-mcp:latest
```

**2. Configure Docker MCP Gateway:**

Add to your MCP Gateway configuration:
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "ssh-mcp:latest",
        "--host=YOUR_HOST",
        "--user=YOUR_USER",
        "--password=YOUR_PASSWORD"
      ]
    }
  }
}
```

**3. Using docker-compose with MCP Gateway:**

Create a `docker-compose.yml` based on the example file:
```bash
# Copy and customize the example
cp docker-compose.example.yml docker-compose.yml
# Edit docker-compose.yml with your settings
```

Configure MCP Gateway to use the compose service:
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "docker",
      "args": [
        "compose",
        "exec",
        "-T",
        "ssh-mcp-gateway"
      ]
    }
  }
}
```

### Environment Variables

For security, you can use environment variables with Docker:

```bash
# Create a .env file
cat > .env << EOF
SSH_HOST=192.168.1.100
SSH_PORT=22
SSH_USER=admin
SSH_PASSWORD=your_password
SUDO_PASSWORD=sudo_password
EOF

# Run with environment variables
docker run -i --env-file .env \
  ssh-mcp:latest \
  --host=\${SSH_HOST} \
  --user=\${SSH_USER} \
  --password=\${SSH_PASSWORD}
```

**Security Note:** Never commit `.env` files or sensitive credentials to version control.

### Docker Image Details

- **Base Image:** Node.js 20 Alpine (minimal size)
- **Multi-stage build:** Optimized for production
- **Includes:** OpenSSH client for SSH key support
- **Entry Point:** `node build/index.js`

### Troubleshooting

**Permission issues with SSH keys:**
```bash
# Ensure correct permissions on host
chmod 600 ~/.ssh/id_rsa

# Then mount as read-only
docker run -i -v ~/.ssh/id_rsa:/root/.ssh/id_rsa:ro ssh-mcp:latest ...
```

**Network connectivity:**
```bash
# Use host network if container can't reach SSH server
docker run -i --network host ssh-mcp:latest --host=192.168.1.100 ...
```

## Multi-Host Usage

SSH MCP Server supports managing multiple SSH connections simultaneously. You can execute commands on different hosts by specifying the `host` parameter.

### How It Works

1. The server maintains a connection pool with persistent connections to each host
2. Connections are identified by `user@host:port` key
3. The `host` parameter supports two formats:
   - Hostname/IP only: `192.168.1.100` (uses default port from config)
   - Hostname/IP with port: `192.168.1.100:2222` or `example.com:22`
4. When you specify a `host` parameter in `exec` or `sudo-exec`, the server automatically:
   - Creates a new connection if needed
   - Reuses an existing connection if available
   - Manages the connection lifecycle independently

### Example Usage

**Using MCP Inspector or Claude Desktop:**

```javascript
// Execute command on default host
{
  "command": "ls -la /tmp",
  "description": "List files on server 1"
}

// Execute command on a different host (uses default port)
{
  "command": "df -h",
  "description": "Check disk space on server 2",
  "host": "192.168.1.101"
}

// Execute command on a host with specific port
{
  "command": "uptime",
  "description": "Check uptime on server 3",
  "host": "192.168.1.102:2222"
}

// Execute command on same host but different port
{
  "command": "hostname",
  "description": "Get hostname from alternate SSH port",
  "host": "192.168.1.100:2223"
}

// List all active connections
// Call the 'list-hosts' tool with no parameters
// Output format: user@host:port (connected/not connected)
```

### Benefits

- **Performance**: Persistent connections reduce connection overhead
- **Flexibility**: Manage multiple servers from a single MCP server instance
- **Reliability**: Independent connection management - issues on one host don't affect others
- **Convenience**: No need to start multiple MCP server instances

### Notes

- Each host connection uses the same authentication credentials (user/password/key) configured at startup
- For different user credentials per host, you'll need to start separate MCP server instances
- The `list-hosts` tool shows all active connections with format: `user@host:port (status)`
- You can connect to the same host on different ports (e.g., `192.168.1.100:22` and `192.168.1.100:2222` are treated as separate connections)
- Connection pooling ensures that repeated commands to the same host reuse existing connections for better performance

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