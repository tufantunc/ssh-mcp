# SSH MCP Server

[![License](https://img.shields.io/github/license/tufantunc/ssh-mcp)](./LICENSE)
[![NPM Version](https://img.shields.io/npm/v/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)

**SSH MCP Server** is a local Model Context Protocol (MCP) server that exposes SSH control for Linux servers, enabling LLMs and other MCP clients to execute shell commands securely via SSH.

## Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Client Setup](#client-setup)
- [Example Usage](#example-usage)
- [Disclaimer](#disclaimer)
- [Support](#support)

## Quick Start

- [Install](#installation) SSH MCP Server
- [Configure](#configuration) SSH MCP Server
- [Set up](#client-setup) your MCP Client (e.g. Claude Desktop, Cursor, etc)
- Execute remote shell commands on your Linux server via natural language

## Features

- MCP-compliant server exposing SSH capabilities
- Execute shell commands on remote Linux servers
- Secure authentication via password or SSH key
- Built with TypeScript and the official MCP SDK

### Tools

- `exec`: Execute a shell command on the remote server

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

## Configuration

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```
2. **Edit `.env` with your SSH and server details:**
   - `SSH_HOST`: Hostname or IP of the Linux server
   - `SSH_PORT`: SSH port (default: 22)
   - `SSH_USER`: SSH username
   - `SSH_PASSWORD`: SSH password (or use `SSH_KEY_PATH` for key-based auth)
   - `SSH_KEY_PATH`: Path to private SSH key (optional)

## Client Setup

SSH MCP Server is compatible with any MCP client, such as Claude Desktop, Cursor, or MCP Inspector.

- Configure your client to connect to the SSH MCP Server endpoint.
- Use the `exec` tool to run shell commands on your remote server.



## Example Usage

Example JSONRPC request to execute a command:

```json
{
  "tool": "exec",
  "parameters": {
    "command": "ls -la"
  }
}
```

## Disclaimer

SSH MCP Server is provided under the [MIT License](./LICENSE). Use at your own risk. This project is not affiliated with or endorsed by any SSH or MCP provider.

## Support

If you find SSH MCP Server helpful, consider starring the repository or contributing! Pull requests and feedback are welcome. 