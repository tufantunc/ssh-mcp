# MCP SSH Server

This is an MCP (Model Context Protocol) server that exposes SSH control for Linux servers. It allows LLMs and other MCP clients to execute commands via SSH, using the official MCP TypeScript SDK.

## Features
- MCP-compliant server exposing SSH capabilities
- Execute shell commands on remote Linux servers
- Built with TypeScript and the official MCP SDK

## Setup

1. **Clone the repository**
2. **Install dependencies:**
   ```bash
   npm install
   ```
3. **Configure environment variables:**
   - Copy `.env.example` to `.env` and fill in your SSH and server details.

## Environment Variables
- `SSH_HOST`: Hostname or IP of the Linux server
- `SSH_PORT`: SSH port (default: 22)
- `SSH_USER`: SSH username
- `SSH_PASSWORD`: SSH password (or use `SSH_KEY_PATH` for key-based auth)
- `SSH_KEY_PATH`: Path to private SSH key (optional)

## Building and Running the Server
```bash
npm run build
npm start
```

## MCP Tools
- `exec`: Execute a shell command on the remote server

## Example: Execute a Command
```json
{
  "tool": "exec",
  "parameters": {
    "command": "ls -la"
  }
}
```

## References
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- [MCP Server Quickstart](https://modelcontextprotocol.io/quickstart/server#node)

## License
MIT 