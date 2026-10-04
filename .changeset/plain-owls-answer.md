---
"ssh-mcp": patch
---

HTTP transport: an MCP request that fails inside the server, such as when creating the session's server throws, now gets a `500` JSON-RPC internal error and a line on stderr, instead of no answer and an unhandled promise rejection.
