---
"ssh-mcp": patch
---

Require `@modelcontextprotocol/sdk` `^1.31.0` (was `^1.30.0`), so an install can no longer keep an SDK affected by GHSA-6qxp-vccf-f47h (the SDK's OAuth client could send credentials to an authorization server the MCP server chose). That SDK also brings `proxy-addr` 2.0.8, past GHSA-jqcg-44mw-7w3h. Neither is reachable through this server — it uses neither the SDK's OAuth client nor express's proxy trust, and its HTTP transport resolves client addresses itself — but a dependency scanner reports both against any install that still resolves the older versions.
