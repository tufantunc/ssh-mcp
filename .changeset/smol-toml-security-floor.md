---
"ssh-mcp": patch
---

**Security:** require `smol-toml` 1.7.1 or newer, which fixes a denial of service via malformed TOML documents ([GHSA-7w5x-hrqm-74c2](https://github.com/advisories/GHSA-7w5x-hrqm-74c2), high).

`smol-toml` is what parses `config.toml`, so the parser sits directly in front of operator-supplied input. The declared range was `^1.7.0`, which still permits the affected version: a fresh install resolves to a fixed one, but anything holding an existing lockfile entry at 1.7.0 would keep it. Raising the floor is the only part of that we control.

The transitive `hono` bump that landed alongside it (moderate, reachable only through the HTTP transport, which pulls it via `@hono/node-server` inside the MCP SDK) is a lockfile update: the range belongs to the SDK, not to this package.
