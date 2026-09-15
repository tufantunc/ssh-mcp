---
"ssh-mcp": patch
---

**Fix:** a profile whose handshake was cut short can reconnect, instead of failing every later call until the server is restarted ([#197](https://github.com/tufantunc/ssh-mcp/issues/197)).

If a connection dropped mid-handshake — an `sshd` restarting under a running command is the usual way — the failed attempt stayed cached. `ensureConnected()` returned that same rejected promise to every later call on the profile, so every tool call failed instantly with a stale message, including read-only ones, and the profile stayed broken even after the server came back. Restarting the MCP server was the only way out.

The cause was a conflation: clearing the cached attempt was gated on the connection still owning the current client, and the disconnect handler clears that client first. Ownership of the cached attempt is now tracked on its own, so a failed handshake leaves nothing behind and the next call tries again.
