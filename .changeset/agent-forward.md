---
"ssh-mcp": minor
---

A profile may set `forwardAgent = true` to forward the local SSH agent for the life of the connection. It is off by default and only valid with `auth = "agent"`. Changing it closes the connection. An agent handshake waits 60 seconds so a FIDO touch can finish; key and password authentication keep the 20 second bound.
