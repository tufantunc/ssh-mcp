---
"ssh-mcp": minor
---

HTTP transport: MCP sessions that clients abandon without a `DELETE` no longer fill the 64-session limit for good (#253). A session with no request in flight and no open SSE stream expires after `--httpSessionTtl` (default 30 minutes), and at the cap a new client is admitted by evicting the least-recently-active such session — one holding its SSE stream only when nothing else is evictable, and never one with a request in flight. The eviction happens only once the new session is admitted, so an `initialize` the server goes on to refuse costs no one their session.

**Upgrade note — minor, not patch, because a client that used to keep its session can now lose it.** A session left idle past the TTL, or evicted at the cap, answers `404 Session not found or expired`, and the client has to re-initialize. A client that cannot do that should keep a request or its SSE stream open, or run with a larger `--httpSessionTtl`.
