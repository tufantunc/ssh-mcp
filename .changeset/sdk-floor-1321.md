---
"ssh-mcp": patch
---

Require `@modelcontextprotocol/sdk` `^1.32.1` (was `^1.31.0`), so an install can no longer keep an SDK affected by GHSA-46jr-4wx8-v453 (one HTTP request could exhaust server memory while it was validated). Over this server's HTTP transport that request is only accepted after the bearer token check, and the body is capped at 1 MiB, so it takes a token holder to send it. The same SDK release also fixes GHSA-rvq5-wwqv-78pq, GHSA-22jm-h49p-29qw and GHSA-6prh-2h8m-c8cw, none of which this server reaches: it checks its own bearer token rather than using the SDK's `requireBearerAuth()`, passes no `taskStore`, and uses no SDK client transport. A dependency scanner still reports all four against any install that resolves an older SDK.
