---
"ssh-mcp": minor
---

**`--rateLimit` is now counted per client.** It was one bucket for the whole process: with
`--rateLimit=3`, one client was served three times and a second client was refused before
it had sent a single request, both on direct connections and behind a trusted proxy. Each
client now has its own budget, keyed exactly as the failed-auth budget is: the socket
address, or the rightmost `X-Forwarded-For` entry when `--trustProxy` is set and the peer
is the proxy. Closes #187.

**Minor, not patch, because a client that used to be served can now get a 429.** The budget
is charged on every authenticated request, not only the MCP route: `GET /status` and an
authenticated request to an unknown path spend from it too, and `GET /health` still does
not. A monitor polling `/status`, or an MCP client and a `/status` poller sharing one
address, can now exceed `--rateLimit` where before `/status` was unlimited. Behind a
reverse proxy without `--trustProxy`, every client still shares one budget, as before; the
server's warning about that now names both budgets and fires with only `--rateLimit` on.

`Retry-After` on both 429s is now the time until that client's next request will be
accepted, at least one second, rather than a full token interval. The request-limit 429
body now carries `id: null`, as the other error responses already did.

**Fix to the failed-auth budget.** Its table of tracked clients judged itself "saturated" by
stored token counts, which never change for a client that stops sending. Once 1024
addresses had each spent a budget, every later client started with an empty budget for
good, so a single typo made its correct token wait, even an hour after the attack ended.
Saturation is now judged by tokens after refill, so the condition ends when those buckets
refill.
