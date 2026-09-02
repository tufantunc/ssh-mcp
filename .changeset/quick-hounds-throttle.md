---
"ssh-mcp": minor
---

**Security:** throttle failed bearer authentication on the HTTP transport ([#187](https://github.com/tufantunc/ssh-mcp/issues/187)).

`--rateLimit` never saw a wrong token. The auth check answers before the limiter is
reached, so a failed attempt consumed nothing — measured as twelve 401s and zero 429s
against `--rateLimit=3`, with the bucket still full afterwards. A bearer token is the only
thing in front of a tool that runs commands over SSH, and guessing it ran at network speed
with no backoff.

`--authFailureLimit` (default 10 per client per minute, 0 disables) is a separate budget,
spent only on a 401. A correct token never consumes from it, so a working client never
throttles itself, which is why the default is on. Moving the request limiter above the auth
check instead would have closed this and opened something worse: that bucket is global, so
unauthenticated traffic could then starve every legitimate client.

Two things worth knowing before upgrading:

- **Once an address has spent its budget, every request from it waits — including one with
  the right token.** That is deliberate. Gating only the 401 path would still evaluate the
  guess and still serve a correct token, so the status code would tell an attacker which
  token was right and the limit would slow nothing down. A client with a correct token in
  its config never spends any of the budget, so it never throttles *itself* — but it does
  wait if it shares a source address with something that is failing. Behind a reverse
  proxy that is every client at once, so **set `--trustProxy` when the proxy is yours**;
  without it the server keys on the proxy's address and one failing client can lock out the
  rest. The server says so on stderr the first time it sees `X-Forwarded-For` without
  `--trustProxy`.
- **Clients are told apart by socket address.** `--trustProxy` reads `X-Forwarded-For`
  instead, and is off by default because a client that can set that header could otherwise
  pick its own budget. When it is on, the **rightmost** entry is used — a proxy appends the
  address it saw, so everything left of the last entry came from the client. Reading the
  leftmost would be worse than having no limit: a client could mint a fresh budget per
  request, or name a victim's address and spend theirs. This assumes one trusted proxy hop.
- **The budget is tracked for at most 1024 addresses**, and a fresh address evicts the
  emptiest tracked one rather than the oldest, so cycling addresses cannot refund a spent
  budget.
- **A malformed `--authFailureLimit` is now refused at startup** rather than silently
  disabling the check. Only `0` turns it off.

The request limiter itself is unchanged, and is still one global bucket rather than one per
client — a separate question, tracked in #187.
