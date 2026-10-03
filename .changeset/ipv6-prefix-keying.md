---
"ssh-mcp": minor
---

**IPv6 clients are told apart by their /64.** The failed-auth budget (`--authFailureLimit`)
and the per-client request budget (`--rateLimit`) both keyed a client by its full address.
An IPv6 client is now keyed by its /64, the smallest block a subscriber is handed, for a
direct connection and for an address read from `X-Forwarded-For` behind a trusted proxy.
Different spellings of one address — upper case, leading zeros, `::` written out, a zone
suffix — reach the same key, and so does a forwarded `::FFFF:`-mapped IPv4 address, which
used to stay IPv6. IPv4 and loopback keying is unchanged, and a trusted proxy is still
recognised by its exact address.

**Minor, not patch, because a client that used to be served can now wait.** Hosts that
share a /64 — a home or office network — now share one failed-auth budget and one request
budget, the way hosts behind one IPv4 NAT already did.
