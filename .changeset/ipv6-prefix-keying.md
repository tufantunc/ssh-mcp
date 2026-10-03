---
"ssh-mcp": minor
---

**IPv6 clients are told apart by their /64.** The failed-auth budget (`--authFailureLimit`)
and the per-client request budget (`--rateLimit`) both keyed a client by its full address.
An IPv6 client is now keyed by its /64, usually the smallest block a subscriber is handed,
for a direct connection and for an address read from `X-Forwarded-For` behind a trusted
proxy. Any spelling of an address — upper case, leading zeros, `::` written out, a zone
suffix — reaches the same key.

An IPv6 address that carries an IPv4 address is keyed as that IPv4 client: IPv4-mapped in
any spelling (a forwarded `::FFFF:` or `::ffff:c000:280` used to stay IPv6, or fall back to
the proxy's key), and the NAT64 prefix `64:ff9b::/96`. IPv4 and loopback keying is
unchanged, and a trusted proxy is still recognised by its exact address.

**Minor, not patch, because a client that used to be served can now wait.** Hosts that
share a /64 — a home or office network, or customers a hosting provider places on one /64 —
now share one failed-auth budget and one request budget, the way hosts behind one IPv4 NAT
already did.
