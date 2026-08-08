---
"ssh-mcp": patch
---

Update @modelcontextprotocol/sdk to ^1.30.0 and enable DNS rebinding protection
on the HTTP transport.

The dependency was pinned to `~1.17.5`, a range that could never receive fixes
for three advisories against it: cross-client data leak via shared
server/transport reuse (GHSA-345p-7cg4-v4c7), DNS rebinding protection not
enabled by default (GHSA-w48q-cv73-mx4w), and a ReDoS (GHSA-8r9q-7v3j-jr4g).

The HTTP transport now validates the Host header. A page the user visits can
make their browser POST to a localhost server, and the bearer token does not
help if the browser is tricked into attaching it — checking Host is what stops
it. Defaults to the bind address plus localhost; override with `--allowedHosts`
when running behind a reverse proxy that presents a different hostname.
