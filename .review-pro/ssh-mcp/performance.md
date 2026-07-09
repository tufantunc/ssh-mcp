# Stack pack: ssh-mcp — performance
extends: core/skills/performance/SKILL.md

## Stack-specific signals
- **Sequential `exec()` calls where parallel is safe** — multiple `read-command` calls to different profiles should use `Promise.all()`, not sequential awaits. Each goes to a different SSH connection.
- **Unbounded ring buffer** — `BackgroundSession.ringBuffer` is capped at 10K lines / 100KB, but if the cap logic is wrong, a `tail -f` on a busy log can exhaust memory.
- **Connection pool not reusing** — `ConnectionRegistry.getOrCreate()` should return the existing `SSHConnection` if already connected. If it creates a new connection on every call, that's an SSH handshake per command.
- **Keepalive not configured** — missing `keepaliveInterval`/`keepaliveCountMax` on the ssh2 Client causes idle connections to be dropped by network NAT/firewall timeouts.
- **Per-command `fs.readFile` for key material** — if `resolveCredentials()` reads the private key file on every `getOrCreate()` call instead of caching, that's I/O on every command.
- **Audit write blocking** — `appendFile()` is async but on a slow disk, audit writes can become a bottleneck. Consider batching or a write queue.
- **Property test with excessive `numRuns`** — 10K runs of `fast-check` adds ~100ms to CI. Fine for sanitizer, but don't use 10K for integration-level property tests.

## Stack-specific remedies
- `ConnectionRegistry` caches connections per profile name; `getOrCreate()` returns cached if connected.
- Set `keepaliveInterval: 15000`, `keepaliveCountMax: 3` on all SSH connections.
- `resolveCredentials()` is called once per `getOrCreate()`, not per `exec()` — the SSHConnection stores the credentials.
- Consider `pino` with async flushing for audit if disk I/O becomes a bottleneck.

## Stack-specific severity guidance
- New SSH connection per command (no pooling): **High** (latency + resource exhaustion).
- Missing keepalive on long-lived connections: **Medium** (drops after NAT timeout).
- Ring buffer unbounded: **Medium** (memory).
- 10K fast-check runs: **Low** (CI time).
