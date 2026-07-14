# Stack pack: ssh-mcp — correctness
extends: core/skills/correctness/SKILL.md

## Stack-specific signals
- **Stream listener leak** — `dataHandler` without `removeListener` in all exit paths accumulates listeners (Issue #34 root cause).
- **Sentinel detection race** — UUID sentinel must be unpredictable. Output containing sentinel text must not trigger false completion.
- **`connecting` promise stale** — after `close()`, `connecting` must be nulled or `ensureConnected()` returns stale promise.
- **`connected` flag vs `_sock`** — v2 uses a `connected` boolean (not `_sock.destroyed`). Verify flag is set/reset in all handlers (ready, end, close, error).
- **Session `status` on connection drop** — `markSessionsDisconnected()` must call `Session.markDisconnected()` (not `as any`).
- **`activeChannels` counter leak** — decrement must be OUTSIDE `if (!resolved)` guard in stream close handler (timeout sets resolved=true first).
- **TTL reaper scheduling** — `setInterval` in `index.ts` must call both `reapExpiredSessions()` per connection AND `reapIdleConnections()` globally.
- **ProxyJump connection lifecycle** — `forwardOut` sock must outlive the target connection setup. If bastion closes, target connection must fail gracefully.
- **AbortSignal cancel timing** — `stream.signal('INT')` on abort must have bounded escalation (INT → 1s → TERM → 1s → close). Unbounded retry loops hang.
- **Progress throttle interaction with cancel** — if `onProgress` fires while abort is being processed, verify no race condition on `resolved` flag.
- **Rate limiter refill** — token-bucket `tryConsume()` must refill based on elapsed time, not reset per request. Verify `lastRefill` timestamp logic.
- **changesets config** — `baseBranch` in `.changeset/config.json` must match the actual default branch.

## Stack-specific remedies
- Always pair `stream.on('data', handler)` with `removeListener` in every branch.
- Use unguessable markers (`crypto.randomUUID`-based) for command completion sentinels.
- Reset `connecting = null` and `connected = false` in `close()`.
- `activeChannels--` outside `if (!resolved)` block.
- `setInterval(reaper, 60_000)` cleared on shutdown.
- `forwardOut` errors must reject the target `getOrCreate()` promise, not silently hang.

## Stack-specific severity guidance
- Stream listener leak causing PTY exhaustion: **High**.
- Stale connecting promise preventing reconnect: **High**.
- Sessions not marked disconnected after connection drop: **High**.
- Missing `activeChannels` decrement on timeout: **High**.
- AbortSignal escalation unbounded: **Medium**.
- Rate limiter incorrect refill: **Medium**.
