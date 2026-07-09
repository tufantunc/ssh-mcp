# Stack pack: ssh-mcp — correctness
extends: core/skills/correctness/SKILL.md

## Stack-specific signals
- **Stream listener leak** — adding `dataHandler` to an SSH channel/stream without removing it after command completion accumulates listeners and causes PTY session exhaustion (Issue #34 root cause). Always `removeListener('data', handler)` in all exit paths.
- **Sentinel detection race** — the interactive session uses a UUID sentinel to detect command completion. If the sentinel regex is not anchored or the marker is predictable, output containing the sentinel text can cause false completion.
- **`connecting` flag not reset on `close()`** — after `SSHConnection.close()`, the `connecting` promise must be nulled, otherwise `ensureConnected()` returns the stale promise without reconnecting.
- **`isConnected()` false negative** — `_sock.destroyed` check may lag behind actual socket state during reconnection. Consider a grace period or explicit state tracking.
- **Session `status` not transitioned on connection drop** — when `client.on('end')` fires, sessions must be marked `disconnected`; otherwise `session.run()` on a dead session hangs.
- **Concurrency cap not enforced** — if `activeChannels` counter is not decremented in all exit paths (error, timeout, close), the semaphore drains and all future `exec()` calls block.
- **TTL reaper not running** — `reapExpiredSessions()` and `reapIdleConnections()` must be called periodically; otherwise idle sessions/connections leak indefinitely.
- **PTY initialization race** — `openInteractiveSession()` resolves after a prompt regex match OR timeout. If the prompt never matches and timeout is too short, commands sent immediately may arrive before the shell is ready.
- **ANSI escape codes in output** — PTY sessions add bracketed-paste sequences (`\x1b[?2004h/l`) that corrupt output if not stripped.

## Stack-specific remedies
- Always pair `stream.on('data', handler)` with `stream.removeListener('data', handler)` in every branch (success, error, timeout).
- Use unguessable markers (crypto.randomUUID) for command completion sentinels.
- Reset `connecting = null` in `close()`.
- Strip ANSI sequences (`/\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r/g`) from session output.
- Decrement `activeChannels--` in all stream close/error paths.

## Stack-specific severity guidance
- Stream listener leak causing PTY exhaustion: **High** (availability + correctness).
- Stale connecting promise preventing reconnect: **High**.
- Sessions not marked disconnected after connection drop: **High** (hangs on next command).
- Missing `activeChannels` decrement: **Medium** (degrades over time).
- ANSI sequences in output: **Medium** (data corruption).
