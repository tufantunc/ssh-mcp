# Stack pack: ssh-mcp — backend
extends: core/skills/backend/SKILL.md

## Stack-specific signals
- **Policy evaluation order** — denylist checked BEFORE role-binding allow check.
- **Missing policy evaluation** — any `conn.exec()` or `session.run()` without `policy.evaluateWithOpa()` bypasses all authorization.
- **Missing audit on error paths** — failed commands must still produce audit records.
- **MCP tool annotations mismatch** — `readOnlyHint: true` on mutating tool = auto-approval safety regression.
- **All tools must go through policy + audit** — `read-command`, `run-command`, `privileged-command` via `runAudited()`; `sftp-upload`, `sftp-download`, `signal-process`, `open-session(background)` via inline `checkPolicyAndApprove()` + `auditResult()`.
- **HTTP transport auth enforcement** — `startHttpServer()` must throw if `bearerToken` is missing.
- **Rate limiter scope** — applies only to MCP routes (`pathname === '/'`), NOT to `/health` or `/status`. Verify this is intentional for ops endpoints.
- **Body size limit** — POST body capped at 1MB. `req.destroy()` on overflow causes EPIPE on client; consider `res.writeHead(413)` + `req.destroy()` instead.
- **Audit write stream lifecycle** — `ensureStream()` must close+null the write stream during rotation, then reopen. `rotateIfNeeded()` runs BEFORE write, not after.
- **MCP resources registration** — `registerResources()` must be called alongside `registerTools()`. Resources: `ssh://connections`, `ssh://connections/{profile}`, `ssh://sessions/{profile}/{session}`.
- **Progress sender graceful degradation** — `makeProgressSender()` returns `undefined` when no `progressToken`. `exec()` must handle `undefined` onProgress without crash.
- **Cancel signal threading** — `AbortSignal` from `extra.signal` must reach `exec()` via `ExecOpts.abortSignal`. Missing thread = client cancel ignored.
- **OTEL NoopTracer** — when `--otelEndpoint` is not set, `tracer.startSpan()` returns NoopSpan. `setAttribute()` and `end()` must be no-ops.

## Stack-specific remedies
- Every tool handler: sanitize → `checkPolicyAndApprove()` → execute → `auditResult()`.
- `runAudited()` helper wraps the common pattern for exec tools.
- HTTP: `bearerToken` required, rate limiter on MCP routes, 1MB body cap.
- `registerResources()` for profile/session discovery.
- `makeProgressSender()` + `abortSignal` threaded to `exec()`.

## Stack-specific severity guidance
- SSH command without policy evaluation: **Critical**.
- Missing audit on error path: **High**.
- `readOnlyHint: true` on mutating tool: **High**.
- HTTP without bearer enforcement: **High**.
- Cancel signal not threaded to exec: **Medium**.
- Rate limiter misconfiguration: **Medium**.
