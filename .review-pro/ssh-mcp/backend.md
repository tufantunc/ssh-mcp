# Stack pack: ssh-mcp — backend
extends: core/skills/backend/SKILL.md

## Stack-specific signals
- **Policy evaluation order** — denylist must be checked BEFORE role-binding allow check. A command matching both allow and deny must be denied. The `evaluate()` method must check denylist first, then class-allowed, then approval.
- **Missing policy evaluation** — any code path that calls `conn.exec()` or `session.run()` without first calling `policy.evaluate()` bypasses all authorization.
- **Missing audit record on error paths** — if a command fails (timeout, SSH error, policy deny), the audit store must still record the attempt with the error/decision. Otherwise the audit log has gaps.
- **MCP tool annotations mismatch** — `readOnlyHint: true` on a tool that can mutate state misleads client-side auto-approval. `destructiveHint` missing on `privileged-command` or `signal-process` is a safety regression.
- **Approval mode bypass** — `approvalPolicy: "auto"` on a production profile, or `readOnly: false` with `role: "viewer"`, contradicts the profile's intent.
- **Connection not closed on profile removal** — if a profile is removed from config but its `SSHConnection` is still in the registry, it remains accessible.
- **HTTP transport without auth** — starting HTTP server without `bearerToken` exposes the SSH gateway to the network.
- **Config file permissions not checked** — loading a world-readable config (`0644`) leaks all profile credentials.

## Stack-specific remedies
- Every tool handler must follow: sanitize → policy.evaluate → (if require-approval) elicit → execute → audit.
- Use the `checkPolicyAndApprove()` helper in `tools/registry.ts` consistently.
- Record audit entries in `try/catch/finally` to cover both success and error paths.
- Verify tool annotations match actual behavior (`read-command` = truly read-only, `privileged-command` = truly needs sudo).
- Always set `bearerToken` when `--transport=http`.
- `checkPermissions()` in `config/loader.ts` must reject files with group/world read bits.

## Stack-specific severity guidance
- Code path executing SSH command without policy evaluation: **Critical**.
- Missing audit on error path: **High** (forensic gap).
- `readOnlyHint: true` on mutating tool: **High** (auto-approval safety).
- HTTP transport without bearer token: **High** (unauthenticated access).
- Config file world-readable: **High** (credential leak).
