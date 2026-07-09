# Stack pack: ssh-mcp — craft
extends: core/skills/craft/SKILL.md

## Stack-specific signals
- **Layer leak** — `tools/registry.ts` reaching into `(conn as any).sshConfig` or `(session as any)._status` — if a tool handler accesses SSHConnection internals via `as any`, the layer boundary is broken. Use the public API (`getSudoPassword()`, `toInfo()`).
- **`src/index.ts` growing past 200 lines** — v2's entry point should be thin (parse args → load config → wire modules → start transport). Business logic belongs in modules.
- **Credential resolution duplicated** — if any module other than `config/credential-resolver.ts` reads `process.env.SSH_MCP_PASSWORD` or calls `readFile(keyPath)`, the cascade is broken.
- **Policy engine bypassed** — if any tool handler calls `conn.exec()` without going through `checkPolicyAndApprove()`, the authorization layer is optional instead of mandatory.
- **`any` type in SSH layer** — `connectConfig: any` in `connection.ts` defeats the purpose of the typed `SSHConfig` interface.
- **God object** — `SSHConnection` has connection management, session management, exec, and SFTP access. If it grows past ~300 lines, extract `SessionManager` or `ExecHelper`.

## Stack-specific remedies
- All SSH access goes through `SSHConnection` public methods (`exec()`, `openSession()`, `closeSession()`).
- All credential access goes through `resolveCredentials(profile)`.
- All command execution goes through `checkPolicyAndApprove()` → `conn.exec()`.
- Replace `any` with proper types (`ConnectConfig` from ssh2 or a local interface).

## Stack-specific severity guidance
- Tool handler accessing SSHConnection internals via `as any`: **High** (layer leak).
- Credential resolution outside the cascade resolver: **High**.
- Command execution bypassing policy engine: **Critical**.
- `index.ts` over 200 lines: **Medium**.
