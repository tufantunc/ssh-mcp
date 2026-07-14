# Stack pack: ssh-mcp — security
extends: core/skills/security/SKILL.md

## Stack-specific signals
- **Command injection via `stream.write()`** — any caller-controlled string that reaches `shell.write()` or `conn.exec()` without sanitization of CR/LF/NUL.
- **Credential leakage via `/proc/<pid>/cmdline`** — CLI arg secrets are CWE-214. Env vars visible via `/proc/<pid>/environ`.
- **Sudo password in remote `argv`** — `printf | sudo -S` puts password in process list (CWE-522). Must pipe via stdin.
- **Host key verification bypass** — omitting `hostVerifier` or `--insecureHostKey` in non-test code.
- **Weak SSH algorithms** — allowing `ssh-rsa`, SHA-1 MACs, CBC ciphers violates RFC 9142.
- **Prompt injection via tool output** — file contents returned to LLM can contain adversarial instructions (OWASP LLM01:2025).
- **Error message secret leakage** — interpolated buffer in error messages.
- **Unbounded output** — disabling `maxOutputBytes` or `maxChars` enables memory exhaustion.
- **`shellSingleQuote` bypass** — privileged-command uses `shellSingleQuote()` for sudo wrapper. Any change to this function must be tested against injection payloads.
- **HTTP transport without bearer** — `startHttpServer()` must throw if `bearerToken` is missing.
- **HTTP rate limiting bypass** — rate limiter only applies to MCP routes (`/`), not `/health` or `/status`. Verify this is intentional.
- **AbortSignal cancel abuse** — cancel handler sends INT→TERM→KILL to remote process. Verify the signal escalation timing is bounded.
- **OTEL span attributes leaking secrets** — span attributes (`ssh.command`) must pass through `redactText()` before being set. Raw command in span = secret leak to tracing backend.
- **Progress notification data leak** — `onProgress` sends last 3 lines of stdout to client. Verify no secrets in tail output.
- **ProxyJump credential leak** — `forwardOut` through bastion must NOT forward the agent. Verify `agentForward` is never set.

## Stack-specific remedies
- All metadata through `sanitizeMetadata()` (strips `\r\n\u2028\u2029\x00`).
- Credentials only via `resolveCredentials()` cascade (agent → keychain → env → key file), never CLI args.
- Sudo password via `stream.write(password + '\n')` on exec channel, never in argv.
- Host key: TOFU default, strict mode, `insecure` only behind `--insecureHostKey` flag.
- Frozen algorithm allow-list from `src/ssh/algorithms.ts`.
- Error messages: fixed strings only.
- Output redaction via 3-layer pipeline (field → regex → entropy) before client/audit/OTEL.
- `connectConfig` typed as `ConnectConfig` from ssh2, not `any`.
- Rate limiter: token-bucket per client, 429 + Retry-After, body cap 1MB.

## Stack-specific severity guidance
- Command injection via `shell.write()` or `shellSingleQuote` bypass: **Critical**.
- Secret in OTEL span attribute (raw command without redaction): **Critical**.
- Credential in CLI arg or remote argv: **Critical**.
- HTTP transport without bearer enforcement: **High**.
- Host key verification disabled in non-test code: **High**.
- Error message with raw buffer: **High**.
- Missing `maxChars`/`maxOutputBytes` enforcement: **Medium**.
- Rate limiter not covering all MCP routes: **Medium**.
