# Stack pack: ssh-mcp — ai-antipatterns
extends: core/skills/ai-antipatterns/SKILL.md

## Stack-specific signals
- **Hallucinated ssh2 API** — `stream.signal()` exists in ssh2 but `stream.sendSignal()` does not. `conn.sftp()` callback is `(err, sftp)` not `(err, sftp, info)`. If the code calls an ssh2 method that doesn't exist, it's a hallucination.
- **Hallucinated MCP SDK method** — `server.server.request()` for elicitation may not match the actual SDK API. Check the installed SDK's exports. `server.tool()` with 4th argument annotations: verify the SDK supports the `{ readOnlyHint }` overload.
- **Invented config keys** — `--sessionMax`, `--sessionTtl`, `--httpHost` in `index.ts` must match what the parser actually reads. If `argv.httpHost` is used but never documented in README, it may be invented.
- **Needless dependency** — adding `smol-toml` when the project could use a simpler parser. Adding `@napi-rs/keyring` as a hard dep when it's optional.
- **Over-engineered policy engine** — the YAML engine with `roleBindings`, host-group inference, and `CLASS_RANK` may be more complex than the actual 3-role system needs. If there are only 3 roles (viewer, operator, admin), a lookup table suffices.
- **Ignored existing helpers** — `sanitizeCommand()` exists in both `src/index.ts` (old) and `src/guard/sanitizer.ts` (new). If code uses the old one, it ignores the new module.
- **Invented TOML schema fields** — `approvalPolicy = "manual"` was in an early fixture but `"manual"` is not in the zod enum (`auto | ask-destructive | ask-all | deny`). Validate all config examples against the schema.

## Stack-specific remedies
- Verify every ssh2 API call against `node_modules/ssh2/lib/client.js` or the `.d.ts` file.
- Verify MCP SDK API calls against `node_modules/@modelcontextprotocol/sdk/dist/esm/`.
- Run `npm run build` after any API usage change — TypeScript catches most hallucinations.
- Cross-reference CLI args in `index.ts` with the README CLI flags table.

## Stack-specific severity guidance
- Hallucinated ssh2 or MCP SDK method: **High** (runtime crash).
- Invented config key accepted silently: **Medium** (confusing UX).
- Over-engineered abstraction beyond the 3-role model: **Low** (maintainability).
