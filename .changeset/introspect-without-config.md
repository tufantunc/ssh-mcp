---
"ssh-mcp": minor
---

Start without a config, so the server can be introspected before it is configured.

Starting with nothing configured used to be fatal. Measured against the published image, `initialize` and `tools/list` drew **no JSON-RPC response at all** — the process exited on the config check before the handshake — so an MCP directory or a client's "add this server" flow saw a crash rather than a tool list. The visible consequence: Glama lists ssh-mcp as a server that "cannot be installed", and leaves its quality score ungraded, because that score is computed from tool definitions it was never able to read.

Tool definitions are static metadata; the config decides what those tools may *reach*. Coupling "no config" to "no server" bought no safety and cost every introspection, so the refusal moved rather than disappeared:

- with nothing configured, the server starts, answers the handshake, and lists every tool;
- **every tool call is refused** with the same message the startup refusal used to give, naming the platform config path;
- startup prints that message to stderr as a warning, so an operator who mistyped a flag gets a server that says it is unconfigured instead of one that looks healthy and fails once per call.

**The security posture is unchanged.** No command reaches a host without a profile, and the refusal is the same text in the same circumstances — it simply arrives at the moment a caller tries to use the server rather than at the moment the server starts.

Only "configured nothing" softens. `--config <path>` naming a file that is not there still refuses, because that is a typo rather than a discovery scenario, and so does a half-given quick start such as `--host` without `--user`.

One latent hole closed on the way: with no profiles and no default, `getProfile` fell through to `profiles[0]` and returned `undefined` silently, which downstream would have become a TypeError rather than an explanation. It now refuses.
