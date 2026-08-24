---
"ssh-mcp": minor
---

Start without a config, so the server can be introspected before it is configured.

Starting with nothing configured used to be fatal. Measured against the published image, `initialize` and `tools/list` drew **no JSON-RPC response at all** — the process exited on the config check before the handshake — so an MCP directory or a client's "add this server" flow saw a crash rather than a tool list. Glama lists ssh-mcp as a server that "cannot be installed" and leaves its quality score ungraded; a directory that never reaches `tools/list` has nothing to grade, which is the likely link, though how Glama scores is theirs to say and not something measured here.

Tool definitions are static metadata; the config decides what those tools may *reach*. Coupling "no config" to "no server" bought no safety and cost every introspection, so the refusal moved rather than disappeared:

- with nothing configured, the server starts, answers the handshake, and lists all eleven tools;
- **every tool call is refused** with the same message the startup refusal used to give, naming the platform config path;
- startup prints that message to stderr as a warning, so an operator who mistyped a flag gets a server that says it is unconfigured instead of one that looks healthy and fails once per call.

Only "configured nothing" softens. `--config <path>` naming a file that is not there still refuses, and so does a half-given quick start — including `--host example.com --user root` written with spaces instead of `=`, a bare `--host`, and `--host= --user=` from a wrapper whose env vars are unset. Those all parse to falsy values while the flags were plainly given, so the soft path keys on the flags being *absent* rather than on their values being truthy.

**No command reaches a host without a profile.** The only construction site for an SSH connection is inside `getOrCreate`, whose first act is to resolve a profile, and that now refuses. Two things did change and are worth an operator's attention: the process no longer exits `2` when nothing is configured, so a supervisor watching for that should watch stderr for `starting unconfigured` instead; and an HTTP deployment now binds its port while unconfigured, so `GET /health` gained a `configured` field to say so — it is the case of a config bind mount that silently did not attach.

Refusals are audited. The profile was previously resolved *above* the audit pipeline's `try`, so a tool call refused for want of a profile left no record at all — an operator whose config went missing saw an empty log, which reads as "nobody used this server" rather than "this server was probed". Resolution moved inside, and the audit writer stopped re-deriving the profile it was auditing, which would have thrown for the very reason the call was being recorded and silently dropped the write.

The refusal is raised by `ConnectionRegistry` rather than by the config loader's `getProfile`. That lookup can only check the branch where no profile was named, so a client with a profile name baked into its MCP config — a common setup — got `Profile "prod" not found`: a message telling the operator they mistyped a name when in fact they had no config at all. The registry is the sole caller of that lookup, so checking there covers both branches.

The refusal names the config path, which reaches the MCP client rather than only the operator's terminal. That is deliberate: on stdio the recipient is local, on HTTP it holds a bearer token to a server whose purpose is remote command execution, and a directory or hosted client that cannot read stderr has no other way to learn the remedy.

One note for anyone reading the types: `AppConfig.profiles` was effectively a non-empty list before this, since `configSchema` requires at least one entry and the quick-start path always built exactly one. This change introduces the empty case, and `getProfile` had fallen through to `profiles[0]` — `undefined` typed as `Profile` — which would have become a TypeError rather than an explanation. It now refuses.
