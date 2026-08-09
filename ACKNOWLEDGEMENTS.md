# Acknowledgements

v2 is a near-total rewrite, which means a lot of contributed work shaped the
result without being merged as commits. GitHub's contributor graph only counts
merged commits, so this file exists to record what that graph cannot.

## Reported problems that changed the design

- **[@BlackBird-BB](https://github.com/BlackBird-BB)** — found that credentials
  could only be passed as command-line flags, readable by any local user
  (CVE-2026-7038). Removing that was the first thing v2 did.
- **[@codyaverett](https://github.com/codyaverett)**, with
  [@amosroger91](https://github.com/amosroger91) and
  [@apage43](https://github.com/apage43) — argued the Lethal Trifecta case in
  [#33](https://github.com/tufantunc/ssh-mcp/issues/33) and listed the
  mitigations. The policy engine, command classification, approval flow and
  audit log all trace back to that thread.
- **[@msexxeta](https://github.com/msexxeta)** — reported that output vanished
  and that command text leaked into results
  ([#27](https://github.com/tufantunc/ssh-mcp/issues/27)), and proposed
  replacing prompt detection with a generated marker
  ([#46](https://github.com/tufantunc/ssh-mcp/pull/46)). v2's session protocol
  works exactly that way.
- **[@wbern](https://github.com/wbern)** — asked for read-only commands to be
  distinguishable so an agent could be trusted with them
  ([#23](https://github.com/tufantunc/ssh-mcp/issues/23)). That is why there is
  a `read-command` separate from `run-command`.
- **[@jonathanbird](https://github.com/jonathanbird)** — asked for
  `readOnlyHint` ([#36](https://github.com/tufantunc/ssh-mcp/issues/36)), and
  noted that annotating `exec` would not be truthful. Splitting the tool was the
  answer to that objection.
- **[@sunjl17](https://github.com/sunjl17)** — hit "the input device is not a
  TTY" ([#31](https://github.com/tufantunc/ssh-mcp/issues/31)), now a per-call
  `tty` option.
- **[@veithly](https://github.com/veithly)** — could not use an encrypted
  private key ([#25](https://github.com/tufantunc/ssh-mcp/issues/25)), now
  supported and tested.
- **[@deevus](https://github.com/deevus)** — asked for configuration through
  environment variables ([#32](https://github.com/tufantunc/ssh-mcp/issues/32));
  `SSH_MCP_KEY` is the variable requested.

## Contributed implementations

Merged in spirit rather than as commits — these pull requests were built on v1
and could not be rebased onto the rewrite, but they arrived at the same designs.

- **[@Isla-Liu](https://github.com/Isla-Liu)** — TOML profile configuration
  (#55), redacted audit logging (#56), approval modes (#58) and per-profile
  approval settings (#59): four of v2's core mechanisms. Also identified that a
  multi-profile setup with no explicit selection silently targets the first host
  (#54) — a bug v2 still carried until it was fixed with their co-authorship.
  The WebUI (#60–#63) and config hot-reload (#64) proposals remain open.
- **[@ta5n](https://github.com/ta5n)** — Docker packaging and multi-host
  connection pooling (#28).
- **[@mario-chamuty](https://github.com/mario-chamuty)** — SFTP transfer tools
  (#38).
- **[@henrik-koren](https://github.com/henrik-koren)** — HTTP transport for
  multi-host execution (#41).
- **[@mikusnuz](https://github.com/mikusnuz)** — passphrase support for
  encrypted keys (#35).
- **[@burtherman](https://github.com/burtherman)** — determining command success
  by exit code rather than stderr output (#67).
- **[@donejeh](https://github.com/donejeh)** — default working directory (#45).
- **[@hamb3r](https://github.com/hamb3r)** and
  **[@GautamKumarOffical](https://github.com/GautamKumarOffical)** — keeping v1
  working against moving SDK and zod releases (#37, #51).
- **[@glebtv](https://github.com/glebtv)** and
  **[@Ghits01](https://github.com/Ghits01)** — review comments on #23 and #25
  pointing at simpler alternatives worth considering.
