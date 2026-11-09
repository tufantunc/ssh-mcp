---
'ssh-mcp': minor
---

A session can now be given its own idle timeout, per call, and `0` means "no
cap" for the session timeouts in the config.

`open-session` accepts `ttlMs`. It may shorten the profile's idle timeout for
that session. It may lengthen it only up to a ceiling the operator already set:
`sessionBackgroundMaxMs` for a background session. Where that cap is `0`, the
ceiling is the profile's own `sessionIdleTimeoutMs`, since turning the absolute
cap off does not turn the idle timeout off. An interactive session has no
absolute cap, so its ceiling is always the profile's own `sessionIdleTimeoutMs`. A call
above the ceiling is refused, and the refusal names the ceiling. A call cannot
ask for `0`: the timeout is the operator's control, and the agent can narrow
what the operator allows but not widen it.

`sessionIdleTimeoutMs` / `sessionBackgroundMaxMs` in the config file, and
`--sessionTtl`, now accept `0` = no cap. This is the spelling
`commandMaxChars` and `commandQuotaPerDay` already use.

The comparisons behind it were bare `>`, which read a literal 0 as "expire
immediately" — the opposite of the request — and `parseInt(x) || default` turned
`--sessionTtl=0` back into the 10-minute default, because 0 is falsy, not
invalid.
