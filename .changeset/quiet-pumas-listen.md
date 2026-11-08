---
'ssh-mcp': minor
---

A session can now be told how long it may live, per call.

`open-session` accepts `ttlMs`, and `0` means "never idle-expire". That makes
`0 = no cap` true for `sessionIdleTimeoutMs` / `sessionBackgroundMaxMs` in the
config file and `--sessionTtl` too, the spelling `commandMaxChars` and
`commandQuotaPerDay` already use. `SessionManager.open()` honoured `opts.ttlMs`
all along and the type carried it; the tool schema was the only layer not
passing one, so a job that outlives the profile's idle timeout had to change a
global setting.

The comparisons behind it were bare `>`, which read a literal 0 as "expire
immediately" — the opposite of the request — and `parseInt(x) || default` turned
`--sessionTtl=0` back into the 10-minute default, because 0 is falsy, not
invalid.
