---
"ssh-mcp": patch
---

**Fix (Windows):** a directory whose name begins with `..` is no longer mistaken for an escape when deciding whether a config file sits inside the user profile.

`isTightenable` compared paths with `!rel.startsWith('..')`, which rejects a legitimately named child such as `..cache` as if it were `../cache`. The remediation printed for a config-ACL problem in such a directory was therefore the wrong one. Containment now goes through a single shared helper that tests the `..` path segment instead of the string prefix.

No other behaviour changes: the local-path gate added alongside it is not yet wired to any tool.
