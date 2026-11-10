---
"ssh-mcp": patch
---

`--opaUrl`, `--opaTimeoutMs`, `--opaFailClosed`, `--httpSessionTtl` and `--authFailureLimit` are now checked before the config file is loaded, as `--hostKeyMode` already is. A wrong value in one of them is reported first, instead of after whatever the loader refused, which cost a second restart. The conditions are unchanged: the HTTP flags are still read only with `--transport=http`, and `--opaTimeoutMs` only with `--opaUrl`.
