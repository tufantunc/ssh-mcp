---
"ssh-mcp": patch
---

An invalid `--hostKeyMode` is now reported before the config file is read, instead of after the loader has checked (and possibly refused) it, so a typo no longer costs a second restart. The Windows config-ACL messages now name the directory the server actually reads its config from, rather than the literal `%APPDATA%\ssh-mcp`, which was wrong whenever `APPDATA` is unset.
