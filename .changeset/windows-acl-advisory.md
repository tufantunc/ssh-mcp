---
"ssh-mcp": patch
---

Report the Windows config ACL instead of refusing to start on it.

2.3.0 added an ACL check for the Windows config file and made it refuse. On the first day it blocked a reporter's config at the documented `%APPDATA%` location ([#138](https://github.com/tufantunc/ssh-mcp/issues/138)): their ACL carried a principal the allowlist did not know about, because that allowlist was measured on one machine and generalised. `--allowUncheckedConfigAcl` deliberately did not cover a known-bad verdict, so there was no way past it at all — not a flag, not a config change they could discover from the message.

A security check whose worst outcome is stranding an operator in their own config is not a good trade, and the guarantee it enforces is one Windows states far less clearly than POSIX does. So the check still runs and still says exactly what it found — including the two `icacls` commands, because a config under `C:\` really does grant `BUILTIN\Users` read and `Authenticated Users` modify — but it loads the config afterwards.

`--strictConfigAcl` restores refusing, for anyone who wants it enforced. Under that flag `--allowUncheckedConfigAcl` keeps its old meaning: load anyway when the ACL could not be determined.

The POSIX mode check is unchanged and still refuses. There "only the owner" is unambiguous, `chmod` is a one-line fix, and the check has been in place since 2.0.0 without this problem.
