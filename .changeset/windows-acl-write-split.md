---
"ssh-mcp": patch
---

Refuse a Windows config another account can *change*, and report one it can only read.

2.3.1 made the whole ACL check advisory, because 2.3.0 refused a config at the documented `%APPDATA%` location and left its owner no way past ([#138](https://github.com/tufantunc/ssh-mcp/issues/138)). That was too broad a retreat: the check never looked at the rights an ACE granted, so `Authenticated Users:(M)` — another account being able to rewrite the file — was reported in the same words, and with the same shrug, as `BUILTIN\Users:(RX)`.

Those are not the same finding. The config decides which hosts, which roles, which approval policy and which command classes this server honours, so another account being able to rewrite it is an authorization bypass rather than a disclosure. And Windows is not ambiguous about it: "an ACE grants a non-owner FILE_WRITE_DATA or WRITE_DAC" is exactly as clear as `0o022`. The ambiguity that justified retreating is specific to *read* access on a shared volume.

So the rights mask is now read, and the posture follows it:

| The ACL lets another account… | Default |
|---|---|
| only read the config | reported; the server starts |
| change the config | refused |
| nothing at all (a NULL DACL) | refused — that is full control for everyone |
| an ACL that could not be read | refused, unless `icacls` is absent or the check timed out |

The message says which it found — "can be modified by accounts other than its owner" rather than "is readable beyond its owner" — because calling a modify grant readable understated it.

`--strictConfigAcl` refuses everything the check objects to, read-only grants included. `--allowUncheckedConfigAcl` now reports everything and refuses nothing, so it is the single exit from any of this; in 2.3.1 it covered only an undeterminable ACL, which is how #138's reporter ended up with no exit at all.

Also in this release: every ACL finding now reaches the caller's `onFinding` sink rather than the strongest one going straight to stderr; `userInfo()` throwing (a Windows service under a virtual account) no longer turns a report into a crash; and the `ci` gate's `toJSON(needs)` moved out of the command line into an env var.

## Behaviour changes

- **On Windows, a config another account can modify refuses to start again.** If you are relying on 2.3.1's blanket advisory posture, `--allowUncheckedConfigAcl` restores it. A read-only over-grant is unaffected — it still reports and starts.
