---
"ssh-mcp": patch
---

Detect elevation anywhere a shell would act on it, not just at the start of the command.

`classifyCommand` decided the `privileged` class with four regexes anchored at `^`: `/^\s*sudo\b/` and the same for `su`, `doas` and `pkexec`. Only a *leading* prefix counted. `sudo id` classified as `privileged` and went to the approval gate; `echo hi; sudo id` classified as **`safe`** and ran with no approval at all.

Any harmless first segment was enough — `true &&`, `cd /tmp;`, a newline, a pipe. The elevation itself was never inspected, so under the default `approvalMode = "ask-destructive"` the prompt a `privileged` command is supposed to raise simply never appeared. `roleBindings` had the same blind spot from the other side: `admin` on `prod` is granted `read-only, safe, destructive` and *not* `privileged`, so a compound command classified `safe` was permitted outright on a tier whose whole point is that it cannot elevate.

The fix reuses the tokenizer that already exists in this file. `parseSegments` walks privilege prefixes to find each segment's head binary, so it always knew which segments were elevated — it just discarded that fact. It now records it as `Segment.privileged`, and `isPrivileged()` is true when any segment carries it.

Scanning the raw string for `\bsudo\b` would have been the smaller diff and the wrong one: it re-breaks for `sudo` exactly what #91 fixed for `reboot`. `grep sudo /var/log/auth.log`, `cat /etc/sudoers`, `ls -la /usr/bin/sudo` and `journalctl -u sudo` mention elevation without invoking it, and all four stay `read-only` here. `classifier.ts` had already written down the rule this follows: *"Matching an invocation rather than a mention needs to know where a command word can start, and that is a tokenizer's job, not a regex's."* That reasoning was applied to power-state commands and not to privilege prefixes.

Unchanged: a bare `sudo`, or `sudo -u root` with no command, still classifies `privileged` — the anchored regex counted it, and a head-less segment now carries the flag so it still does. `sudoedit` and `subl` are not prefixes and are not elevation. Path-qualified spellings (`/usr/bin/sudo`) were already handled by `stripPath` and now benefit in every segment rather than only the first. The prefix list keeps its second, narrower use in `extractBinary`, where anchoring is correct — that names `sudo systemctl status` after `systemctl` — and it is renamed `LEADING_PRIVILEGE_PREFIXES` so the two questions stop sharing one constant.

No regex was added, and nothing here backtracks, so the linear-classification property from the previous release holds. Measured on the shapes that release targeted, at 1 MB: the repeated `dd`/`curl`/`chown` literal case goes 84 ms → 103 ms and a 150k-segment command 240 ms → 311 ms, the cost of one more linear pass over the same tokens. A command that *does* elevate gets faster — 243 ms → 65 ms — because `isPrivileged` now returns before the destructive rules run. Both directions stay linear; the 65 s quadratic case from #128 does not reappear.

One deliberate behaviour change beyond the classification itself: under the default bindings, `admin` on `prod` is not granted `privileged`, so a compound command that previously ran as `safe` — `cd /srv && sudo systemctl restart app` — is now refused rather than prompted. That is the point of the fix, but it will surface as newly-failing commands for anyone whose CLI-configured host took the default `prod` group. `--group=staging`/`dev`, or a `roleBindings` override granting `admin.prod` the `privileged` class, restores it deliberately.
