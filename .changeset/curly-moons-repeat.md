---
"ssh-mcp": patch
---

Stop refusing read-only commands for mentioning a dangerous word, and say what a refusal actually refused ([#91](https://github.com/tufantunc/ssh-mcp/issues/91)).

The never-allowed list matched `shutdown`, `reboot`, `halt`, `poweroff` and `eval` anywhere in the command string, so reading about one was refused as if it caused one. `last reboot`, `grep -r reboot /etc/`, `cat /var/run/reboot-required` and `journalctl | grep shutdown` were all denied. On a NAS, where an agent tends to check boot history early, this landed on the first command.

These five now match an *invocation*: the head of each `;`/`&&`/`||`/`|`/newline-separated segment, looked at past any `sudo`/`doas`/`pkexec` prefix and its value-taking flags, with the directory part stripped. `sudo -u root reboot`, `/sbin/reboot`, `true && reboot` and `systemctl reboot` are still refused; `sudo grep reboot /var/log/syslog` is not. The check is a tokenizer rather than a regex, so it adds no backtracking to a path that is deliberately free of it.

A knock-on fix: a command that merely mentions one of these words is no longer *classified* destructive either. `cat /var/run/reboot-required` comes back read-only, which is what it is.

**Refusals now name what matched.** `Command matches denylist pattern` said nothing — not the rule, not its origin, not whether the reader could change it. A built-in refusal now names the rule and states that `[policy].denylist` adds patterns rather than removing these; an operator pattern is quoted back with the config key that carries it.

**`APPROVAL_DENIED` no longer covers two different failures.** Approval fails closed, so a client that cannot be asked — no elicitation support, a transport failure, a malformed reply — denied the command with `User did not approve this command`, blaming the user for a prompt they never saw. That case is now `APPROVAL_UNAVAILABLE`, carrying the underlying error. The real decline keeps `APPROVAL_DENIED`. The diagnosis previously existed only on stderr, which for a stdio server is a client log file nobody reads.
