---
"ssh-mcp": patch
---

Correct three places where the documentation promised more than the code delivers, and two tool descriptions with it.

From an unsolicited source review by [Can Yildirim](https://github.com/canyildirim) against v2.5.0. Each was reproduced against the shipped build before being written up here; nothing in this release changes behaviour.

**Host key trust does not survive a restart.** `SECURITY.md` listed "TOFU host key verification by default" as the mitigation for MITM. The store behind it is a `Map` created per `ConnectionRegistry` — nothing reads or writes it to disk and nothing consults `~/.ssh/known_hosts` — so "verify after" means verify within one process. For a stdio server that starts and exits with its client, a fresh accept happens every session, and an attacker positioned to intercept has to win once per start rather than once ever. A new section says so, and names the one setting that does outlive a restart: `trustedHostKey` on the profile. It also records that `--hostKeyMode=strict` is currently unusable — the only write to the store sits below the strict throw, so the store never fills and every host is refused, with or without a pin.

**`ask-destructive` gates less than the name suggests.** Outside the never-allowed list, the `destructive` class comes from one `rm -rf /path` pattern, a `find` carrying a write/exec flag, and an unresolvable command word; elevation classifies `privileged`, which the mode also gates. `SECURITY.md` disclosed this for `kill`, which read as a single carve-out rather than the general rule. It is now stated as the rule, with the measured list: `rm -f /etc/passwd`, `rm -r -f /`, `rm --recursive --force /`, `mv`, `truncate`, `shred`, `systemctl stop`, `sftp-upload` and a reverse shell all classify `safe` and raise no prompt in this mode. `ask-all` is named as the mode that gates writes.

**Two tool descriptions overstated the approval gate.** `privileged-command` said approval is "ALWAYS" required; `approvalPolicy = "auto"` removes it. `run-command` had the same defect in the same sentence. Both now say the command goes through the approval gate and that `approvalPolicy` decides whether that is a prompt, an allow, or a refusal — which is true of all four modes, where naming `auto` alone was not: `ask-all` prompts for every class, and `deny` refuses instead of prompting.

That last change moves two `--dumpToolHashes` values: `run-command` 69b38cb4f45d7bc8 to 87a68e83fe483d53, and `privileged-command` e71bf56a334cf488 to dda5722295cb704b. The other nine are unchanged. An operator pinning tool-description hashes will see those two move, and that is expected here rather than a sign of tampering, as it was for `close-session` in 2.3.3.
