---
"ssh-mcp": minor
---

`read-only` now requires every argument of an allowlisted reader (`cat`, `grep`, `journalctl`, `git log`, `sort`, …) to be provable as data under a grammar declared for that binary, rather than granting the class to any invocation of a listed binary name. A spelling outside a reader's grammar — an unlisted option, an abbreviation of one that is listed, a short-option cluster containing an unlisted letter, an argument carrying an unquoted shell glob (`*`, `?`, `[`), or an operand shaped like something the reader would write to rather than read — falls the whole command to `safe` instead of `read-only`.

`read-only` is what a `readOnly` profile is confined to, what the `viewer` role holds on prod and staging (on dev the viewer holds `safe` too), and what `read-command` requires; all of these refuse `safe` except the viewer on dev. So a command that classified `read-only` — and ran — under the old, name-only rule may now be refused under the same profile, role, or tool. The refusal names the rejected word (`` `journalctl` is read-only only with the options and operands its grammar lists; `--foo` is not accepted there. ``), so the caller can see which spelling of the same command still works, instead of concluding the binary is forbidden outright.

Spellings that fell to `safe` in the final-review hardening wave, on top of the grammar's own exclusions: an unquoted glob argument of any grammar-checked reader (`uniq /root/.ssh/id_ed25519*` — the shell expands it into operands the grammar never counted), an option-looking word after the reader's first operand on `uniq` and `ifconfig` (`uniq IN -c` — macOS reads it as the output file), `find -- …` (find keeps evaluating primaries after `--`), `git remote show …` (its operand can name a URL git will run ssh against), and Windows trailing-slash switch forms (`sort /O/`).

No other class moves: `safe`, `destructive` and `privileged` classify exactly as they did.

**Minor**, not patch, for the reason applied since 2.8.0: a command a `readOnly` profile or a `viewer` ran successfully yesterday can be refused today.
