---
"ssh-mcp": minor
---

**Security:** classify the command a shell would actually run ([GHSA-qvx5-rxrj-9vfh](https://github.com/tufantunc/ssh-mcp/security/advisories/GHSA-qvx5-rxrj-9vfh), CVSS 9.9). Affects 2.0.0 through 2.5.1.

`minor` rather than `patch` for the reason 2.3.0 and 2.5.0 used it: the version reflects what
upgrading can do to you, not how large the change is. Two shipped tools stop working for one
role on one tier — see **Behaviour changes** below.

Quoting is removed by the transport before the command runs, but the classifier's regexes
were written against the text as sent. `rm -rf "/etc"` therefore matched nothing, came back
`safe`, and ran without approval on a `prod` profile where `safe` is granted to `operator`.
`"rm" -rf /etc` and `s"u"do id` are the same bug spelled two more ways. This is the fourth
advisory in this area, and the previous three each taught the classifier one more carrier;
the shape of the mistake was reading the string instead of the tokens.

One tokeniser now resolves quoting and splits on `;`, `&`, `|` and newline outside quotes,
and the seven consumers that used to split on whitespace read it. Regex rules are tried
against both the written and the tokenised form, because neither is a superset of the other —
the tokenised form loses the separators the fork bomb's `:|:&` needs, the written form loses
the quote removal. The word-based rules deliberately keep the written form only: handing them
the tokenised one turns a separator that was safely inside a quoted argument into a real one,
which put `grep -E "warn|reboot" syslog` on the never-allowed list.

Three narrower holes travelled with it:

- A command's class was decided from its outer command alone, and the scan for carried
  commands *replaced* it rather than raising it. `sudo sh -c 'rm -rf /etc'` reported the
  inner `destructive` and lost the outer `privileged`. The class is now the maximum over the
  command and everything it carries.
- `sftp:upload` and `session:open` are built by this server rather than typed by a user, and
  no rule named them, so both fell through to `safe`. Writing an arbitrary file to the target
  is the same authority as `rm` spelled through a different tool, and it reaches
  `~/.ssh/authorized_keys` without touching a shell. Both are `destructive` now.
- An interpreter laundered the class of what it was handed. `python3 -c`, `perl -e`,
  `node -e`, `node -p`, `php -r` and `echo … | bash` all reached root classified `safe`, and
  `runuser` and `setpriv` were missing from the elevation prefixes. Where the program is
  shell it is classified as shell; where it is not, this server cannot read what will run and
  says so with `destructive`. `awk` is read rather than gated wholesale, so an ordinary
  `awk '{print $1}' file` is unaffected, and its ways out to a shell or a file — `system()`,
  a command pipe, `print > "file"`, `-f`, gawk's `--load` — are gated including the forms
  where a `-v` or `-F` value sits before the program.

`find -exec` was already `destructive` before this release and stays gated; reading the
carrier is what raises `find / -name x -exec sudo id +` to `privileged`.

## Behaviour changes

- **`sftp-upload` and interactive `open-session` are refused for `operator` on `prod`.** Under
  the default rules that role holds `['read-only','safe']`, and both are now `destructive`, so
  the decision is `deny` rather than an approval prompt. `viewer` loses them on every tier.
  Grant `destructive` on the tier to restore them. On `staging` and `dev`, `operator` and
  `admin` already hold `destructive`, so those degrade to a prompt instead.
- **`awk '$3 > 100'` asks for approval it does not need**, because `>` is both output
  redirection and greater-than and the redirection form writes arbitrary files. That is the
  direction to be wrong in, but it is a prompt you did not get before.
- `sftp:download` and `session:close` deliberately keep the class they have today. Both would
  move *down* from `safe`, and a security release is the wrong place for a widening.

Measured against 84 ordinary read and maintenance commands — including quoted arguments that
are not commands, and commands that merely name an interpreter (`which python3`,
`ls -l /usr/bin/node`, `ps aux | grep python3`) — exactly one changed class: the `awk`
comparison above. Of 25 attack forms, 20 moved from ungated to gated, 5 were already gated,
and none is left open.
