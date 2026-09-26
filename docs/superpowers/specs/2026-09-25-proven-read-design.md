# Proven read: `read-only` granted by argument grammar, not by binary name

**Advisory:** GHSA-mwmj-jr2h-q546 (draft, embargoed)
**Work happens in:** `tufantunc/ssh-mcp-ghsa-mwmj-jr2h-q546`, branch `advisory-fix-1`.
Nothing reaches the public repository before the advisory is published.
**Release:** minor.

## Problem

`classifyOuter` grants `read-only` when a command's first word is in `READERS`
(`READ_ONLY_ALLOWLIST`), unless `DISQUALIFYING_ARGS` names one of its arguments.
Those are two lists answering one question — "does this invocation only read?" —
and the second one holds 2 of the ~70 binaries the first one vouches for. Every
reader without a `DISQUALIFYING_ARGS` entry is vouched for with *any* arguments.

`DISQUALIFYING_ARGS` is a denylist. Every argument it does not name is let
through, so each binary's write modes have to be found one spelling at a time.
That is what happened to `sort` in GHSA-qmx6-47vm-3vf7's review: one spelling
closed per round (`-o`, then `-mo`, then `--out`), three rounds on one binary.
The same approach does not scale to seventy.

### Measured

All of the following classify `read-only` on 2.12.0, so a `readOnly` profile, a
`viewer` on prod or staging, and the `read-command` tool all run them.

From the draft advisory, measured against real binaries:

| command | effect |
|---|---|
| `uniq /etc/passwd /root/.ssh/authorized_keys` | overwrites the second operand (positional output file) |
| `journalctl --vacuum-time=1s` | deletes archived journal files |
| `journalctl --rotate` | rotates journal files |
| `hostname pwned` | sets the hostname |
| `date -s 00:00` | sets the system clock |
| `git branch -D main` | deletes a branch |
| `git remote add x url` | writes repository config |
| `find / -fprint0 FILE` | creates/truncates FILE |
| `ip route add …` | changes the routing table |
| `ifconfig eth0 down` | takes an interface down |
| `arp -d HOST` | deletes an ARP entry |

Found during this design round:

| command | status |
|---|---|
| `git log --output=FILE`, `git show --output=FILE` | **measured**: writes FILE (git, local) |
| `git diff --output=FILE` | documented, same option family |
| `sort /O FILE IN` on Windows | **measured** on Windows 11 build 26200: writes FILE. Case-insensitive (`/o`), abbreviations accepted (`/OU`, `/OUTPUT`); `-O` is not a switch |
| `arp /d`, `arp /s` on Windows | inferred, not run: `arp /a` is accepted, so the slash form is; `-d`/`-s` are documented as delete/add |
| `ss -K …` | documented (kills sockets); not measured, `ss` is absent from the test containers |
| `file -C -m FILE` | documented (writes a compiled `.mgc`); not measured, `file` is absent from the test containers |
| `journalctl --flush/--sync/--relinquish-var`, `ip route flush all`, `ip addr flush dev X`, `git remote set-url`, `git branch -m`, `hostname -F FILE`, `date --set=…` | classify `read-only`; effects per the tools' documentation |

Found by the final review over the finished branch (fixed in the final-review
wave, 2026-09-26):

| command | status |
|---|---|
| `uniq /root/.ssh/id_ed25519*` | **measured** on debian:12: the glob expands, the `.pub` becomes uniq's OUTFILE and is overwritten with the private key |
| `uniq IN -c`, `ifconfig en0 -av`/`-dad` on macOS | POSIX option order: the trailing option word is an operand there (OUTFILE / interface settings) |
| `find -- d -fprint /tmp/x` | **measured**: GNU find keeps evaluating primaries after `--`; writes the file |
| `git remote show <URL>` | **measured** (git accepts a URL there): runs ssh / `git-remote-<helper>` to a caller-chosen target |
| `sort /O/ …` (trailing slash) | **measured** on the Windows VM: `Invalid switch`, writes nothing — rule tightened fail-closed anyway (shared with `arp`) |

## Contract

A command classifies `read-only` only when the classifier can **prove** every
word after the command word is data under a grammar declared for that binary.
Anything it cannot prove falls to `safe`.

When the classifier fails to recognise a spelling, the result is a refusal the
caller can see. It is never silent permission. The cost falls on the three
consumers of `read-only`, and only on them:
- `readOnly` profiles
- the `viewer` role on prod and staging
- the `read-command` tool

`operator` and `admin` hold `safe` on every tier, so for them a `read-only` →
`safe` fall changes nothing.

## Decision

**A — every `READERS` entry declares an argument grammar**, matched by one
generic, fail-closed matcher.

Rejected:
- **B, shrink the list to binaries with no write mode.** A viewer would lose
  `journalctl -u`, `git log`, `ip addr`, `hostname`, `date` and `find -name`,
  the commands a viewer exists to run. B's rule survives inside A anyway: a
  mode-bearing entry whose grammar has not been written accepts no arguments.
- **C, a hand-written parser per binary** (the `awk.ts` shape). That means
  seventy functions to review, and awk alone took two rounds and produced five
  holes.
- **Best effort plus documenting the limit.** This quietly turns "does not
  change the host" into "usually does not change the host", and it leaves the
  next report the same shape as this one.

## Design

### Where the grammar applies

Measured: `read-only` is reached only when the first word *is* the reader.
Everything else is already `safe` before the allowlist is consulted:
- wrappers: `nice cat`, `timeout 5 cat`, `env cat`, `command cat`, `exec cat`
- assignments: `LC_ALL=C sort`, `GIT_DIR=/x git log`
- paths: `/usr/bin/cat`
- global options: `git -C /r log`
- case variants: `CAT`

Any shell control character sends the command to `safe`
(`SHELL_CONTROL_CHARS`), so `read-only` is only ever granted to a single
segment. Words reach the grammar dequoted (`"cat"` and `c\at` both read as
`cat`), so the grammar sees the word the binary sees — with one exception,
closed by correctness condition 3: an unquoted glob character never reaches
the binary as part of one word (the shell expands it first), so a word
carrying one is refused before the grammar is consulted.

The grammar therefore reads `words[1..]` for a one-word entry and `words[2..]`
for a two-word entry (`git log`, `ip route`, `docker ps`, `systemctl status`).

### Data shape

```ts
type ArgGrammar =
  | { args: 'any'; audit: string }
  | {
      args: 'getopt' | 'exact';
      flags?: readonly string[];        // take no value
      valueFlags?: readonly string[];   // take a required value
      optionalValueFlags?: readonly string[]; // value optional: never consumes the next word
      numericShort?: boolean;           // getopt only: accept `-<digits>` (git -<n>)
      optionsBeforeOperands?: boolean;  // refuse an option-looking word after the first operand
      operands?: {
        max?: number;                   // uniq: 1, hostname: 0
        first?: readonly string[];      // ip route: show | list | get
        each?: RegExp;                  // date: ^\+ ; sort, arp: see Windows
      };
    };
```

`READERS` entries become `{ readOnly, operandsAreData, grammar }`. The type makes
`grammar` required, and an `'any'` entry cannot be written without its `audit`
text. The text names the implementations checked and what was found.

### The matcher

`matchesGrammar(words: readonly string[], grammar: ArgGrammar): boolean`. It is
pure and returns `false` on the first word it does not recognise.

- `'any'`: `true`.
- `--` ends options under `getopt`, and every later word is an operand. In
  `exact` style `--` has no special meaning and is refused as an unrecognised
  word (condition 5).
- A lone `-` is an operand (stdin).
- `optionsBeforeOperands` (either style) refuses an option-looking word once
  an operand has been seen (condition 4).
- `getopt` style, short cluster. The word is read character by character, the
  way getopt reads it:
  - a character in `flags` continues the scan;
  - a character in `valueFlags` consumes the rest of the word as its value, or
    the next word if the rest is empty;
  - any other character: `false`.

  So `-rn5` passes when `-r` is a flag and `-n` is a value flag, and `-mo`
  fails when `-o` is not listed.
- `getopt` style, long options. The option must be listed exactly, and
  abbreviations are not recognised. `--name=value` is accepted for a
  `valueFlags` or `optionalValueFlags` entry, and `--name value` consumes the
  next word only for a `valueFlags` entry — an `optionalValueFlags` entry
  never consumes a separate word.
- `exact` style is for binaries that do not use getopt (`find` predicates, `ip`,
  `dig`). There is no clustering: each option word must be listed exactly, and
  a `valueFlags` entry consumes the next word.
- `optionalValueFlags` models getopt's optional argument (`::`). A short
  option in a cluster takes the rest of the word as its value, if there is
  any. A long option is accepted bare or as `--name=value`. **The next word
  is never consumed**; it is judged on its own. In exact style, an entry
  matches only its bare word.
- `numericShort` (getopt only) accepts a word matching `^-\d+$` as a no-value
  option.
- A name listed in more than one of `flags`, `valueFlags` and
  `optionalValueFlags` is refused.
- Every word that is not an option or a consumed value is an operand. Operands
  are checked against `max`, `first` (the first operand only) and `each`
  (every operand).

### Correctness conditions

The design makes one security assumption: **every word the matcher consumes as
a value, the binary also consumes as a value.** If the matcher took a word as a
value while the binary read it as an option, that would be a hole. Two
authoring rules protect it:

1. **An option with an optional argument (getopt `::`) goes in
   `optionalValueFlags`, never `valueFlags`.** The same applies when
   implementations disagree on whether the option takes a value, or when that
   is known only from documentation and is uncertain. An unconsumed word is
   then judged as an operand, which is the safe direction. Measured case:
   `git log --pretty --output=FILE` writes `FILE`, because `--pretty`'s value
   is optional and git does not consume `--output=FILE` as that value.
2. **An option, or an operand shape, is listed only if it only reads on every
   implementation the name resolves to.** That means GNU, busybox and
   BSD/macOS. When the name resolves to a native binary or builtin on Windows,
   it means Windows too, including Windows `/X` switch syntax. This also
   covers a subcommand whose operand can make the binary run another program:
   `git remote show <URL>` accepts a URL (measured, git 2.55.0) and runs ssh /
   `git-remote-<helper>` against the caller-chosen target, so `show` is not
   in `git remote`'s `first`.
3. **No unquoted glob in a grammar-checked argv.** A `*`, `?` or `[` the
   caller left unquoted is not a word the binary sees: the host shell expands
   it into however many filenames it matches, and the matcher's operand count
   is then false before the binary runs (`uniq /root/.ssh/id_ed25519*`
   counted one operand; measured on debian:12, the expansion made the `.pub`
   uniq's OUTFILE and it was overwritten with the private key). For every
   non-`'any'` grammar, an argv word carrying an unquoted or unescaped glob
   character falls to `safe`, and the refusal names the word. Quoted forms
   (`find -name '*.conf'`) stay allowed — the quotes make them one operand of
   data — and `'any'` entries are exempt: no write or exec option exists to
   inject there, and extra operands from an expansion are data.
4. **Option position is part of the grammar.** An entry sets
   `optionsBeforeOperands: true` when any implementation the name resolves to
   reads options in POSIX order (no permutation), so an option-looking word
   after the first operand is an *operand* there — one that can overwrite
   (macOS uniq's `+`-prefixed optstring reads `uniq IN -c`'s `-c` as OUTFILE)
   or configure (macOS `ifconfig en0 -av` reads the letters as interface
   settings). Set on `uniq` and `ifconfig` only: every other grammar either
   refuses such words anyway (unlisted) or permutes on every implementation.
   Cost: on a permuting implementation the spelling is only harmless, and it
   is refused anyway.
5. **`--` ends options only under getopt.** An `exact` parser keeps
   evaluating its option words after `--` (measured: GNU `find -- d -fprint
   /tmp/x` wrote the file), so the matcher refuses `--` in exact style as an
   unrecognised word rather than treating it as end-of-checks. Cost:
   `find -- dir …` is refused (rare).

### Windows

Measured on Windows 11 build 26200. OpenSSH `DefaultShell` is unset, so
commands run under `cmd.exe`. `READERS` names resolving there:

- native binaries: `arp`, `find`, `git`, `hostname`, `netstat`, `nslookup`,
  `ping`, `sort`, `whoami`
- `cmd` builtins: `date`, `echo`

When PowerShell is the DefaultShell, `cat`, `diff`, `echo`, `ls`, `ps`, `pwd`
and `sort` resolve to cmdlets (`Get-Content`, `Compare-Object`, `Write-Output`,
`Get-ChildItem`, `Get-Process`, `Get-Location`, `Sort-Object`), and none of
them writes a file.

A `/X` switch is an operand under a POSIX grammar and cannot be told apart from
`/etc`. The fix is the existing `each` field, applied only to entries whose
Windows namesake has a write switch:

```ts
operands: { each: /^(?!\/[^/]*\/?$)/ }   // no single-segment "/word" operand, with or without a trailing slash
```

- `sort /etc/passwd` passes: it has a second `/`.
- `sort /O x` fails, and so does `sort /OU x`.
- `sort /O/ x` fails too. Measured on the Windows VM (2026-09-26, build
  10.0.26200.9550, confined to %TEMP%): `/O/`, `/o/`, `/OU/`, `/OUTPUT/`,
  `/T/`, `/A/` are all "Invalid switch" and write nothing (control `/O`
  writes) — but the rule is shared with `arp`, whose `/d`/`/s` slash
  tolerance cannot be measured without running a state-changing form, so it
  is fail-closed.
- Cost: an operand naming a file directly under `/` (`sort /data`), or such a
  directory with a trailing slash (`sort /etc/`), is refused.

The rule applies to **`sort`** (`/O`, `/T`) and **`arp`** (`/d`, `/s`). `date`
needs no extra rule: `^\+` already refuses `date 01-01-2020`. The cost is that
`date /T` is refused too. `find /var -name x` is unaffected, because `find.exe`
only reads.

A `platform` field on the profile was rejected. The classifier is
profile-independent today, and every Windows profile that left the field unset
would fall back to the POSIX assumption, so the hole would remain.

### The audit

Every entry needs a decision, recorded in the code:
- an `'any'` entry carries an `audit` string;
- a grammar entry carries a source comment.

There is no separate audit document, so there is no second copy to drift. What
follows is a starting guess, made in the design round from memory. It is **not
an audit**, and the plan's audit task must confirm or correct each line:

- `'any'` candidates: `basename`, `cat`, `comm`, `cut`, `df`, `diff`, `dig`,
  `dirname`, `du`, `echo`, `false`, `free`, `grep`, `head`, `host`, `htop`,
  `id`, `iostat`, `ls`, `netstat`, `nslookup`, `ping`, `printenv`, `printf`,
  `ps`, `pwd`, `readlink`, `realpath`, `seq`, `stat`, `tail`, `test`, `top`,
  `tr`, `traceroute`, `true`, `uname`, `uptime`, `vmstat`, `wc`, `whereis`,
  `which`, `who`, `whoami`, `docker images/inspect/logs/ps/stats`,
  `systemctl status`, `git status`
- grammar needed: `arp`, `date`, `file`, `find`, `hostname`, `ifconfig`,
  `ip addr`, `ip route`, `journalctl`, `sort`, `ss`, `uniq`, `git branch`,
  `git diff`, `git log`, `git remote`, `git show`

Questions the audit must settle rather than assume:
- `git status` refreshes the index opportunistically. Is that a write the
  contract forbids?
- Do `top`/`htop` have a non-interactive write mode?
- `nslookup` on Windows.

`ss` and `file` must be measured in a container that has them, or recorded as
documented-only.

### Components

- **`src/policy/reader-grammar.ts` (new):** `ArgGrammar` and `matchesGrammar`.
  It imports nothing from the classifier.
- **`src/policy/classifier.ts`:**
  - `READERS` entries gain `grammar`.
  - In `classifyOuter`'s allowlist branch, after the `SHELL_CONTROL_CHARS`
    check, a failed match returns `safe`. The branch carries the rejected word
    (see below).
  - `READ_ONLY_SYNTHETIC` (the SFTP verbs) is not affected, because the tool
    layer builds those strings, not the caller.
  - `operandsAreData` and the carrier scan are not touched.
- **`DISQUALIFYING_ARGS` stays** and still runs before the allowlist branch.
  It answers a different question, "is this worse than `safe`?", and raises the
  class for every role (`find -exec sudo id +` → `privileged` for an operator
  too). The grammar only decides `read-only` versus `safe`. The two are kept
  apart for the same reason `READERS` split `readOnly` from `operandsAreData`.

### The refusal names the word

`ParsedCommand` gains an optional
`readOnlyRejection?: { binary: string; word: string }`. When the engine refuses
a `safe` command for a caller limited to `read-only`, `explainRoleDenial`
appends:

> `journalctl` is read-only only with the options and operands its grammar lists; `--foo` is not accepted there.

Without this, the viewer reads "`safe` commands are refused", concludes that
`journalctl` is forbidden outright, and never learns which spelling would work.
An empty rejected word — a quoted empty operand, `hostname ""` — renders as
`""`, the shell's own spelling of that operand, rather than as blank
backticks.

## Out of scope, with reasons

- **Interactive programs** (a pager started by `git log` under a pty, `top`'s
  `k`). A caller limited to `read-only` cannot reach one with input:
  `session:open interactive …` classifies `destructive` (measured), and
  `run-command`'s `tty: true` path has no stdin writes. A caller who can open a
  session already holds a class that runs a writer directly.
- **Wrappers and global options** stay `safe`. Opening them up would mean
  widening `parseWords`, which `invokedWords` also reads.
- **Host-side configuration** (git aliases, `core.pager`, shell rc files)
  belongs to the host. The caller cannot set it through a `read-only` command,
  because assignments already classify `safe`.

## Residual risks, recorded not closed

- **UNC operands on Windows.** `cat \\host\share\x` and `sort \\host\x` make the
  host authenticate to an SMB server, which can leak an NTLM credential. The
  host is not changed, so this falls outside the `readOnly` contract. It goes
  next to the existing DNS/ICMP egress note on `dig`/`ping`.
- **The `'any'` claims themselves.** No test can prove a binary has no write
  mode. The mitigation is that every claim is written down with its source, and
  that the default for an entry without a claim is "no arguments".

## Testing

New file `test/unit/policy/proven-read.test.ts`.

1. **Matcher unit tests:**
   - clusters (`-rn5`, `-mo`)
   - `--`, a lone `-`
   - `--name=value` against `--name value`
   - attached values
   - `max`, `first`, `each`
   - `exact` style refusing clusters
   - an abbreviation (`--out`) refused
2. **Every measured form above, driven through the engine**, asserting class and
   decision together (`safe` + deny for a `readOnly` profile and for
   `viewer`/prod). This includes the Windows `sort /O` and `arp /d` forms.
3. **A friction corpus that must stay `read-only`:**
   - `journalctl -u nginx --since today -n 100`
   - `git log --oneline -20`
   - `ls -la`
   - `tail -n 50 -f x`
   - `grep -rn foo /etc`
   - `find / -name x -type f`
   - `ip addr show`
   - `date +%F`
   - `sort -rn x`
   - `uniq -c x`
4. **Every `READERS` entry** has a grammar, and every `'any'` entry has a
   non-empty `audit`. This is a table test, so a new entry cannot skip the
   question.
5. **Differential fuzz against the base classifier, with one invariant.** For
   every input, the new class equals the old one, or the old class was
   `read-only` and the new one is `safe`. This proves mechanically that the
   change only ever *lowers* `read-only`, and that no other class moves.
6. **The refusal message** names the binary and the rejected word, asserted on
   the engine's `reason`.

A test is accepted only after its production line has been deleted and the test
has been measured failing.

## Release

- **Minor.** A command a viewer ran yesterday can be refused today, which falls
  under the rule applied since 2.8.0.
- The changeset lists the spellings that now fall to `safe` and says how a
  viewer finds out which ones still work (the refusal message).
- Before publication, the advisory's table is updated with this round's
  findings: `git --output`, Windows `sort /O`, `arp /d`, `ss -K`, `file -C`.
- Then `patched_versions` is filled and the advisory is published. Credit goes
  to the maintainer's own review, and the advisory says it was found during
  GHSA-qmx6-47vm-3vf7's allowlist sweep.
