# `[policy].denylist` sees the remote path of the SFTP tools, not only the string we compose

**Issue:** #230.
**Work happens in:** branch `worktree-issue-230-denylist-remote-path`.
**Release:** minor.

## Problem

`PolicyEngine.findDenyMatch` (`src/policy/engine.ts`) tests every `[policy].denylist`
pattern against the whole command string the caller is approving. For a shell command
that string is what the caller typed. For the five SFTP tools it is a string this server
composes (`sftp:upload-file <remote> [--overwrite] [--mode=N] <- <local>`), whose layout
is ours to change, and which does not put the remote path in the same place for every
tool. An operator's rule is therefore coupled to a presentation format, and it fails
silently: no startup error, no warning, and the refusal degrades to whatever the role
binding and approval mode allow.

Measured on `main` at `210cc54`, `PolicyEngine` with the default rules plus one
operator pattern, admin role, `approvalPolicy = "auto"`:

| composed string | `authorized_keys$` | `/root/\.ssh/` |
|---|---|---|
| `sftp:list /root/.ssh/authorized_keys` | deny | deny |
| `sftp:download /root/.ssh/authorized_keys` | deny | deny |
| `sftp:upload --overwrite --bytes=3 --sha256=… /root/.ssh/authorized_keys` | deny | deny |
| `sftp:upload-file /root/.ssh/authorized_keys --overwrite <- ./k` | **pass** | deny |
| `sftp:download-file /root/.ssh/authorized_keys -> ./k` | **pass** | deny |
| `sftp:upload --overwrite --bytes=3 --sha256=… /root//.ssh/x` | — | **pass** |

The first column is the issue's second finding: a rule anchored on the end of the path,
which the README recommends since #229, has never protected the streaming pair, because
their strings end with the local path. The last row is a spelling of the same directory
that a substring rule does not see.

## Decisions

Taken in the design round on 2026-10-04, each with the alternative it was chosen over.

1. **Scope: the tools whose remote path the server knows as a field.** That is the five
   SFTP tools. Shell commands keep today's matching against their text. Extracting paths
   from shell text (`$HOME`, `cd`, quoting, globs, `tee`/`cp`/`dd` and their variants)
   cannot be made complete, and a partial extractor would read as a guarantee it does not
   give.
2. **No new config key.** `[policy].denylist` keeps its meaning and is *also* tested
   against the remote path. An operator's existing `authorized_keys$` starts covering the
   streaming pair with no config change, which is exactly the silent gap #230 reports. A
   separate `denyRemotePaths` key was rejected because it leaves that gap open until every
   operator migrates.
3. **Lexical normalization only, plus a measured Windows reading.** The pattern sees the
   path as given, a lexically normalized form, and a Windows reading of that path tested
   case-insensitively. Nothing is resolved on the target: relative paths stay relative
   and symlinks are not followed. The Windows reading exists because spellings that reach
   the same file on a Windows target were measured over SFTP on the test VM (Windows 11,
   build 26200) and a rule that caught one spelling but not another was a bypass:
   case variants, a trailing run of dots and spaces, and the `::$DATA` default-stream
   spelling all reached the same file; a UNC spelling did too, and a drive-relative one
   resolves against process state this server cannot see, so it is rooted at its drive as
   the fail-closed reading. Backslash separators resolved as well, both after a drive
   letter (`C:\Users\…`, no leading `/`) and in a UNC path (`\\server\share\…`); the
   reading treats `\` as a separator throughout. `\\?\` device prefixes did **not**
   resolve over SFTP, but the reading drops them anyway — it only widens what can match.
   (Corrected after merge: an earlier version of this paragraph said backslash-separated
   spellings did not resolve at all, which the design-round measurement contradicts.)
   Two equivalences stay outside any lexical reading and are documented residuals: 8.3 short names (`AUTHOR~1`), which need the target's directory
   listing, and symlinks. Resolving with SFTP `REALPATH` would cost a round trip per
   call, needs its behaviour on a not-yet-existing file measured, and is a hardening step
   rather than part of decoupling rules from our format.
4. **Remote path only, not the local one.** The denylist answers what may happen on the
   target host; the local side is confined by `transferRoot`. The local path is not
   tested *on its own*. It still ends the command string of `sftp-upload-file` and
   `sftp-download-file`, which every pattern sees exactly as before, so an end-anchored
   pattern such as `authorized_keys$` can still match it there — as it always could.
   (Corrected during implementation: the first version of this decision said such a
   download would not be refused, which contradicted the compatibility section.)
5. **Case-insensitivity lives in the pattern, not the path.** The Windows reading keeps
   the case it was given and is tested with a case-insensitive compile of each operator
   pattern, so `authorized_keys$` catches `Authorized_Keys` and `AUTHORIZED_KEYS$`
   catches `authorized_keys` alike. On a POSIX target those are different files; the
   over-refusal is accepted as the fail-closed direction, the same trade the `\`-as-
   separator reading already makes.

## Design

### Normalization — `src/policy/remote-path.ts` (new)

`normalizeRemotePath(path: string): string`, pure, no I/O.

- `\` is read as a separator as well as `/`, and the result is written with `/`. A
  Windows target's `C:\Users\a\.ssh\authorized_keys` is then also seen as
  `C:/Users/a/.ssh/authorized_keys`. On a POSIX target a filename containing `\` can
  match where it did not before; that error only ever goes toward denying.
- Empty segments collapse (`//` → `/`), `.` segments are dropped, a trailing separator is
  removed.
- `..` removes the preceding segment. An absolute path cannot climb above its root
  (`/../etc` → `/etc`). A relative path keeps a leading `..` it cannot resolve
  (`../../x` stays `../../x`).
- A path that is already normal comes back unchanged, so the engine can skip the second
  test when the two forms are equal.

`normalizeRemotePathForWindows(path: string): string`, pure, no I/O — the same path as
Win32 would resolve it, on top of the reading above:

- A trailing run of dots and spaces is dropped from every segment
  (`authorized_keys.` and `authorized_keys..` are the file), and a segment that is
  nothing but dots disappears, as Win32 reads it (`a.../b` → `a/b`).
- A `::` suffix is cut (`authorized_keys::$DATA` is the default stream, not a different
  file). A single `:` is left alone: that names a different stream, and the measurement
  showed it does not reach the same bytes.
- A drive-relative spelling (`C:x/…`) is rooted at its drive; `..` cannot climb above
  it.
- `\\?\` and `\\.\` device prefixes are dropped.
- A UNC spelling keeps its root (`\\server\share\…` → `//server/share/…`), which the
  plain reading collapses.
- Case is untouched — the engine tests this reading with a case-insensitive compile of
  the pattern.

Not `node:path`: `posix.normalize` lets `..` climb above a drive root and keeps a
trailing separator, and `win32.normalize` answers in backslashes, while a deny rule
needs one reading, in forward slashes, that never climbs.

### Engine — `src/policy/engine.ts`

- `evaluate(command, profile, resource?)` and `evaluateWithOpa(command, profile, toolName, resource?)`
  take an optional `resource: PolicyResource` — `{ remotePath?: string }`, named for the
  OPA input it lands in (the subject there is the profile). `evaluate` no longer takes a
  tool name it never read.
- `findDenyMatch(command, resource)`: for each operator pattern — compiled once as
  written and once case-insensitively — test the command string as today; then, when a
  remote path is present (an empty one means none was), the path as given; then the
  normalized form when it differs; then the Windows reading with the case-insensitive
  compile, always, because case is what it adds even when the strings are equal. The
  first match denies. With no operator patterns at all, nothing is computed or tested.
- The refusal says what matched, each quoted spelling capped at 256 characters (the
  command string in the audit record carries the full one):
  - command: unchanged, `Command matches /p/, a pattern from [policy].denylist …`
  - path as given: `Remote path "<path>" matches /p/, a pattern from [policy].denylist …`
  - normalized form: `Remote path "<path>" (read as "<normalized>") matches /p/, …`
  - Windows reading: `Remote path "<path>" (read as "<windows>", the Windows reading)
    matches /p/i, …`
- OPA input gains `resource.remotePath` (as given), `resource.remotePathNormalized` and
  `resource.remotePathWindows` — the same readings the denylist tests, so a Rego rule
  need not reimplement them. All three are omitted when there is no path, an empty path
  included.

### Pipeline — `src/tools/pipeline.ts`

- `AuditedOpts` gains `resource?: PolicyResource`, forwarded whole to
  `checkPolicyAndApprove` → `evaluateWithOpa`, so a field added to `PolicyResource`
  cannot be silently dropped between the tool layer and the engine.
- `preCheck` already validates the path before the policy check, so the engine only sees
  a path that passed `sanitizeRemotePath` — the same value that appears in the composed
  string.
- Approval grants stay keyed on the command string, which already contains the path.

### Tools

`sftp-list`, `sftp-download`, `sftp-upload` (`src/tools/transfer-tools.ts`,
`src/tools/file-tools.ts`), `sftp-upload-file` and `sftp-download-file` pass the
sanitized remote path as `remotePath`. `session:open`, `session:close` and
`signal-process` carry no remote path and are unchanged.

## Documentation

- **README, denylist:** what a pattern is tested against (the command string for every
  call; for the five SFTP tools also the remote path — as given, normalized, and in a
  Windows reading tested case-insensitively). The Windows reading section states what it
  strips and roots and that it was measured over SFTP on Windows 11 (build 26200), and
  that on a POSIX target its case-insensitivity over-refuses, in the fail-closed
  direction. What no reading does: relative paths are not made absolute, so a rule
  anchored on `/root/` does not see `.ssh/x`; symlinks are not followed; 8.3 short names
  are not expanded. The advice: anchor on trailing segments — `\.ssh/authorized_keys$`
  catches the absolute, relative and Windows spellings, case and trailing-dot variants
  included. One performance note: patterns run against caller-supplied path bytes,
  bounded by the remote-path limit — prefer anchored, linear patterns.
- **README, the "path comes last" paragraph** in the `sftp-upload` section, and the
  matching comment in `src/tools/file-tools.ts`: shortened to say that a rule anchored on
  the whole string stays coupled to the format, and a path rule no longer is.
- **README, config examples:** a path rule next to the existing
  `denylist = ["^terraform\\s+destroy"]`.
- **README, OPA:** the request shape is described as *modeled on* the AuthZEN Access
  Evaluation contract (the keys are flat, not nested under `properties`); the three
  `resource` path keys and their presence rules; advice to match fields rather than the
  whole `resource` object, whose keys vary by tool.

## Compatibility and release

- No config breaks. Every pattern is still tested against the command string exactly as
  before; what is added only ever leads to more denials.
- The behaviour changes: a pattern written for commands is now also tested against
  SFTP paths (`^rm` refuses an `sftp-download` of `rmlist.txt`), and path rules match
  case-insensitively and dot-insensitively through the Windows reading, so on a
  case-sensitive target `authorized_keys$` now also refuses `AUTHORIZED_KEYS` and
  `authorized_keys.`.
- **Minor**, because a call that was allowed can now be refused. The changeset's upgrade
  note: a denylist pattern now also sees the remote path of the SFTP tools and its
  Windows reading; a pattern written for commands can match a file name, so check
  refusals, whose message says which reading matched.

## Tests

Every test is written first, seen to fail, and accepted only once it fails with its
production line removed or mutated. No wall-clock waits.

1. **`test/unit/policy/remote-path.test.ts` (new):** a table for each reader — `//` and
   `/./` collapse; `..` against the preceding segment; no climb above an absolute root
   (`/../etc` → `/etc`); a relative path's leading `..` kept; trailing separator removed;
   `\` and mixed separators (`C:\Users\a/.ssh\..\x`); `.` and `./`; a bare drive `C:`;
   a UNC spelling (collapsed by the plain reading, kept by the Windows one); an
   already-normal path unchanged. The Windows table: trailing dot, double trailing dot,
   trailing space, `::$DATA`, drive-relative rooted (with and without `..`s), UNC root
   kept, `\\?\` prefix dropped, case preserved, a dots-only segment dropped.
2. **`test/unit/policy/engine.test.ts`:** with `denylist` and a `remotePath` — a pattern
   matching the path as given denies; one matching only the normalized form denies and
   the message shows that form; one matching only the Windows reading denies and the
   message shows that reading and the `/i` pattern; the pattern spelled in the other
   case denies; a drive-relative spelling caught by a root-anchored rule; a UNC root
   anchored on; an empty path treated as no path; a very long path capped in the
   message; a pattern anchored on the whole string (`^sftp:upload `) still denies;
   without `remotePath`, a pattern that only a path could match does not deny
   (`^/root/` against `sftp:list /root/x` is allowed, as today); the message says
   whether the command or which reading of the path matched.
3. **`test/unit/policy/opa.test.ts`:** `resource.remotePath` present when passed — pinned
   with a non-normal spelling, so a regression that normalizes before building the input
   is visible — with `remotePathNormalized` and `remotePathWindows` beside it; all three
   absent when there is no path and when the path is empty.
4. **Tool level (`test/unit/tools/`):** the harness gains a `rules` parameter.
   - For each of the five SFTP tools, `authorized_keys$` with remote path
     `/root/.ssh/authorized_keys` gives `deny`, `ruleId: denylist`, an audit record, and a
     message naming the path. The `sftp-upload-file` and `sftp-download-file` rows fail on
     today's code — the RED that proves #230.
   - For each tool, a second row where the pattern matches only the normalized form
     (`/srv/x/../../root/.ssh/authorized_keys` with `^/root/\.ssh/`), so a tool that stops
     passing its path fails its own row.
   - One row where only the Windows reading matches (`C:\Users\a\.ssh\Authorized_Keys.`
     with `\.ssh/authorized_keys$`).
   - `sftp-download-file` with remote `/srv/backup.tar` and local `authorized_keys` is not
     refused by `^authorized_keys$`, a pattern that matches the local path alone and
     neither the command string nor the remote path. The row asserts the allow decision's
     audit record exists, so it cannot pass vacuously if the call stops reaching policy.

## Out of scope

- Matching paths inside shell commands.
- Resolving paths on the target (`REALPATH`, symlinks, home-relative paths).
- Testing patterns against local paths.
- Expanding 8.3 short names (`AUTHOR~1`): no lexical reading can, and the Windows
  measurement is volume-dependent — they need the target's own directory listing.
