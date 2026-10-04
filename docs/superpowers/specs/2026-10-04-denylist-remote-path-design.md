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
3. **Lexical normalization only.** The pattern sees the path as given and a lexically
   normalized form. Nothing is resolved on the target: relative paths stay relative and
   symlinks are not followed. Resolving with SFTP `REALPATH` would cost a round trip per
   call, needs its behaviour on a not-yet-existing file measured, and is a hardening step
   rather than part of decoupling rules from our format.
4. **Remote path only, not the local one.** The denylist answers what may happen on the
   target host; the local side is confined by `transferRoot`. The local path is not
   tested *on its own*. It still ends the command string of `sftp-upload-file` and
   `sftp-download-file`, which every pattern sees exactly as before, so an end-anchored
   pattern such as `authorized_keys$` can still match it there — as it always could.
   (Corrected during implementation: the first version of this decision said such a
   download would not be refused, which contradicted the compatibility section.)

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

### Engine — `src/policy/engine.ts`

- `evaluate(command, profile, toolName, subject?)` and `evaluateWithOpa(…, subject?)`
  take an optional `subject: { remotePath?: string }`. Every existing caller passes
  nothing and behaves exactly as today.
- `findDenyMatch(command, remotePath?)`: for each operator pattern, test the command
  string as today; then, when `remotePath` is present, the path as given; then the
  normalized form when it differs. The first match denies. Nothing else in
  `findDenyMatch` changes.
- The refusal says what matched:
  - command: unchanged, `Command matches /p/, a pattern from [policy].denylist …`
  - path as given: `Remote path "<path>" matches /p/, a pattern from [policy].denylist …`
  - normalized form: `Remote path "<path>" (read as "<normalized>") matches /p/, …`
- OPA input gains `resource.remotePath` when the path is present, and omits the key
  otherwise.

### Pipeline — `src/tools/pipeline.ts`

- `AuditedOpts` gains `remotePath?: string`. `runAudited` hands it to
  `checkPolicyAndApprove`, which hands it to `evaluateWithOpa`.
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
  call; for the five SFTP tools also the remote path, as given and normalized). What it is
  not tested against or does not resolve: relative paths are not made absolute, so a rule
  anchored on `/root/` does not see `.ssh/x`; symlinks are not followed; local paths are
  not tested; matching is case-sensitive, Windows paths included. The advice: anchor on
  trailing segments — `\.ssh/authorized_keys$` catches the absolute, relative and Windows
  spellings.
- **README, the "path comes last" paragraph** in the `sftp-upload` section, and the
  matching comment in `src/tools/file-tools.ts`: shortened to say that a rule anchored on
  the whole string stays coupled to the format, and a path rule no longer is.
- **README, config examples:** a path rule next to the existing
  `denylist = ["^terraform\\s+destroy"]`.

## Compatibility and release

- No config breaks. Every pattern is still tested against the command string exactly as
  before; what is added only ever leads to more denials.
- The one behaviour change: a pattern written for commands is now also tested against
  SFTP paths. `^rm` would refuse an `sftp-download` of `rmlist.txt`.
- **Minor**, because a call that was allowed can now be refused. The changeset's upgrade
  note: a denylist pattern now also sees the remote path of the SFTP tools; a pattern
  written for commands can match a file name, so check refusals, whose message says
  whether the path matched.

## Tests

Every test is written first, seen to fail, and accepted only once it fails with its
production line removed. No wall-clock waits.

1. **`test/unit/policy/remote-path.test.ts` (new):** a table — `//` and `/./` collapse;
   `..` against the preceding segment; no climb above an absolute root (`/../etc` →
   `/etc`); a relative path's leading `..` kept; trailing separator removed; `\` and mixed
   separators (`C:\Users\a/.ssh\..\x`); an already-normal path unchanged.
2. **`test/unit/policy/engine.test.ts`:** with `denylist` and a `remotePath` — a pattern
   matching the path as given denies; one matching only the normalized form denies and
   the message shows that form; a pattern anchored on the whole string (`^sftp:upload `)
   still denies; without `remotePath`, a pattern that only a path could match does not deny
   (`^/root/` against `sftp:list /root/x` is allowed, as today); the message says whether
   the command or the path matched.
3. **`test/unit/policy/opa.test.ts`:** `resource.remotePath` present when passed, absent
   when not.
4. **Tool level (`test/unit/tools/`):** the harness gains a `policyRules` option.
   - For each of the five SFTP tools, `authorized_keys$` with remote path
     `/root/.ssh/authorized_keys` gives `deny`, `ruleId: denylist`, an audit record, and a
     message naming the path. The `sftp-upload-file` and `sftp-download-file` rows fail on
     today's code — the RED that proves #230.
   - For each tool, a second row where the pattern matches only the normalized form
     (`/srv/x/../../root/.ssh/authorized_keys` with `^/root/\.ssh/`), so a tool that stops
     passing its path fails its own row.
   - `sftp-download-file` with remote `/srv/backup.tar` and local `authorized_keys` is not
     refused by `^authorized_keys$`, a pattern that matches the local path alone and
     neither the command string nor the remote path.

## Out of scope

- Matching paths inside shell commands.
- Resolving paths on the target (`REALPATH`, symlinks, home-relative paths).
- Testing patterns against local paths.
- Case-insensitive matching for Windows targets.
