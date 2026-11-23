# `split --filter` as a carrier (GHSA-gpfp-xjq7-64hv)

## Problem, as measured on 2.26.0 (e04ebf2)

GNU `split --filter=COMMAND` runs `sh -c COMMAND` once per output chunk. `split` is in no
table the classifier keeps, so the only thing that reads its operands is the speculative
catch-all in `nestedCommands`, which classifies an operand, or the value attached to a
`--flag=`, as a command only when it contains whitespace.

| Command | Class on 2.26.0 |
|---|---|
| `split --filter=reboot x` | `safe` (direct: `destructive`, never-allowed) |
| `split --filter reboot x` | `safe` |
| `split --filter='sudo id' x` | `privileged` (already read: it has a space) |
| a filter value that reaches `sudo` with no whitespace character in it | `safe` |
| `split --filter='id;reboot' x` | `safe` |

The fourth row is not in the report: the gap reaches elevation, not only one-word commands.

Measured in the test container (coreutils 9.11): `--filter=X`, `--filt=X`, `--f=X`,
`--filter X` and `--fi X` all run `X`. No other `split` long option starts with `--f`, so
every prefix from `--f` up is unambiguous to `getopt_long`.

## Design

`splitFilterPrograms(words)`, beside `tarCheckpointExecPrograms` and with the same rules:

- head-gated through `commandHeads` on `split` and `gsplit` (the name GNU coreutils is
  installed under on macOS and the BSDs), so wrappers are read past and a mention
  (`echo --filter=reboot`) or another binary's `--filter` carries nothing;
- attached (`--f…=X`) and detached (`--f… X`) spellings, every prefix from `--f` to
  `--filter`, every occurrence on the line;
- the value is pushed whatever its shape, so a single word is classified;
- emitted outside the speculative block, so the forbidden-command scan
  (`nestedCommands(command, false, …)`) sees it too;
- listed in `hasUnreadableProgram` next to the tar and sqlite3 carriers, so the outer
  command is `destructive` whenever a filter is present and an inner elevation raises it to
  `privileged`. `split --filter=/tmp/x.sh` therefore gates on approval too.

A filter that reaches `sudo` through `$IFS` classifies `destructive`, not `privileged`:
that is the class the same text has when typed directly (a command word nothing here can
name). The approval gate holds; the audit class is the weaker of the two.

## What was tried on this branch and withdrawn

While fixing this, a wider defect was found: the classifier does not read the shell's own
grammar. A command inside a subshell or a brace group, after a reserved word, in a function
body or a `case` arm, or behind a redirection, is classified by a word that names no binary
and comes out `safe`, with no never-allowed match. That is a separate finding with its own
advisory and its own design; it ships in the same release as this fix.

A first attempt at it was made on this branch (commit 9c7a230) by adding rules to the
existing tokeniser, together with a wider shape test for the operand catch-all. Three
independent reviews (security, correctness, tests) measured it and it is withdrawn:

- it lowered classes main gets right — an empty or ordinary substitution among the
  arguments, a quoted `>` as a wrapper's operand, a redirection between a carrier and the
  argument it reads — including lost never-allowed matches;
- one new loop was quadratic (64 KB of input: 23 ms on main, 47 s on the branch);
- it raised everyday commands to `destructive` or `privileged`: template and JSON
  arguments, `jq` filters, SQL with `count(*)`, search patterns holding `|`;
- 38 of 113 single-point mutations survived its tests.

The common cause: the tokeniser does not record whether a word was quoted or how deep in a
substitution a character sits, and every added rule needed one of the two. The lesson for
the grammar design is in its own spec; the withdrawn code and its tests are not kept here.

## Tests

`test/unit/policy/split-filter-carrier.test.ts`, 49 tests; 37 fail on main's classifier.
27 single-point mutations of the added lines — each prefix in each spelling, each
condition, each head — were run against the file and every one fails at least one test.
Rows that already passed on main are marked as guards in the file.

## Release

Minor: commands that classified `safe` now gate on approval. Held until the shell-grammar
fix is ready; both ship in one release. Advisory published after the merge with
`patched_versions` filled and @chrispham-cyber credited; Security line in the CHANGELOG and
release notes.
