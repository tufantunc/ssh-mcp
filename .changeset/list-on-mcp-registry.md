---
"ssh-mcp": patch
---

List ssh-mcp on the official MCP registry, and keep the listing current from the release that produces it.

`registry.modelcontextprotocol.io` verifies that whoever registers `io.github.tufantunc/ssh-mcp` also owns the npm package it points at, and it does that by fetching `registry.npmjs.org/ssh-mcp/<version>` — the manifest of one exact version, not the package — and requiring an `mcpName` field in it that matches the server name. npm versions are immutable, so no version already published can ever gain that field: the listing is only reachable through a release, and this is it. There is no behaviour change in the server; the only thing this version adds over 2.3.3 is a manifest the registry will accept.

`server.json` carries the version twice — the listing's own, and the npm version it resolves — and both have to name what actually shipped. `scripts/sync-server-json.mjs` writes them from `package.json` and is wired to the `version` npm script, which is what the changesets action runs when it opens the "Version Packages" pull request; the rewrite is committed there alongside the version bump, so main is already correct by the time anything publishes. The script also refuses a `mcpName`/`server.json` name mismatch, and refuses a `packages[].identifier` that is not the npm package name — the registry reports both as ownership failures *after* npm has published, at the single step of a release that a re-run cannot undo.

Publishing to the registry is a second job in the Changesets workflow, gated on the action's `published` output, and not the tag-triggered workflow that shape usually takes: the `v*` tag is pushed with `GITHUB_TOKEN`, and GitHub starts no workflows for those pushes — the same loop-breaker that already keeps `ci.yml` off `changeset-release/main`. A workflow listening for that tag would simply never run. It is a separate job rather than more steps on the release job because a registry failure has to be retryable without re-attempting the npm publish, which would fail first and hide it.

Both credentials are OIDC, so the registry step adds no secret: `mcp-publisher login github-oidc` exchanges the workflow's identity for a registry token, and the `io.github.tufantunc/*` namespace is authorised from the repository owner in its claims.

## What review changed

The first version of this was reviewed before merging, and five things it got wrong are worth recording, because each one is a mistake the shape of the change invites.

**The publisher binary was executed unverified.** Pinning `v1.8.1` in the download URL pins a *release*, not its bytes — GitHub release assets can be replaced in place. That is a weaker pin than any other reference in this workflow, and it lands in the worst possible job: npm's trusted publisher is bound to a workflow *filename*, and the registry job lives in the same `changesets.yml`, so anything executing there can mint a token npm accepts for ssh-mcp. The install step now checks the sha256 published in `registry_1.8.1_checksums.txt` before extracting, and a version bump means bumping both lines.

**Two schema rules were copied into the script, on a false premise.** A hand-rolled 100-character cap on `title` and `description` was defended by a comment claiming mcp-publisher only reports such things at publish time. It does not: `mcp-publisher validate` checks the whole schema — required fields, the name pattern, the enums, every cap — against an endpoint that needs no credentials. The workflow runs it before the npm wait, the copied constant is gone, and the caps that a person can actually get wrong by hand are asserted on the real file in `test/unit/sync-server-json.test.ts`, which fails on the pull request that writes them rather than on the release two merges later.

**`needs: release` could strand a published version permanently.** `needs` means "only if that job succeeded", and the action pushes the git tag and creates the GitHub release *after* `changeset publish` returns — so npm can have the version while the release job fails. The registry job would skip, and no re-run could reach it: `changeset publish` finds the version already on npm, releases nothing, and reports `published: false` forever. The gate is now `!cancelled() && …`, and a `list_only` dispatch input lists the current version without going near the publish path, for the one state the output cannot describe.

**The npm-visibility wait could not do its job.** `npm view pkg@version` fetches the whole packument and resolves locally; npm serves packuments with `max-age=300` and defaults `prefer-online` to false. The loop checked for 290 seconds, entirely inside that window, so in the only scenario it exists for — the version not yet visible on the first attempt — every later attempt could be answered from the same stale cached document, failing while npm was serving the version. It now GETs `registry.npmjs.org/<identifier>/<version>`, which is the exact URL the registry's own validator builds, with the identifier read from `server.json` rather than hardcoded, and it keeps curl's error rather than reporting every failure as propagation lag.

**The admin-merge checklist went stale.** The comment describing what a "Version Packages" pull request is allowed to touch now has to include `server.json`, or every future release PR looks wider than the rule allows. `CONTRIBUTING.md` says what `server.json` is and which of its fields are generated.

## Two deliberate deviations

`--check` and the `server.json` assertions were not in the plan this change was written against; they are additions, kept because the script's guards are otherwise unobservable — on a healthy repo every guard branch is false, and `scripts/` sits outside Sonar, the coverage report and both tsconfigs, so a guard that stopped firing would look exactly like one that passed.

`SSH_MCP_KEY` is declared with `format: "filepath"` and *not* `isSecret`, unlike the three password variables. It names a path, not key material; marking it secret would have clients mask a filename while telling the reader something untrue about what the variable holds.
