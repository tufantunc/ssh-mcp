---
"ssh-mcp": minor
---

Upgrade zod to 4.x.

`minor` rather than `patch` for the reason 2.3.0 used it: the version reflects what upgrading can do to you, not how large the change is. Nothing that started on 2.4.2 refuses to start here and no config that loaded then fails now — but `tools/list` changes on ten of the eleven tools, and every config validation message is reworded. A client or a wrapper can observe this release.

**What made it more than a version bump.** Our `overrides` block pinned `zod-to-json-schema` to `3.24.6`, added to fix a startup crash under zod 3 (#47). That pin needs zod `^3.24.1`, so npm satisfied the MCP SDK with a *nested* zod 3 while our own code used zod 4 — two copies in one tree, which is why a bare bump reports `Type 'ZodString' is not assignable to type 'AnySchema'` at every tool definition. Dropping the override lets `zod-to-json-schema` reach 3.25.2, which accepts zod 4, and the tree dedupes onto a single `zod@4.4.3`. The SDK needed nothing: it ships its own version-compat layer. Note the override only ever governed *our* install — npm honours overrides in the root project only, so anyone who installed `ssh-mcp` was already resolving `zod-to-json-schema` from the SDK's own range.

`defaults: defaultsSchema.default({})` became `.prefault({})`. zod 4 wants the parsed output from `.default()`, and `.prefault()` is the input-side behaviour zod 3 had — with `.default({})` the inner defaults are skipped and `commandMaxChars` arrives `undefined`.

**A config guard had to be rebuilt.** `[policy.roleBindings."__proto__"]` was rejected under zod 3 by the key schema. zod 4's `z.record` never hands `__proto__` to the key schema — it drops the key and returns an object without it, so the block parsed cleanly and vanished. Not prototype pollution: zod 4 declines to write the key, which is the safe half. What was lost is the refusal, and downstream only notices when a profile actually uses that role, so a binding block nothing referenced disappeared in silence. zod 4 also replaces key-schema messages with its own `Invalid key in record`, so the reserved-name text and the empty-name text both stopped reaching the operator. The check now runs against the raw object before `z.record` sees it and owns both rules; the unreachable `refine` came off the key schema at the same time. Reserved-name diagnostics also name the role a bad tier sits under rather than only the tier.

Against the released 2.4.2 this changes no verdict — zod 3 refused all three reserved names too. It matters to anyone bisecting the two commits in this release, and it is what keeps the refusal working now.

### Client- and operator-visible changes

- **`tools/list` no longer advertises `additionalProperties: false`** on the nine tools that take arguments. Runtime behaviour is unchanged: an extra argument is accepted and stripped before the handler sees it, on both versions. zod 3's advertisement was the inaccurate one — it told clients extra properties were rejected while they were silently dropped. A client that validated locally loses a guard that used to catch invented arguments early; the server behaves as it always did.
- **`signal-process.pid` gained `maximum: 9007199254740991`**, advertised and enforced. zod 4's `.int()` carries a safe-integer bound where zod 3's only tested `Number.isInteger`. A pid above 2^53−1 is now refused; no operating system issues one — Linux caps `pid_max` at 2^22.
- **Every config validation message is reworded.** `Unrecognized key(s) in object: 'x'` becomes `Unrecognized key: "x"`; `Array must contain at least 1 element(s)` becomes `Too small: expected array to have >=1 items`. Refusals and exit codes are unchanged; a wrapper matching on message text is not. Enum failures no longer echo the rejected value, which was the useful half for a typo like `priviledged`.
- **Key order inside emitted schemas differs**, and `additionalProperties` no longer precedes `$schema`. Not semantic.

Config parsing, every policy decision, and the runtime validation of every argument a client can realistically send are unchanged.
