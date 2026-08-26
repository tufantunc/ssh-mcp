---
"ssh-mcp": patch
---

Upgrade zod to 4.x, and restore a config guard that it silently disabled.

The bump alone does not build. Three things had to move with it.

**The `zod-to-json-schema` override had to go.** It was pinned to `3.24.6` to fix a startup crash under zod 3 (#47), and that pin requires zod `^3.24.1` — so npm satisfied the MCP SDK with a *nested* zod 3 while our own code used zod 4. Two copies in one tree means the SDK types our schemas against internals they do not have, which is why a bare version bump reports `Type 'ZodString' is not assignable to type 'AnySchema'` at every tool definition. Dropping the override lets `zod-to-json-schema` move to 3.25.2, which accepts zod 4, and the whole tree dedupes onto a single `zod@4.4.3`. The SDK needs no help beyond that: it carries its own version-compat layer.

**`defaults: defaultsSchema.default({})` became `.prefault({})`.** zod 4 requires `.default()` to supply the parsed output, and added `.prefault()` for the input-side behaviour zod 3 had.

**And the reserved-key guard stopped working.** `[policy.roleBindings."__proto__"]` was rejected with "Reserved name" under zod 3. Under zod 4, `z.record` never hands `__proto__` to the key schema — it drops the key and returns an object without it, so the config parses *cleanly* and comes out empty. This is not prototype pollution; zod 4 declines to write the key at all, which is the safe half. What is lost is the refusal: an operator naming that role gets a clean startup and a role that silently does not exist, which is the exact failure the guard was written for. `constructor` and `prototype` still reach the key schema and are still rejected. The check now runs against the raw object before `z.record` sees it, and covers all three.

Nothing changes for a valid config. `tools/list` schemas, config parsing and every policy decision are unaffected — the one behaviour difference is that an invalid role or tier name is refused again instead of being dropped.
