---
"ssh-mcp": patch
---

Let a config file say "no command-length limit", the way the CLI flag already can ([#123](https://github.com/tufantunc/ssh-mcp/issues/123)).

`--maxChars=none` disables the cap and the README documents `none` or `0` as doing so. The TOML schema was `positive()`, so `commandMaxChars = 0` was a startup error and the config file had no spelling for it. Moving a flags-based invocation into a config file therefore tightened the limit back to the 5000 default, and the only way to express uncapped was to write `9007199254740991` out in full.

`commandMaxChars` and the per-profile `maxChars` are now `nonnegative()`, with `0` meaning unlimited. That is the convention this config file already uses for `commandQuotaPerDay` and `approvalGrantTtlMs`, so `commandMaxChars` was the odd one out rather than the key needing a new spelling invented for it.

**`0` is mapped rather than merely permitted.** `sanitizeCommand` tests `cleaned.length > maxChars`, so a literal `0` arriving there would reject every non-empty command with `Command is too long (max 0 characters)` — a worse failure than the one being fixed. `normalizeConfig` maps it to `Number.MAX_SAFE_INTEGER`, the same value `parseMaxChars` produces for the flag, so the two surfaces hand the rest of the code an identical `Profile` rather than two spellings of uncapped.

Negatives stay rejected. `--maxChars=-1` means unlimited only as a wart of `parseInt` handling, it is undocumented, and it is likelier to be a typo than an intent; parity is worth having between the documented behaviours, not between the accidents.
