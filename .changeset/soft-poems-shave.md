---
"ssh-mcp": minor
---

Read policy overrides from the config file. An optional `[policy]` section is now merged over the compiled-in `DEFAULT_RULES` at startup, so `roleBindings` and `denylist` can be set without relabelling a host or standing up an OPA sidecar (#95).

The merge is at role and tier depth, so defining `admin.prod` leaves `admin.staging`, `admin.dev`, `viewer` and `operator` on their defaults. Roles and tiers absent from the defaults are added rather than rejected, which makes a custom `group` on a profile resolve to real bindings instead of falling back to the strictest tier.

Command classes are validated against `read-only | safe | destructive | privileged`, and the root config schema is now `.strict()`. Previously an unknown top-level section, including the `[policy]` block the README told operators to write, parsed cleanly and was dropped with no warning.
