---
"ssh-mcp": minor
---

Read policy overrides from the config file. An optional `[policy]` section is now merged over the compiled-in `DEFAULT_RULES` at startup, so `roleBindings` and `denylist` can be set without relabelling a host or standing up an OPA sidecar (#95).

The merge is at role and tier depth, so defining `admin.prod` leaves `admin.staging`, `admin.dev`, `viewer` and `operator` on their defaults. Roles and tiers absent from the defaults are added rather than rejected, which makes a custom `group` on a profile resolve to real bindings instead of falling back to the strictest tier.

Command classes are validated against `read-only | safe | destructive | privileged`, and role and tier names may not be `__proto__`, `constructor` or `prototype`, which would be accepted and then not exist once merged.

The root config schema is now `.strict()`. Previously an unknown top-level section, including the `[policy]` block the README told operators to write, parsed cleanly and was dropped with no warning.

**Upgrade note:** a config carrying an unrecognised top-level section used to start and ignore it, and now fails at load naming the section. That is the point of the change, but it means an upgrade can surface a typo that has been inert for some time.
