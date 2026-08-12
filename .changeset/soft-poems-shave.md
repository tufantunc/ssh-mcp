---
"ssh-mcp": major
---

Read policy overrides from the config file, and refuse to start when the policy does not mean what it says.

An optional `[policy]` section is now merged over the compiled-in `DEFAULT_RULES` at startup, so `roleBindings` and `denylist` can be set without relabelling a host or standing up an OPA sidecar ([#95](https://github.com/tufantunc/ssh-mcp/issues/95)). The merge is at role and tier depth, so defining `admin.prod` leaves `admin.staging`, `admin.dev`, `viewer` and `operator` on their defaults. Roles and tiers absent from the defaults are added rather than rejected, which is what makes a custom `group` on a profile resolve to real bindings.

An OPA sidecar is not an alternative route to the same grant: OPA is consulted only for commands the local policy already allows, so it can refuse more but never widen. Widening happens in `[policy]` or not at all.

**Nothing is silently ignored any more.** Every way a config could be written, parsed and then quietly mean nothing is now a startup error naming the file's own vocabulary — which is the bug this release exists to close, since #95 was exactly that shape. Startup fails on:

- an unrecognised top-level section or key anywhere in the config (the root schema is now `.strict()`);
- a command class outside `read-only | safe | destructive | privileged`, so a `priviledged` typo cannot parse into a grant of nothing and then read like a policy decision;
- a role or tier under `[policy.roleBindings]` that no profile can reach, so `[policy.roleBindings.operater]` cannot merge in as a fourth role while `operator` keeps its defaults;
- a profile whose `role` has no bindings, which used to be silently demoted to read-only;
- a profile whose tier — set explicitly, or inferred from the profile name — has no bindings under its role;
- an invalid regex in `denylist`;
- a role or tier named `__proto__`, `constructor` or `prototype`, which would be accepted and then not exist once merged.

All problems are reported at once rather than one per restart.

An unresolved tier no longer falls back to the role's `prod` cell. While the matrix was compiled in, that fallback meant falling back to the strictest cell for that role; once `[policy]` can write `prod`, the same hop hands an unresolved tier whatever production was granted. A partial custom role plus profiles that set no `group` was enough to reach it with no typo involved.

**Upgrade notes.** Two kinds of config that started under 2.x now fail at load. Both failures name the offending line, and both are the point of the release rather than side effects:

1. **An unrecognised top-level section.** Previously parsed cleanly and was dropped, so an upgrade can surface a typo that has been inert for some time — including a `[policy]` block written against the old README, which said such a block was accepted and ignored. Read any pre-existing `[policy]` section before upgrading: it is live now, and the usual content of one is a grant.
2. **A custom `role` on a profile.** `role` is a free string that only ever matched `viewer`, `operator` or `admin`; anything else was silently demoted to read-only. That now stops startup, and it is the one new failure that can fire on a config carrying no `[policy]` section at all. Either correct the role, or give it bindings with `[policy.roleBindings.<role>]`.
