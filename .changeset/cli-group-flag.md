---
'ssh-mcp': minor
---

Add `--group`, and say which of role, group and class caused a policy refusal.

A quick-start profile (`--host`/`--user`, no config file) carried no host group,
so it fell to the strictest tier — where the `admin` role has no `privileged`.
`sudo` could therefore never run for anyone who had not written a TOML config,
and no flag existed to change it. Reported in #91.

`--group` accepts `prod`, `staging` or `dev`. The default is still `prod`:
treating an unknown host as production is the safe guess, and what was missing
was a way to correct it. An unrecognised value is rejected rather than quietly
falling back to the prod bindings.

```bash
npx ssh-mcp --host=10.0.0.5 --user=deploy --group=dev
```

The refusal itself was also misleading. It read:

```
Role "admin" cannot run "privileged" commands
```

naming the role and the class but not the host group, which is usually what
decided. It now names all three, lists what the role *can* run, and — when the
group was inferred rather than configured — says so and how to set one:

```
Role "admin" on host group "prod" cannot run "privileged" commands
(allowed: read-only, safe, destructive). No group is set for profile "default",
so it defaulted to the most restrictive tier. Set group = "dev" or "staging" on
the profile, or pass --group, if this host is not production.
```
