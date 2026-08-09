---
'ssh-mcp': patch
---

Refuse to guess which host to use when several profiles are configured and none is selected.

`getProfile` fell back to `profiles[0]` when a tool call carried no `profile`
argument and no `defaults.defaultProfile` was set. With several hosts configured
that meant the command ran against whichever profile happened to be listed
first — no argument, no warning — and the first one written down tends to be
production.

It now raises an error naming the configured profiles and both ways to resolve
the ambiguity:

```
No profile selected and no default configured, but 3 profiles exist:
prod, staging, dev. Pass a "profile" argument, or set
defaults.defaultProfile in the config.
```

A single configured profile is unambiguous and still resolves without one.

If you run several profiles without `defaultProfile` today, set it (or pass
`profile` per call) — previously that configuration ran commands against the
first profile in the file.

Reported by @Isla-Liu in #54.
