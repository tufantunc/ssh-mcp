---
"ssh-mcp": patch
---

Allow `@napi-rs/keyring` 2 (`^2.1.1`, was `^1.1.0`) for `auth = "keychain"` profiles. Its one breaking change is how a store failure is reported: a locked or inaccessible keychain used to read as "no entry" and now raises an error. This server already caught that error, so the outcome is the same — the lookup fails and the remaining credential sources are tried — except that the failure is now logged (`Keychain lookup failed …`) instead of passing silently.
