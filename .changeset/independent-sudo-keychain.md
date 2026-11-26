---
"ssh-mcp": minor
---

Add optional per-profile `sudoKeychainEntry` support, independent of SSH authentication. Retrieve the native keyring credential only for authorized privileged commands, without caching it on the connection or falling back to environment variables when an explicit entry is configured. Ignore and do not refresh sudo authentication timestamps for keychain-backed commands (`sudo -k`). Use non-PTY stdin delivery and withhold live output previews when sending a sudo credential. Existing profiles without the new field retain their environment-based sudo credential resolution.
