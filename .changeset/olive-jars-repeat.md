---
"ssh-mcp": patch
---

Say what a decision was about, and what a refusal leaves you able to do.

**`binary` now names the command the class describes** ([#134](https://github.com/tufantunc/ssh-mcp/issues/134)). Since elevation began to be detected per segment in 2.2.4, the class and the binary could describe different commands: `echo hi; sudo id` recorded `binary: "echo"` against a `privileged` decision, and `cd /srv && sudo systemctl restart app` recorded `cd`. That is what reached the audit log, the OTel span attribute `command.binary` and OPA's `resource.binary`, so an auditor filtering the store by binary would not have found the privileged decision at all.

It now names what runs under elevation — `id`, `systemctl` — looking past exec wrappers, `NAME=value` assignments and the prefix's own value-taking flags, and falling back to the prefix itself for a bare `sudo`. Every other class still names the leading command, which is what it always meant. No decision changes: `binary` is a classification input only in the read-only allowlist check, and the privileged branch returns before reaching it.

**`HOST_KEY_MISMATCH` no longer leaves the reader to guess.** It stated that the key had changed and stopped there, truncating both fingerprints to twenty characters — the one comparison the reader has to make, made harder. A rebuilt server and an interception produce the identical symptom, and with nothing to separate them the available move is `--insecureHostKey`, which disables verification for every host and every future connection rather than for this one. The message now names both causes, shows both fingerprints in full, says to confirm out of band and how (`ssh-keygen -lf` on the host itself), points at `trustedHostKey` for the genuine case, and says plainly what the escape hatch costs.

**Credential resolution failures name the method the profile asked for.** The message listed all four available methods regardless of which one `auth` selected, which reads as an invitation to take whichever is easiest — and the easiest is a plaintext password in the environment. It now says which method was requested and why it produced nothing (`SSH_AUTH_SOCK` unset, `keychainEntry` missing, and so on), then orders the alternatives by how much each exposes.

All three are the same defect with different surfaces: the mechanism decided correctly and then described the outcome rather than what produced it. `explainRoleDenial`, the denylist refusal and `APPROVAL_DENIED` were earlier instances.
