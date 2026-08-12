---
"ssh-mcp": patch
---

Fix the approval dialog turning Accept into a decline, and three boolean CLI flags that did nothing ([#91](https://github.com/tufantunc/ssh-mcp/issues/91)).

**Approving a command now takes one keystroke, and works.** The elicitation request asked for a required `confirm` boolean on top of the protocol's own `accept`/`decline`, so clients rendered a checkbox beside the accept row. Choosing Accept without ticking it submitted a form missing a required field, the client answered `cancel`, and ssh-mcp reported `APPROVAL_DENIED: User did not approve this command` — to a user who had just pressed Approve. The decision now comes from `action` alone. An explicit `confirm: false` is still honoured for clients that send one.

**Approval waits 10 minutes instead of 60 seconds.** The request inherited the SDK's `DEFAULT_REQUEST_TIMEOUT_MSEC`, setting a human's reading time from a default meant for machine round trips. An operator who stepped away, or who was working out an unfamiliar dialog, had it expire underneath them.

**A timed-out approval says so.** `APPROVAL_UNAVAILABLE` led with "a client without elicitation support" for every error, including a timeout where support was fine — the same wrong-cause defect the message was split out to fix, one release later, inside its own fix. Timeouts now name the elapsed budget and say the prompt may still be open.

**`--disableApproval`, `--auditEntropyScan` and `--auditTamperEvident` were no-ops.** `parseArgv` stores `null` for a flag written without `=`, which is how all three are documented, and each call site tested that for truthiness. They did nothing unless spelled `--flag=1`. The audit pair is the serious half: anyone who turned on hash-chained tamper-evident logging was running without it and had no signal. All flags now read presence through one helper, and `--flag=false` (or `0`, `no`, `off`) turns one back off.
