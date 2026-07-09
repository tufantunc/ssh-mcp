# Stack pack: ssh-mcp — tests
extends: core/skills/tests/SKILL.md

## Stack-specific signals
- **No property test for sanitizers** — `sanitizeMetadata()` and `sanitizeCommand()` are security-critical. If there's no `fast-check` property test asserting "no CR/LF/NUL survives sanitization", that's a gap.
- **Integration tests without real SSH server** — mocking `ssh2.Client` entirely hides PTY/session/connection bugs. Tests must use the Docker `linuxserver/openssh-server` container.
- **Session tests not verifying CWD persistence** — the key value of interactive sessions is state persistence. If tests don't assert `cd /tmp` → `pwd` returns `/tmp`, the sentinel/ANSI stripping logic is untested.
- **Sudo tests checking password in argv** — if tests verify `printf '%s\n' '<pw>' | sudo -S`, they're testing the vulnerable pattern. Tests should verify the password is NOT visible in the remote process list.
- **Missing CWE-78 regression corpus** — the Issue #44 PoC (`description` with `\nid > /root/poc.txt`) must be in a regression test.
- **Connection lifecycle tests missing reconnect** — if tests don't close → reconnect → verify `isConnected()`, the reconnect bug (`connecting` not reset) won't be caught.
- **Test env vars leaking to other tests** — `SSH_MCP_TEST_PASSWORD` set in `beforeEach` but not cleaned in `afterEach` causes cross-test contamination.
- **Vitest config not excluding legacy tests** — `test/legacy/` must be in the `exclude` array or old v1 tests break the build.

## Stack-specific remedies
- Every sanitizer has a property test with 10k+ random inputs.
- Integration tests start from `docker-compose --profile test up -d` before running.
- Session integration test: `cd /tmp` → `pwd` asserts `/tmp`; `export FOO=bar` → `echo $FOO` asserts `bar`.
- Regression corpus in `test/fixtures/payloads.json` with CWE-78 injection patterns.
- `beforeEach`/`afterEach` save and restore `process.env`.

## Stack-specific severity guidance
- Security-critical function with no property test: **High**.
- Session tests mocking SSH entirely: **High** (false confidence).
- Missing Issue #44 regression test: **High** (known CVE-class bug).
- Env var leak between tests: **Medium** (flaky).
