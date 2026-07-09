# Stack pack: node — tests
extends: core/skills/tests/SKILL.md

## Stack-specific signals
- Unit tests that mock everything and assert only mocks (no real behavior exercised).
- Integration tests sharing a real database with no isolation/truncation between tests → order-dependent flakes.
- Tests depending on wall-clock time / `Date.now()` / timeouts without freezing or injecting time.
- Network/external-service calls not stubbed → flaky on CI / offline.
- `supertest`/handler tests that don't assert status + body, only "no throw".
- Tests that mutate module-level/shared state and don't restore it.

## Stack-specific remedies
- Prefer integration tests that exercise the real handler + a isolated test DB; mock only true external boundaries.
- Truncate/transaction-rollback the DB between tests for isolation.
- Inject a fake clock; stub `fetch`/HTTP at a single boundary (e.g. MSW) for determinism.

## Stack-specific severity guidance
- Order-dependent integration test (shared DB state): High (flaky).
- Test that only asserts the mock was called (no real behavior): High.
- Untested time/external dependency causing CI flakes: Medium/High.
