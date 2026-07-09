# Stack pack: node — backend
extends: core/skills/backend/SKILL.md

## Stack-specific signals
- Async middleware/handlers not wrapped → rejected promises never reach the error handler (silent 500s/hangs).
- Missing input validation on route handlers; trusting `req.body`/`req.query`/`req.params` directly.
- Mutating endpoints without idempotency (no idempotency key, no unique constraint) → unsafe retries/double-submit.
- Expensive endpoints with no rate limit / concurrency cap.
- Synchronous heavy work (`JSON.parse` of huge payloads, blocking crypto) on the request thread.
- Inconsistent error response shapes across handlers (some `{error}`, some `{message}`, some strings).
- Business logic in route handlers instead of a service layer.

## Stack-specific remedies
- Use an async-handler wrapper + a single typed error middleware with a consistent response shape.
- Validate at the boundary with a schema (zod/joi/valibot); reject early with a clear 400.
- Make mutating endpoints idempotent via key + unique constraint; cap expensive work with rate limiting.
- Move business logic into a service module; keep routes thin.

## Stack-specific severity guidance
- Unvalidated mutating endpoint: High.
- Async handler swallowing rejections: High.
- Business logic sprawled in route handlers (layer leak): Medium.
