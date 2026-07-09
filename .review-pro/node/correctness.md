# Stack pack: node — correctness
extends: core/skills/correctness/SKILL.md

## Stack-specific signals
- Unhandled promise rejections (async without try/catch, or `.then` without `.catch`) → app crash or silent skip.
- `async` handler in Express/Connect registered without a wrapper → rejected promise never propagates, error swallowed.
- `EventEmitter` with unbounded listeners, or listeners added per-request without removal → leak + `MaxListenersExceededWarning`.
- `process.exit(...)` inside libraries/handlers (kills the process) instead of propagating errors.
- Mixing `await` and `.then` on the same value, or forgetting `await` on a side-effecting async call.
- Streams consumed incorrectly (reading before `data`/`readable`, or not handling `error`).
- `setTimeout`/`setInterval` scheduled but never cleared.

## Stack-specific remedies
- Wrap async route handlers with an error-forwarding wrapper; add a central error middleware.
- Remove listeners on completion; reuse single emitters.
- Let errors propagate; reserve `process.exit` for boot/shutdown, not request handling.
- Always `await` side-effecting async calls; handle stream `error` events.

## Stack-specific severity guidance
- Async route handler that swallows rejections on a mutating path: High.
- EventEmitter leak that grows per request: High (memory + correctness over time).
- Forgotten `await` on a write: High.
