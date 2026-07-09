# Stack pack: node — performance
extends: core/skills/performance/SKILL.md

## Stack-specific signals
- Synchronous CPU-heavy work on the event loop (`JSON.parse` of very large payloads, sync crypto, `fs.readFileSync` in a request path) → blocks all requests.
- `await`ing independent async calls sequentially that could run with `Promise.all` → unnecessary latency.
- Whole payloads buffered into memory instead of streamed (large uploads/responses).
- `setImmediate`/`process.nextTick` recursion starving the event loop.
- Unbounded in-memory caches that grow per request.
- Per-request work that could be hoisted to module init / memoized.

## Stack-specific remedies
- Move heavy/sync work off the request path (worker threads, or precompute at boot); stream large payloads.
- `Promise.all` independent async work; hoist invariant work to module scope.
- Bound caches (LRU with a size limit); avoid per-request allocations that accumulate.

## Stack-specific severity guidance
- Blocking sync I/O/CPU on a hot request path: High (availability).
- Sequential awaits where parallel is trivially correct: Medium.
