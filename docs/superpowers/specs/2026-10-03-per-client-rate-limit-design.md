# Per-client request limiting: `--rateLimit` counts each caller, not the process

**Issue:** #187 (the second half; the first was closed by #188).
**Work happens in:** branch `worktree-issue-187-auth-failure-budget`.
**Release:** minor.

## Problem

#187 named two problems in `src/transport/http.ts`. The first — a wrong bearer
token consumed nothing, so guessing ran at network speed — was fixed by #188 and
released in 2.7.0 as `--authFailureLimit`, which is option A of the issue. The
second is still open: `RateLimiter` is one bucket for the whole process, so one
client spends `--rateLimit` for every other client.

Measured on `main` at `09ecbad` against `build/index.js`,
`--bearerToken=correct-secret`. A 400 means the request passed auth and the
limiter (it carries no session); 401 is a wrong token; 429 is a limiter.

| Run | Flags | Result |
|---|---|---|
| The issue's measurement | `--rateLimit=3` | 12 wrong → `401`×10, `429 429`; then 5 correct → `429`×5 |
| The same with #188 disabled | `--rateLimit=3 --authFailureLimit=0` | 12 wrong → `401`×12; 5 correct → `400 400 400 429 429` |
| Two socket addresses | `--rateLimit=3 --httpHost=::` | A `127.0.0.1` ×4 → `400 400 400 429`; B `::1` ×2 → `429 429` |
| Two clients behind a trusted proxy | `--rateLimit=3 --trustProxy` | A XFF `203.0.113.1` ×4 → `400 400 400 429`; B XFF `203.0.113.2` ×2 → `429 429` |
| Wrong tokens do not drain the request bucket | `--rateLimit=3 --httpHost=::` | A wrong ×12 → `401`×10, `429 429`; B correct ×4 → `400 400 400 429` |
| `/status` is not limited | `--rateLimit=1` | `POST /` ×2 → `400 429`; `GET /status` ×5 → `200`×5 |

The first row is the issue's measurement on today's code: the failure budget now
answers 429 after ten guesses, and the correct token waits with it — the test the
issue asks for already exists (`test/unit/transport/http.test.ts`, "makes a
correct token wait too, once the budget is spent"). The third and fourth rows are
the open problem: client B never sent a request before it was refused.

## Decisions already made, and not reopened here

#188 settled these, and this change reuses them unchanged:

- **Client identity** is `clientKey()`: the socket's remote address, canonicalised
  (`::ffff:` stripped). `X-Forwarded-For` is read only with `--trustProxy`, only
  when the peer is a trusted proxy (loopback for bare `--trustProxy`, otherwise
  `--trustedProxies`), and only its rightmost entry, which must parse as an IP.
- **The failure budget** is independent of `--rateLimit`, on by default at 10 per
  client per minute, checked before the token is compared, charged only on a 401,
  covers every route but `GET /health`, and holds at most `MAX_TRACKED_CLIENTS`
  (1024) clients, evicting the fullest bucket. When every tracked bucket is spent,
  a new key starts empty.
- **`/health`** stays unauthenticated and unlimited.

## Design

### Units

**`consume(bucket, maxTokens)`** — the shared token-bucket step — reports the exact
wait when it refuses. A token comes back `REFILL_INTERVAL_MS / maxTokens` after
`lastRefill`, so the wait is

```
retryAfterMs = max(1000, bucket.lastRefill + REFILL_INTERVAL_MS / maxTokens − now)
```

The floor of one second keeps `Retry-After` from ever reading `0`, which a client
would take as "retry now". The old value, `ceil(60000 / maxTokens)`, is the
interval for one token and therefore an upper bound on this one; once rounded up
to the whole seconds `Retry-After` carries, the new value is never larger. `AuthFailureLimiter.peek()` computes its refusal from the same
expression rather than repeating the refill arithmetic, so the two limiters have
one formula.

**`ClientRateLimiter`** replaces `RateLimiter`: a `Map<string, Bucket>` with
`tryConsume(key)`.

- A key it has not seen starts with a full bucket, then consumes.
- At `MAX_TRACKED_CLIENTS` entries, inserting a new key evicts the fullest bucket.
  The new key starts full **even when every tracked bucket is spent** — unlike the
  failure budget. A request bucket is created only after the token check passes,
  so saturating the table takes 1024 addresses that hold the token, and a token
  holder with many addresses already gets that many times the rate; the refund
  opens nothing new. Starting empty would instead refuse a legitimate client's
  first request because of other people's traffic.
- Choosing the fullest bucket is one helper, used by both `ClientRateLimiter` and
  `AuthFailureLimiter`, so the eviction scan exists once. What each does when the
  fullest is spent stays its own rule.
- The helper ranks buckets by the tokens they hold **after refill**, not by the
  stored count. #188's scan read `b.tokens` as stored, which never changes for a
  key that stops sending, so a failure table that was saturated once stays judged
  saturated forever. Measured on `09ecbad`: saturate 1024 keys, advance the clock
  an hour (every bucket has refilled), and a new key still starts empty — one typo
  and its correct token waits, where an unsaturated table allows it. Because the
  table never has a free slot again, every later arrival takes the same path.
  This is a correction to how #188 measures "spent", not to its rule: a table
  whose buckets really are all spent still starts a new key empty. It is its own
  commit, with its own test.

### Request flow

Every route except `GET /health`, in order:

1. `clientKey()` is resolved when **either** limiter is on. Today it is resolved
   only for the failure budget, so with `--authFailureLimit=0 --rateLimit=60` the
   key would otherwise never be computed. The shared-budget warning fires on the
   same conditions as today, whichever limiter caused the key to be resolved.
2. Failure budget spent → 429, `-32604`, "Too many failed authentication
   attempts…" (unchanged).
3. Token compared; wrong → 401, a failure is charged (unchanged).
4. **Moved:** directly after a successful token check,
   `ClientRateLimiter.tryConsume(key)` charges every authenticated request — `/`
   with any method, `/status`, and authenticated 404s. Refused → 429, `-32604`,
   "Rate limit exceeded. Retry after Ns.", `Retry-After: N`, and now `id: null`,
   which the 401 and the failure 429 already carry and a JSON-RPC error response
   requires.

Unauthenticated traffic still never reaches a request bucket, so the DoS the issue
warned about — moving the request limiter above auth — is not reintroduced.
`--rateLimit=0`, the default, still means no request limiter.

### Messages

- Startup: `Rate limit: N req/min per client`.
- The shared-budget warning names both budgets: behind a proxy without
  `--trustProxy`, every client shares the request budget as well as the
  failed-auth one.

## Documentation

- **README**, both `--rateLimit` rows: "Max authenticated requests per minute, per
  client (0 = unlimited)". The 429 paragraph says the budget is per client, that
  `/status` counts and `/health` does not, and that `Retry-After` is the wait for
  this client's next request. The proxy paragraph says the request budget
  collapses onto the proxy's address without `--trustProxy`, as the failure budget
  does.
- **SECURITY.md:332**: "per-client `--rateLimit` token bucket".
- **`.review-pro/ssh-mcp/backend.md:11` and `security.md:15`** say the limiter
  covers only `/` and not `/status`; both are rewritten to the new scope, so a
  reviewer is not told to flag the change itself. (Content only — the files keep
  their names.)
- The Command Quota section's "the HTTP rate limiter caps request rate" stays: it
  is still true per client, and the paragraph's point (rate is not total work) is
  unchanged.

## Release

**Minor**, by the rule applied since 2.8.0: a client that used to be served can now
be refused. Per-client buckets give most deployments more capacity, not less, but
`/status` and authenticated 404s now spend the budget — a monitor polling
`/status`, or an MCP client plus `/status` traffic above N from one address, now
receives 429 where it received 200. The changeset says so, says that behind a
proxy without `--trustProxy` the budget is still shared, and names the
refill-aware eviction scan as a fix to the failed-auth budget.

## Testing

All in `test/unit/transport/http.test.ts`. A test is accepted only after deleting
or reverting the production line it covers has been measured to make it fail. Time
is asserted with a fake clock (`vi.useFakeTimers({ toFake: ['Date'] })`) and as a
ratio of `60 / N`, never by waiting.

- **Per client, over HTTP.** A server with `--rateLimit=N --trustProxy`; client A
  (XFF `203.0.113.1`) is served exactly N times and then refused; client B (XFF
  `203.0.113.2`) is then served exactly N times. Fails on today's code.
- **`/status` counts.** `--rateLimit=1`: `POST /` served, then `GET /status` → 429.
- **`/health` does not.** Same server, bucket spent: `GET /health` → 200.
- **The key is resolved without the failure budget.** `--authFailureLimit=0
  --rateLimit=N --trustProxy`: two XFF clients still get separate buckets.
- **Exact `Retry-After`**, for both limiters: spend the bucket, advance the fake
  clock by a fraction of `60 / N`, assert the remaining whole seconds; assert the
  floor of 1.
- **`id: null`** in the request 429 body.
- **A once-saturated failure table recovers.** Saturate, advance the fake clock an
  hour, a new key fails once and is still allowed. Fails on today's code.
- **`ClientRateLimiter`** directly: the cap holds at 1024; eviction removes the
  fullest bucket, not the oldest; in a table where every bucket is spent a new key
  is still served; a spent bucket refills on the fake clock.
- **Existing tests.** The issue's required case is already present and is
  re-measured under the deletion check, not duplicated. The global "rate limiting"
  test, which asserts a shape because its bucket was shared with the rest of the
  file, is tightened to exact counts. The shared fullest-bucket helper must leave
  every `AuthFailureLimiter` eviction test passing unchanged.

The full suite, integration included with the Docker test servers up, runs before
the PR, and its result goes in the PR description.

## Out of scope

- Any change to `--authFailureLimit`'s limits, keying or saturation rule (the
  refill-aware scan above corrects how saturation is measured, not the rule).
- More than one trusted proxy hop.
- A process-wide ceiling on top of the per-client buckets.
