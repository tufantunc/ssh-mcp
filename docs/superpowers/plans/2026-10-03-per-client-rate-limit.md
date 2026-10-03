# Per-client request limiting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `--rateLimit` a per-client budget charged on every authenticated request, with an exact `Retry-After`, and make the failed-auth table recover after it was once saturated.

**Architecture:** Everything lives in `src/transport/http.ts`. Shared token-bucket helpers (refill, wait-until-next-token, fullest-bucket scan) serve two limiter classes: the existing `AuthFailureLimiter` and a new `ClientRateLimiter` that replaces the global `RateLimiter`. In the request handler, the request limiter moves from "only `/`" to "directly after a successful token check", keyed by the same `clientKey()` the failure budget uses.

**Tech Stack:** TypeScript (Node `http`), vitest 4 (`vi.useFakeTimers({ toFake: ['Date'] })`), changesets.

**Spec:** `docs/superpowers/specs/2026-10-03-per-client-rate-limit-design.md`. Read it before starting a task. It has the measurements this plan argues from.

## Global Constraints

- Work only in the worktree `/Users/tufantunc/Desktop/Projects/Personal/ssh-mcp/.claude/worktrees/issue-187-auth-failure-budget`.
- Call git as **`/usr/bin/git`**. A user hook rewrites bare `git` into `rtk git`, and the worktree guard refuses that. Keep shell commands plain and separate (no `cd … &&` chains, no `rm -rf` combined with other commands). The guard refuses compound commands it cannot verify.
- `MAX_TRACKED_CLIENTS` stays `1024`. `REFILL_INTERVAL_MS` stays `60_000`. `DEFAULT_AUTH_FAILURE_LIMIT` stays `10`.
- The `Retry-After` header is `Math.ceil(retryAfterMs / 1000)`, and `retryAfterMs` is never below `1000` and never above `REFILL_INTERVAL_MS / maxTokens`. With `maxTokens > 60` those two bounds cross — one token then takes under a second — and the floor wins: the wait reads `1000` and `Retry-After` is `1`, never `0`.
- Both 429s keep HTTP status `429`, JSON-RPC code `-32604`, and their message text: `"Too many failed authentication attempts. Retry after ${s}s."` and `"Rate limit exceeded. Retry after ${s}s."`. The request 429 gains `id: null`.
- `GET /health` stays unauthenticated and is never charged by either limiter.
- **Test policy:** a test is accepted only after the production change it covers has been reverted or deleted, the test has been run and **seen to fail**, and the change has been restored. Each task lists the exact mutation to make. Record the failing output line in your report.
- **Time:** never wait on the wall clock. Use `vi.useFakeTimers({ toFake: ['Date'], now: T0 })` plus `vi.setSystemTime(...)`, always restored with `vi.useRealTimers()` in `finally`. Only `Date` is faked, so the HTTP server's socket I/O keeps running.
- New test servers use ports `18413`–`18418`. Ports `18399`, `18402`–`18412` and `18422` are taken.
- Comments explain *why*, in the style of the surrounding code: full sentences, the measured reason, no restating the code.
- Commit messages: conventional commits, ending with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Commands: `npm run typecheck`, `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts`, `npm run test:unit`.

## Review Focus

Inputs the spec implies that its listed tests do not exercise. Each one has a test in the task named after it.

1. **The clock steps backwards** (NTP correction, VM resume). `lastRefill` is then in the future, and the raw "time until next token" would advertise an hour-long `Retry-After`. Expected: the wait is capped at one token's interval. Test in Task 1.
2. **Rate limit on, failure budget off, behind a proxy without `--trustProxy`.** Today the shared-budget warning is computed only when the failure budget is on, so this deployment would collapse every client onto one request budget silently. Expected: the warning fires. Test in Task 3.
3. **A request refused by the request limiter must not count as a failed auth.** Expected: a client hammering past its request budget with the *correct* token never finds its failed-auth budget spent. Test in Task 3.
4. **A wrong token must not spend the request budget**, now that the request limiter sits right next to the auth check. Expected: unchanged from today. Re-measured with the existing test in Task 3.
5. **`--rateLimit` larger than 60** (one token's interval under a second). Expected: `Retry-After: 1`, never `0`. Test in Task 1 (the floor case).

---

### Task 1: Shared bucket helpers and `ClientRateLimiter`

Adds the helpers both limiters will use and the new per-client request limiter. It is exported and unit-tested, but not yet wired into the server. `consume()` switches to the exact wait here, which the still-wired global `RateLimiter` also picks up. Its HTTP-level check comes in Task 3.

**Files:**
- Modify: `src/transport/http.ts:21-60` (helpers; `consume`; add `ClientRateLimiter` after `RateLimiter`)
- Test: `test/unit/transport/http.test.ts` (new `describe('ClientRateLimiter', …)` appended after `describe('AuthFailureLimiter', …)`)

**Interfaces:**
- Produces (module-private): `tokensEarned(bucket: Bucket, maxTokens: number): number`, `availableTokens(bucket: Bucket, maxTokens: number): number`, `nextTokenWaitMs(bucket: Bucket, maxTokens: number): number`, `fullestBucket(buckets: Map<string, Bucket>, maxTokens: number): { key: string; available: number } | undefined`.
- Produces (exported): `class ClientRateLimiter { constructor(maxTokens: number); tryConsume(key: string): { allowed: boolean; retryAfterMs: number } }`, with private `buckets: Map<string, Bucket>` (tests read it via `as any`, as the `AuthFailureLimiter` tests already do).

- [ ] **Step 1: Write the failing tests**

Append to `test/unit/transport/http.test.ts`, directly after the closing `});` of `describe('AuthFailureLimiter', …)`:

```ts
describe('ClientRateLimiter', () => {
  const T0 = 1_800_000_000_000;

  it('gives each client its own budget', async () => {
    const { ClientRateLimiter } = await import('../../../src/transport/http.js');
    const limiter = new ClientRateLimiter(2);
    expect(limiter.tryConsume('a').allowed).toBe(true);
    expect(limiter.tryConsume('a').allowed).toBe(true);
    expect(limiter.tryConsume('a').allowed).toBe(false);
    // The point of #187: one client spending its budget leaves another's whole.
    expect(limiter.tryConsume('b').allowed).toBe(true);
    expect(limiter.tryConsume('b').allowed).toBe(true);
  });

  it('keeps the tracked-client map bounded', async () => {
    const { ClientRateLimiter, MAX_TRACKED_CLIENTS } = await import('../../../src/transport/http.js');
    const limiter = new ClientRateLimiter(5) as any;
    for (let i = 0; i < MAX_TRACKED_CLIENTS + 50; i++) limiter.tryConsume(`10.0.${i >> 8}.${i & 255}`);
    expect(limiter.buckets.size).toBe(MAX_TRACKED_CLIENTS);
  });

  it('evicts the fullest bucket, not the oldest', async () => {
    const { ClientRateLimiter, MAX_TRACKED_CLIENTS } = await import('../../../src/transport/http.js');
    const limiter = new ClientRateLimiter(3) as any;
    // The oldest entry is the spent one. Evicting by age would hand it a fresh budget.
    for (let n = 0; n < 3; n++) limiter.tryConsume('spent');
    for (let i = 0; i < MAX_TRACKED_CLIENTS - 2; i++) {
      limiter.tryConsume(`filler-${i}`);
      limiter.tryConsume(`filler-${i}`);
    }
    limiter.tryConsume('idle'); // 2 of 3 left: the fullest in the table
    expect(limiter.buckets.size).toBe(MAX_TRACKED_CLIENTS);

    limiter.tryConsume('arriving');
    expect(limiter.buckets.has('idle')).toBe(false);
    expect(limiter.buckets.has('spent')).toBe(true);
    expect(limiter.tryConsume('spent').allowed).toBe(false);
  });

  it('serves an arriving client even when every tracked bucket is spent', async () => {
    const { ClientRateLimiter, MAX_TRACKED_CLIENTS } = await import('../../../src/transport/http.js');
    const limiter = new ClientRateLimiter(1);
    for (let i = 0; i < MAX_TRACKED_CLIENTS; i++) limiter.tryConsume(`holder-${i}`);
    // Unlike the failure budget: a request bucket exists only past the token check, so a
    // saturated table is 1024 token holders, and refusing a newcomer's first request
    // would punish it for their traffic.
    expect(limiter.tryConsume('arriving').allowed).toBe(true);
  });

  it('refills on the clock and re-arms afterwards', async () => {
    const { ClientRateLimiter } = await import('../../../src/transport/http.js');
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      const limiter = new ClientRateLimiter(2);
      limiter.tryConsume('a');
      limiter.tryConsume('a');
      expect(limiter.tryConsume('a').allowed).toBe(false);
      vi.setSystemTime(T0 + 60_000 / 2); // one token's interval
      expect(limiter.tryConsume('a').allowed).toBe(true);
      expect(limiter.tryConsume('a').allowed).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('reports the wait until this client\'s next token, not a whole interval', async () => {
    const { ClientRateLimiter } = await import('../../../src/transport/http.js');
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      const limiter = new ClientRateLimiter(3); // one token per 20s
      for (let n = 0; n < 3; n++) limiter.tryConsume('a');
      vi.setSystemTime(T0 + 7_500);
      expect(limiter.tryConsume('a')).toEqual({ allowed: false, retryAfterMs: 12_500 });
    } finally {
      vi.useRealTimers();
    }
  });

  it('never reports a wait under a second', async () => {
    const { ClientRateLimiter } = await import('../../../src/transport/http.js');
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      const limiter = new ClientRateLimiter(120); // one token per 500ms
      for (let n = 0; n < 120; n++) limiter.tryConsume('a');
      vi.setSystemTime(T0 + 499);
      // 1ms remains. Retry-After is whole seconds, and 0 would read as "retry now".
      expect(limiter.tryConsume('a')).toEqual({ allowed: false, retryAfterMs: 1_000 });
    } finally {
      vi.useRealTimers();
    }
  });

  it('caps the wait at one token\'s interval when the clock steps back', async () => {
    const { ClientRateLimiter } = await import('../../../src/transport/http.js');
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      const limiter = new ClientRateLimiter(3);
      for (let n = 0; n < 3; n++) limiter.tryConsume('a');
      vi.setSystemTime(T0 - 3_600_000);
      // lastRefill is now an hour in the future; the raw difference would say 3620s.
      expect(limiter.tryConsume('a')).toEqual({ allowed: false, retryAfterMs: 20_000 });
    } finally {
      vi.useRealTimers();
    }
  });
});
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts -t ClientRateLimiter`
Expected: all 8 FAIL with `ClientRateLimiter is not a constructor` (the export does not exist).

- [ ] **Step 3: Implement**

In `src/transport/http.ts`, replace the whole `consume` function (currently lines 28-48) with:

```ts
/** Whole tokens earned since `lastRefill`. Negative when the clock stepped back; callers clamp. */
function tokensEarned(bucket: Bucket, maxTokens: number): number {
  return Math.floor(((Date.now() - bucket.lastRefill) / REFILL_INTERVAL_MS) * maxTokens);
}

/** Tokens the bucket would hold if refilled now, without changing it. */
function availableTokens(bucket: Bucket, maxTokens: number): number {
  return Math.min(maxTokens, bucket.tokens + Math.max(tokensEarned(bucket, maxTokens), 0));
}

/**
 * How long until this bucket earns its next token, for `Retry-After`.
 *
 * Exact, where it used to be the fixed `REFILL_INTERVAL_MS / maxTokens`. That is how long
 * one token takes, so a client refused halfway through the interval was told to wait
 * twice as long as it had to. Bounded on both sides: below at a second, because
 * `Retry-After` is whole seconds and `0` reads as "retry now"; above at one token's
 * interval, because a clock that stepped backwards puts `lastRefill` in the future, and
 * the raw difference would then advertise an arbitrarily long wait.
 */
function nextTokenWaitMs(bucket: Bucket, maxTokens: number): number {
  const interval = REFILL_INTERVAL_MS / maxTokens;
  return Math.max(1000, Math.min(interval, bucket.lastRefill + interval - Date.now()));
}

/**
 * The tracked key whose bucket holds the most tokens *after refill*: the entry with the
 * least worth remembering, so the one to evict.
 *
 * Refilled, not stored. A key that stops sending keeps its stored count forever, so
 * ranking by `tokens` treated a bucket spent an hour ago as still spent. A table that
 * was saturated once was then judged saturated for good, which was measured.
 */
function fullestBucket(
  buckets: Map<string, Bucket>,
  maxTokens: number,
): { key: string; available: number } | undefined {
  let fullest: { key: string; available: number } | undefined;
  for (const [key, bucket] of buckets) {
    const available = availableTokens(bucket, maxTokens);
    if (fullest === undefined || available > fullest.available) fullest = { key, available };
    if (available === maxTokens) break;
  }
  return fullest;
}

/**
 * One token-bucket step, shared by the two limiters so the refill arithmetic exists once.
 *
 * Mutates the bucket. Refills proportionally to elapsed time rather than on a timer, so an
 * idle server costs nothing and there is no interval to clean up.
 */
function consume(bucket: Bucket, maxTokens: number): { allowed: boolean; retryAfterMs: number } {
  const refilled = tokensEarned(bucket, maxTokens);
  if (refilled > 0) {
    bucket.tokens = Math.min(maxTokens, bucket.tokens + refilled);
    bucket.lastRefill += Math.round((refilled / maxTokens) * REFILL_INTERVAL_MS);
  }

  if (bucket.tokens > 0) {
    bucket.tokens--;
    return { allowed: true, retryAfterMs: 0 };
  }

  return { allowed: false, retryAfterMs: nextTokenWaitMs(bucket, maxTokens) };
}
```

Then, directly after the closing `}` of `class RateLimiter` (leave `RateLimiter` in place; Task 3 removes it), add:

```ts
/**
 * A request bucket per client, so `--rateLimit` means N requests per minute *per caller*.
 *
 * It was one bucket for the process: one client spent `--rateLimit` for every other, and
 * a client that had sent nothing was refused (#187, measured). Keyed by `clientKey()`,
 * the same key the failure budget uses, and charged only after the token check passes,
 * so unauthenticated traffic cannot create entries or drain anyone's budget.
 *
 * Bounded like `AuthFailureLimiter`, and it evicts the fullest bucket for the same reason.
 * Where it differs: an arriving key always starts full, even when every tracked bucket is
 * spent. Saturating this table takes 1024 addresses that hold the token, and a token
 * holder with that many addresses already has that many budgets. The refund opens nothing
 * new, while starting empty would refuse a legitimate client's first request because of
 * other clients' traffic.
 */
export class ClientRateLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(private maxTokens: number) {}

  tryConsume(key: string): { allowed: boolean; retryAfterMs: number } {
    let bucket = this.buckets.get(key);
    if (bucket === undefined) {
      if (this.buckets.size >= MAX_TRACKED_CLIENTS) {
        const fullest = fullestBucket(this.buckets, this.maxTokens);
        if (fullest !== undefined) this.buckets.delete(fullest.key);
      }
      bucket = { tokens: this.maxTokens, lastRefill: Date.now() };
      this.buckets.set(key, bucket);
    }
    return consume(bucket, this.maxTokens);
  }
}
```

`availableTokens` and `nextTokenWaitMs` are also used by `AuthFailureLimiter` in Task 2. Every helper already has a caller in this task, so no unused-symbol suppression is needed.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts`
Expected: the whole file passes, including the 8 new tests. `"says how long to wait"` (expects 20 for a fresh spend at limit 3) still passes, because `AuthFailureLimiter.peek` has not changed yet.

- [ ] **Step 5: Deletion check, one mutation at a time.** Make each change, run the command from Step 4, confirm the named test fails, then revert it.

| Mutation in `src/transport/http.ts` | Test that must fail |
|---|---|
| In `tryConsume`, use `this.buckets.get('')`/`set('', …)` instead of `key` (a single global bucket) | `gives each client its own budget` |
| Delete the `if (this.buckets.size >= MAX_TRACKED_CLIENTS) { … }` block in `tryConsume` | `keeps the tracked-client map bounded` |
| In `fullestBucket`, return the first entry: replace the loop body with `return { key, available: availableTokens(bucket, maxTokens) };` | `evicts the fullest bucket, not the oldest` |
| In `tryConsume`, start the new bucket with `tokens: fullest !== undefined && fullest.available <= 0 ? 0 : this.maxTokens` (keep `fullest` in scope) | `serves an arriving client even when every tracked bucket is spent` |
| In `consume`, change `if (refilled > 0)` to `if (refilled > 1_000_000)` | `refills on the clock and re-arms afterwards` |
| In `consume`, return `retryAfterMs: Math.ceil(REFILL_INTERVAL_MS / maxTokens)` | `reports the wait until this client's next token…` |
| In `nextTokenWaitMs`, drop `Math.max(1000, …)` | `never reports a wait under a second` |
| In `nextTokenWaitMs`, drop `Math.min(interval, …)` | `caps the wait at one token's interval when the clock steps back` |

- [ ] **Step 6: Typecheck and commit**

Run: `npm run typecheck` → expected: no errors.

```bash
/usr/bin/git add src/transport/http.ts test/unit/transport/http.test.ts
/usr/bin/git commit -m "feat(http): add a per-client request limiter and exact Retry-After

ClientRateLimiter keeps a token bucket per client key, bounded at
MAX_TRACKED_CLIENTS with fullest-first eviction, and starts an arriving key
full even when the table is saturated. Not wired in yet.

consume() now reports the wait until the bucket's next token, floored at a
second and capped at one token's interval, instead of the fixed interval.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `AuthFailureLimiter` on the shared helpers

Two commits. First, `peek()` reports the exact wait. Second, eviction ranks by refilled tokens, which fixes the permanent-saturation defect the spec measured.

**Files:**
- Modify: `src/transport/http.ts` (`AuthFailureLimiter.peek`, `AuthFailureLimiter.recordFailure`)
- Test: `test/unit/transport/http.test.ts` (inside `describe('AuthFailureLimiter', …)`)

**Interfaces:**
- Consumes: `availableTokens`, `nextTokenWaitMs`, `fullestBucket` from Task 1.
- Produces: no new names. `AuthFailureLimiter`'s public signatures are unchanged.

- [ ] **Step 1: Write the failing test for the exact wait**

Add inside `describe('AuthFailureLimiter', …)`, after its last `it`:

```ts
  it('reports the wait until the next attempt, not a whole interval', async () => {
    const { AuthFailureLimiter } = await import('../../../src/transport/http.js');
    const T0 = 1_800_000_000_000;
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      const limiter = new AuthFailureLimiter(3); // one attempt back every 20s
      for (let n = 0; n < 3; n++) limiter.recordFailure('a');
      vi.setSystemTime(T0 + 7_500);
      expect(limiter.peek('a')).toEqual({ allowed: false, retryAfterMs: 12_500 });
    } finally {
      vi.useRealTimers();
    }
  });
```

- [ ] **Step 2: Run and verify it fails**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts -t "reports the wait until the next attempt"`
Expected: FAIL, `retryAfterMs: 20000` received where `12500` was expected.

- [ ] **Step 3: Implement**

Replace the body of `peek` in `AuthFailureLimiter` with:

```ts
  peek(key: string): { allowed: boolean; retryAfterMs: number } {
    const bucket = this.buckets.get(key);
    if (bucket === undefined) return { allowed: true, retryAfterMs: 0 };
    if (availableTokens(bucket, this.maxTokens) > 0) return { allowed: true, retryAfterMs: 0 };
    return { allowed: false, retryAfterMs: nextTokenWaitMs(bucket, this.maxTokens) };
  }
```

Keep its doc comment (`/** Whether this client may make another attempt. Does not consume. */`).

- [ ] **Step 4: Run the file and verify it passes**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts`
Expected: all pass. `"says how long to wait"` still gets `Math.ceil(60 / 3) = 20`, because there a spend at time t is checked at time t, so the full interval remains.

- [ ] **Step 5: Deletion check**

Mutation: in `peek`, return `retryAfterMs: Math.ceil(REFILL_INTERVAL_MS / this.maxTokens)`. The test from Step 1 must fail. Revert.

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add src/transport/http.ts test/unit/transport/http.test.ts
/usr/bin/git commit -m "fix(http): tell a throttled client its exact wait after failed auth

AuthFailureLimiter.peek now uses the shared refill and wait helpers, so its
Retry-After is the time until this client's next attempt rather than a full
token interval.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Write the failing test for the saturated table**

Add inside `describe('AuthFailureLimiter', …)`, after the test from Step 1:

```ts
  it('recovers once a saturated table has refilled', async () => {
    const { AuthFailureLimiter, MAX_TRACKED_CLIENTS } = await import('../../../src/transport/http.js');
    const T0 = 1_800_000_000_000;
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      const limiter = new AuthFailureLimiter(10);
      for (let i = 0; i < MAX_TRACKED_CLIENTS; i++) {
        for (let n = 0; n < 10; n++) limiter.recordFailure(`atk-${i}`);
      }
      // An hour later every one of those buckets is full again. The scan used to read the
      // stored count, which never changes for a key that stops sending, so the table
      // stayed "saturated" for good: every new client started empty, and one typo made
      // its correct token wait. Measured on 09ecbad.
      vi.setSystemTime(T0 + 3_600_000);
      limiter.recordFailure('arriving');
      expect(limiter.peek('arriving').allowed).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
```

- [ ] **Step 8: Run and verify it fails**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts -t "recovers once a saturated table"`
Expected: FAIL, `expected false to be true`.

- [ ] **Step 9: Implement**

In `AuthFailureLimiter.recordFailure`, replace the block from `// Evict the *fullest* entry, not the oldest.` up to and including `if (fullest <= 0) bucket = { tokens: 0, lastRefill: Date.now() };` with the version below. The two existing comment paragraphs are kept verbatim; only the code lines change.

```ts
        // Evict the *fullest* entry, not the oldest. An exhausted bucket has the oldest
        // `lastRefill` by construction, so evicting by age evicted the locked-out client
        // first and then handed its key a fresh budget: minting enough keys cleared a
        // lockout, which was measured end to end. A full bucket is the one with nothing
        // worth remembering.
        const fullest = fullestBucket(this.buckets, this.maxTokens);
        if (fullest !== undefined) this.buckets.delete(fullest.key);
        // Every tracked client is spent, so the table itself is the signal and a new key
        // does not get a full budget.
        //
        // The cost, stated because it is real and cannot be softened here: while the table
        // is saturated an arriving client has one attempt rather than the full budget, so
        // a first typo leaves its correct token waiting. Seeding one token instead of zero
        // looks like it would help and does not — `consume` spends it immediately, and
        // `peek` already allows a key it has never seen, so the first attempt is free
        // either way and the second is refused either way. Measured both, identical.
        // Giving an arriving key a real budget is the refund this rule exists to stop.
        // Saturation needs 1024 addresses that have each spent a full budget *recently*:
        // `fullestBucket` ranks by refilled tokens, so the condition ends once they refill.
        if (fullest === undefined || fullest.available <= 0) bucket = { tokens: 0, lastRefill: Date.now() };
```

- [ ] **Step 10: Run the file and verify it passes**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts`
Expected: all pass. The three existing `AuthFailureLimiter` tests (`keeps the tracked-client map bounded`, `gives an arriving client one attempt while every bucket is spent`, `does not refund a spent budget when the map is recycled`) must pass **unchanged**. Do not edit them.

- [ ] **Step 11: Deletion check**

Mutation: in `fullestBucket`, replace `availableTokens(bucket, maxTokens)` with `bucket.tokens`. `recovers once a saturated table has refilled` must fail. Revert. (`evicts the fullest bucket, not the oldest` from Task 1 may still pass under this mutation; that is expected.)

- [ ] **Step 12: Typecheck and commit**

Run: `npm run typecheck` → no errors.

```bash
/usr/bin/git add src/transport/http.ts test/unit/transport/http.test.ts
/usr/bin/git commit -m "fix(http): let a once-saturated failed-auth table recover

The eviction scan ranked buckets by their stored token count, which never
changes for a key that stops sending. After 1024 addresses had each spent a
budget, the table stayed judged saturated for good: every new client started
empty, and one typo made its correct token wait. The shared fullestBucket
ranks by refilled tokens, so the condition ends once those buckets refill.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Wire the per-client limiter into the request flow

**Files:**
- Modify: `src/transport/http.ts`: delete `class RateLimiter`; `startHttpServer` (the limiter construction, the shared-budget warning text, the client-key block, the old request-limiter block at `if (rateLimiter && url.pathname === '/' …)`, the startup log line)
- Test: `test/unit/transport/http.test.ts`: the main server's options (line ~42), the old `describe('HTTP transport — rate limiting', …)` block (line ~189), a new `postRequest` helper next to `bareRequest`, and a new `describe` block at the end of the file

**Interfaces:**
- Consumes: `ClientRateLimiter` (Task 1), `clientKey` (existing).
- Produces: no new exports.

- [ ] **Step 1: Write the failing tests**

(a) Add this helper directly after the `bareRequest` function:

```ts
function postRequest(
  port: number,
  headers: Record<string, string> = {},
  path = '/',
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpModule.request(
      {
        hostname: HTTP_HOST, port, path, method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        agent: false as const,
      },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode || 0, headers: res.headers, body }));
      },
    );
    req.on('error', reject);
    req.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }));
  });
}
```

(b) Append at the end of the file:

```ts
/**
 * #187's second half: the request limiter was one bucket for the process, so client B was
 * refused before it had sent anything (measured: A `400 400 400 429`, then B `429 429`).
 * Two clients are told apart through a trusted loopback proxy, for the reason the
 * `clientKey` block above gives: two real source addresses are platform-dependent.
 */
describe('HTTP transport — the request budget is per client', () => {
  const PORT = 18413;
  const LIMIT = 2;
  const auth = { authorization: `Bearer ${BEARER}` };
  const from = (xff: string) => ({ ...auth, 'x-forwarded-for': xff });

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: PORT, host: HTTP_HOST, bearerToken: BEARER,
      rateLimit: LIMIT, trustProxy: true, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  it('a client that spends its budget leaves another client\'s whole', async () => {
    const a: number[] = [];
    for (let i = 0; i < LIMIT + 1; i++) a.push((await postRequest(PORT, from('203.0.113.1'))).status);
    expect(a.slice(0, LIMIT).every((s) => s !== 429)).toBe(true);
    expect(a[LIMIT]).toBe(429);

    const b: number[] = [];
    for (let i = 0; i < LIMIT + 1; i++) b.push((await postRequest(PORT, from('203.0.113.2'))).status);
    expect(b.slice(0, LIMIT).every((s) => s !== 429)).toBe(true);
    expect(b[LIMIT]).toBe(429);
  });

  it('charges /status and an authenticated 404, and says so in a JSON-RPC envelope', async () => {
    // /status was unlimited: a token holder could poll it without bound.
    expect((await bareRequest(PORT, '/status', from('198.51.100.1'))).status).toBe(200);
    expect((await bareRequest(PORT, '/status', from('198.51.100.1'))).status).toBe(200);
    const refused = await bareRequest(PORT, '/status', from('198.51.100.1'));
    expect(refused.status).toBe(429);
    const parsed = JSON.parse(refused.body);
    expect(parsed).toEqual({
      jsonrpc: '2.0',
      error: { code: -32604, message: expect.stringMatching(/^Rate limit exceeded\. Retry after \d+s\.$/) },
      id: null,
    });

    expect((await bareRequest(PORT, '/nope', from('198.51.100.2'))).status).toBe(404);
    expect((await bareRequest(PORT, '/nope', from('198.51.100.2'))).status).toBe(404);
    expect((await postRequest(PORT, from('198.51.100.2'))).status).toBe(429);
  });

  it('never charges or refuses the liveness probe', async () => {
    for (let i = 0; i < LIMIT; i++) await postRequest(PORT, from('198.51.100.3'));
    expect((await postRequest(PORT, from('198.51.100.3'))).status).toBe(429);
    // Same address, budget spent, no token: /health answers.
    expect((await bareRequest(PORT, '/health', { 'x-forwarded-for': '198.51.100.3' })).status).toBe(200);
  });
});

describe('HTTP transport — the request budget without the failure budget', () => {
  it('still tells clients apart with --authFailureLimit=0', async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    const port = 18414;
    await startHttpServer(() => mcpServer, {
      port, host: HTTP_HOST, bearerToken: BEARER,
      rateLimit: 1, authFailureLimit: 0, trustProxy: true, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));

    // The client key used to be resolved only for the failure budget, so with it off
    // every request was charged to one key.
    const auth = { authorization: `Bearer ${BEARER}` };
    expect((await postRequest(port, { ...auth, 'x-forwarded-for': '203.0.113.1' })).status).not.toBe(429);
    expect((await postRequest(port, { ...auth, 'x-forwarded-for': '203.0.113.1' })).status).toBe(429);
    expect((await postRequest(port, { ...auth, 'x-forwarded-for': '203.0.113.2' })).status).not.toBe(429);
  });

  it('warns that clients share a budget behind an untrusted proxy', async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    const port = 18415;
    await startHttpServer(() => mcpServer, {
      port, host: HTTP_HOST, bearerToken: BEARER,
      rateLimit: 5, authFailureLimit: 0, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));

    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      await postRequest(port, { authorization: `Bearer ${BEARER}`, 'x-forwarded-for': '203.0.113.9' });
      const warnings = spy.mock.calls.map((c) => String(c[0])).filter((m) => m.includes('X-Forwarded-For'));
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/request budget/);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('HTTP transport — the two budgets stay separate', () => {
  it('a request-limit 429 does not count as a failed authentication', async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    const port = 18416;
    await startHttpServer(() => mcpServer, {
      port, host: HTTP_HOST, bearerToken: BEARER,
      rateLimit: 1, authFailureLimit: 1, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));

    const auth = { authorization: `Bearer ${BEARER}` };
    expect((await postRequest(port, auth)).status).not.toBe(429);
    for (let i = 0; i < 3; i++) expect((await postRequest(port, auth)).status).toBe(429);
    // The failure budget of 1 is still whole: a wrong token is evaluated and answered 401.
    expect((await postRequest(port, { authorization: 'Bearer wrong' })).status).toBe(401);
  });
});

describe('HTTP transport — the request 429 carries the exact wait', () => {
  it('Retry-After counts down within a token\'s interval', async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    const port = 18417;
    await startHttpServer(() => mcpServer, {
      port, host: HTTP_HOST, bearerToken: BEARER,
      rateLimit: 3, authFailureLimit: 0, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));

    const T0 = 1_800_000_000_000;
    const auth = { authorization: `Bearer ${BEARER}` };
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      // The bucket is created by the first request, so under the fake clock.
      for (let i = 0; i < 3; i++) await postRequest(port, auth);
      vi.setSystemTime(T0 + 7_500);
      const res = await postRequest(port, auth);
      expect(res.status).toBe(429);
      // 20s per token at 3/min, 7.5s gone: 12.5s left, rounded up. The fixed value was 20.
      expect(res.headers['retry-after']).toBe('13');
    } finally {
      vi.useRealTimers();
    }
  });
});
```

(c) In `startTestServer` (top of the file), change `rateLimit: 3,` to `rateLimit: 0,` and put this comment directly above it:

```ts
        // Off on this server, for the reason the failure budget is: every request in this
        // file comes from 127.0.0.1, and `/status`, 404s and the auth cases now spend the
        // request budget too, so a shared limit would couple unrelated tests. The limiter
        // is measured on its own servers below.
```

(d) Delete the whole `describe('HTTP transport — rate limiting', …)` block (the one whose test is `'returns 429 after exceeding rate limit on MCP route'`). Its only assertion was a shape, because its bucket was shared with the rest of the file. `describe('HTTP transport — the request limiter admits exactly its limit', …)` already asserts the exact boundary on a fresh server.

- [ ] **Step 2: Run and verify the new tests fail**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts`
Expected failures (each for its stated reason):
- `a client that spends its budget leaves another client's whole`: B's first request gets 429.
- `charges /status and an authenticated 404…`: the third `/status` is 200.
- `still tells clients apart with --authFailureLimit=0`: the third request gets 429.
- `warns that clients share a budget behind an untrusted proxy`: 0 warnings.
These may pass already, and that is expected; each one's deletion check in Step 5 is what accepts it:
- `never charges or refuses the liveness probe`: the global bucket already answers 429 there.
- `a request-limit 429 does not count as a failed authentication`: true of today's code. It guards Review Focus 3 against a regression.
- `Retry-After counts down within a token's interval`: its pre-change result means nothing. The global bucket was created at server start, before the fake clock, and `consume()` already became exact in Task 1. Record the result, but don't read it as evidence either way.

- [ ] **Step 3: Implement**

In `src/transport/http.ts`:

1. Delete `class RateLimiter { … }` entirely.

2. In `startHttpServer`, replace

```ts
  const rateLimiter = opts.rateLimit && opts.rateLimit > 0
    ? new RateLimiter(opts.rateLimit)
    : null;
```

with

```ts
  const rateLimiter = opts.rateLimit && opts.rateLimit > 0
    ? new ClientRateLimiter(opts.rateLimit)
    : null;
```

3. Replace the `console.error(…)` text inside `warnSharedBudget` with:

```ts
    console.error(
      'POLICY WARNING: X-Forwarded-For is present but not being used to tell clients ' +
      'apart, so every client is charged to one key: one failed-auth budget and one ' +
      'request budget between them, for whichever of the two is on, and one client can ' +
      'lock out or starve the rest. Either --trustProxy is off, or the peer is not a ' +
      'trusted proxy (bare --trustProxy trusts a loopback peer; name others with ' +
      '--trustedProxies), or the rightmost entry is not an address this server can read.',
    );
```

Update the comment above `let warnedSharedBudget` from "every client is keyed on the proxy's socket address and so shares one budget — which means ten failures from anyone locks out everyone" to "every client is keyed on the proxy's socket address and so shares one failure budget and one request budget — ten failures from anyone locks out everyone, and one busy client starves the rest". Leave the rest of that comment as it is.

4. Change the client-key block's guard from `if (authFailureLimiter) {` (the first of the two consecutive `if (authFailureLimiter)` blocks, the one that calls `clientKey`) to:

```ts
      if (authFailureLimiter || rateLimiter) {
```

and add one line to its comment, after "…had no way to know it was not taking effect.":

```ts
        // Resolved for either limiter: with only `--rateLimit` on, skipping this charged
        // every client to one key and kept the warning silent.
```

5. Directly after the closing `}` of the `if (!match) { … }` block (still inside `if (!isHealthProbe) { … }`), insert:

```ts

      // Charged after the token check, never before: a request bucket is per client, but
      // unauthenticated traffic reaching it could still spend a victim's budget under a
      // spoofable key, and its 429 would answer a guess without evaluating it. Every
      // authenticated route spends from it, `/status` and 404s included: `/status` was
      // unlimited, so a token holder could poll it without bound.
      if (rateLimiter) {
        const { allowed, retryAfterMs } = rateLimiter.tryConsume(key);
        if (!allowed) {
          const retryAfterSec = Math.ceil(retryAfterMs / 1000);
          res.writeHead(429, {
            'Content-Type': 'application/json',
            'Retry-After': String(retryAfterSec),
          });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32604,
              message: `Rate limit exceeded. Retry after ${retryAfterSec}s.`,
            },
            id: null,
          }));
          return;
        }
      }
```

6. Delete the old block that starts `if (rateLimiter && url.pathname === '/' && (req.method === 'POST' || req.method === 'GET' || req.method === 'DELETE')) {` through its closing `}`.

7. In the `listen` callback, change `console.error(\`Rate limit: ${opts.rateLimit} req/min\`);` to `console.error(\`Rate limit: ${opts.rateLimit} req/min per client\`);`.

8. Update the JSDoc for `rateLimit` in `HttpTransportOpts` (currently there is none; add one above `rateLimit?: number;`):

```ts
  /**
   * Authenticated requests allowed per client per minute, on every route but
   * `GET /health`. 0 or unset disables the limit. Clients are keyed as for
   * `authFailureLimit`.
   */
```

- [ ] **Step 4: Run and verify it passes**

Run: `npx cross-env SSH_MCP_DISABLE_MAIN=1 vitest --run test/unit/transport/http.test.ts`
Expected: the whole file passes. In particular, the existing `a failed attempt never touches the global request budget` (port 18412: 2 wrong, then 3 correct `/status` → `[200, 200, 200]`) still passes. It now exercises `/status` against the request limiter, which makes it a real check where before it passed vacuously. Rename its title to `'a failed attempt never touches the request budget'` and change "global request budget" to "request budget" in its comment's first sentence. That is the only edit to it.

- [ ] **Step 5: Deletion check, one at a time** (run Step 4's command each time; revert after)

| Mutation in `src/transport/http.ts` | Test that must fail |
|---|---|
| `rateLimiter.tryConsume('')` instead of `tryConsume(key)` | `a client that spends its budget leaves another client's whole` |
| Wrap the new limiter block's body in `if (url.pathname === '/') { … }` | `charges /status and an authenticated 404…` |
| Remove `id: null,` from the request 429 | `charges /status and an authenticated 404…` |
| Move the new `if (rateLimiter) { … }` block to just before `if (!isHealthProbe) {` (using `clientKey(...)` inline for the key) | `never charges or refuses the liveness probe` |
| Revert the guard to `if (authFailureLimiter) {` | `still tells clients apart with --authFailureLimit=0` **and** `warns that clients share a budget…` |
| Revert the warning text to the old one | `warns that clients share a budget…` |
| Add `authFailureLimiter?.recordFailure(key);` before the request 429's `res.writeHead` | `a request-limit 429 does not count as a failed authentication` |
| Move the new limiter block to just before `const auth = req.headers.authorization` | `a failed attempt never touches the request budget` (Review Focus 4) |
| In `nextTokenWaitMs`, return `REFILL_INTERVAL_MS / maxTokens` | `Retry-After counts down within a token's interval` |
| In `AuthFailureLimiter.peek` / the auth gate, delete the `if (!allowed) { … return; }` of the failure budget | `makes a correct token wait too, once the budget is spent` (the issue's required test, existing) |

- [ ] **Step 6: Full unit suite, typecheck, commit**

Run: `npm run typecheck` → no errors.
Run: `npm run test:unit` → all pass (the baseline before this branch was 1668 passed, 17 skipped).

```bash
/usr/bin/git add src/transport/http.ts test/unit/transport/http.test.ts
/usr/bin/git commit -m "feat(http): count --rateLimit per client, on every authenticated request

The request limiter was one bucket for the process: with --rateLimit=3, client A
was served three times and client B was refused before it had sent anything,
directly and behind a trusted proxy (#187). It is now a bucket per client,
keyed as the failed-auth budget is, and charged directly after the token
check, so unauthenticated traffic still cannot reach it.

Every authenticated route spends from it, /status and 404s included; /health
does not. The request 429 carries id: null, and the client key is resolved
when either limiter is on, so the shared-budget warning fires for a
rate-limit-only deployment behind an untrusted proxy too.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(No `!` in the subject: the release is minor, and the changeset in Task 4 sets the level.)

---

### Task 4: Documentation, review criteria and changeset

**Files:**
- Modify: `README.md` (line ~767 table row; line ~780 paragraph; line ~788 proxy sentence; line ~849 table row)
- Modify: `SECURITY.md:332`
- Modify: `.review-pro/ssh-mcp/backend.md:11`, `.review-pro/ssh-mcp/security.md:15`, `.review-pro/ssh-mcp/security.md:30` (content only; do not rename these files)
- Create: `.changeset/per-client-rate-limit.md`

**Interfaces:** none.

- [ ] **Step 1: README**

Replace the row
`| \`--rateLimit\` | 0 (off) | Max requests per minute (0 = unlimited) |`
with
`| \`--rateLimit\` | 0 (off) | Max authenticated requests per minute, per client (0 = unlimited) |`

Replace the row
`| \`--rateLimit\` | 0 | HTTP requests per minute on the MCP route (0 = unlimited) |`
with
`| \`--rateLimit\` | 0 | Max authenticated requests per minute, per client (0 = unlimited) |`

Replace the paragraph
`When rate limit is exceeded, the server returns HTTP 429 with \`Retry-After\` header and a JSON-RPC error body so MCP clients can handle it gracefully.`
with

```markdown
`--rateLimit` is a budget per client, keyed the same way as the failed-auth budget below,
and every authenticated request spends from it: `POST /` and the rest of the MCP route,
`GET /status`, and an authenticated request to a path that does not exist. `GET /health`
never does. A wrong token never does either, so unauthenticated traffic cannot spend a
working client's budget. When a client's budget is spent the server returns HTTP 429 with
a JSON-RPC error body, and `Retry-After` gives the seconds until that client's next request
will be accepted.
```

In the failed-auth paragraph that follows, replace
`Clients are told apart by socket address. **Behind a\nreverse proxy that means every client shares one budget**, so set \`--trustProxy\` when the\nproxy is yours`
(the line breaks in the file may differ; match on the words) with
`Clients are told apart by socket address, for this budget and for \`--rateLimit\` alike. **Behind a\nreverse proxy that means every client shares one of each**, so set \`--trustProxy\` when the\nproxy is yours`.

- [ ] **Step 2: SECURITY.md**

On line 332, replace `` `--rateLimit` token bucket `` with `` per-client `--rateLimit` token bucket ``.

- [ ] **Step 3: `.review-pro` criteria**

`.review-pro/ssh-mcp/backend.md`, replace the line starting `- **Rate limiter scope**` with:

```markdown
- **Rate limiter scope** — a token bucket per client (`clientKey()`), charged after the bearer check on every authenticated route, `/status` and 404s included. Only `GET /health` is exempt. Verify a new route does not bypass it and that unauthenticated traffic never reaches it.
```

`.review-pro/ssh-mcp/security.md`, replace the line starting `- **HTTP rate limiting bypass**` with:

```markdown
- **HTTP rate limiting bypass** — the request limiter is per client and charged after auth on every route but `GET /health`; the failed-auth budget is checked before the token is compared. Verify neither is skipped by a new route, and that the client key is never read from `X-Forwarded-For` unless the peer is a trusted proxy.
```

and in the same file, check that the line `- Rate limiter: token-bucket per client, 429 + Retry-After, body cap 1MB.` is still accurate (it now is). Leave it.

- [ ] **Step 4: Changeset**

Create `.changeset/per-client-rate-limit.md`:

```markdown
---
"ssh-mcp": minor
---

**`--rateLimit` is now counted per client.** It was one bucket for the whole process: with
`--rateLimit=3`, one client was served three times and a second client was refused before
it had sent a single request, both on direct connections and behind a trusted proxy. Each
client now has its own budget, keyed exactly as the failed-auth budget is: the socket
address, or the rightmost `X-Forwarded-For` entry when `--trustProxy` is set and the peer
is the proxy. Closes #187.

**Minor, not patch, because a client that used to be served can now get a 429.** The budget
is charged on every authenticated request, not only the MCP route: `GET /status` and an
authenticated request to an unknown path spend from it too, and `GET /health` still does
not. A monitor polling `/status`, or an MCP client and a `/status` poller sharing one
address, can now exceed `--rateLimit` where before `/status` was unlimited. Behind a
reverse proxy without `--trustProxy`, every client still shares one budget, as before; the
server's warning about that now names both budgets and fires with only `--rateLimit` on.

`Retry-After` on both 429s is now the time until that client's next request will be
accepted, at least one second, rather than a full token interval. The request-limit 429
body now carries `id: null`, as the other error responses already did.

**Fix to the failed-auth budget.** Its table of tracked clients judged itself "saturated" by
stored token counts, which never change for a client that stops sending. Once 1024
addresses had each spent a budget, every later client started with an empty budget for
good, so a single typo made its correct token wait, even an hour after the attack ended.
Saturation is now judged by tokens after refill, so the condition ends when those buckets
refill.
```

- [ ] **Step 5: Verify the docs agree with the code**

Run: `grep -n "rateLimit" README.md SECURITY.md`
Expected: no remaining "MCP route" or "Max requests per minute" wording for `--rateLimit`, and both table rows read "per client".

Run: `npx changeset status`
Expected: lists `ssh-mcp` with a `minor` bump.

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add README.md SECURITY.md .review-pro/ssh-mcp/backend.md .review-pro/ssh-mcp/security.md .changeset/per-client-rate-limit.md
/usr/bin/git commit -m "docs: --rateLimit is per client and covers every authenticated route

README, SECURITY.md and the review-pro criteria described the old scope (MCP
route only, one bucket). The changeset is minor: /status and authenticated
404s now spend the budget, so a client served before can get a 429.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### After the tasks (controller, not a task subagent)

1. Final whole-branch review on the most capable model (`superpowers:subagent-driven-development`'s final review step), against the spec and this plan.
2. Start the Docker test servers: `docker compose --profile test up -d --build`. Then run the full suite: `npm test` (unit, property, integration). Also run `npm run typecheck` and `npm run test:e2e`.
3. `/usr/bin/git push -u origin worktree-issue-187-auth-failure-budget`, then `gh pr create` against `main`, with the measurements table from the spec and the suite result in the body. **Do not merge.**
