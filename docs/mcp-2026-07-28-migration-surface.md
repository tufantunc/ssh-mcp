# MCP 2026-07-28: what it will cost us, and what to do until then

> Written 2026-08-24 against spec revision [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
> and the [roadmap](https://modelcontextprotocol.io/development/roadmap) as of 2026-08-22.
> Nothing in this document is actionable as code today — see [Why there is nothing to upgrade](#why-there-is-nothing-to-upgrade).
> Its purpose is that the day the SDK catches up, we are not rediscovering this list.

## Why there is nothing to upgrade

| | |
|---|---|
| Current spec revision | **2026-07-28** |
| Installed SDK | `@modelcontextprotocol/sdk@1.30.0` |
| Newest published SDK | **1.30.0** — the only dist-tag, no prerelease |
| That SDK's newest protocol | `LATEST_PROTOCOL_VERSION = '2025-11-25'` (default negotiated: `2025-03-26`) |

The TypeScript SDK was published **2026-07-27**, one day before the spec revision, and has not
caught up. We are already on the newest release; the gap is upstream.

How far upstream, measured against `node_modules/@modelcontextprotocol/sdk/dist/esm/`:

| symbol | files |
|---|---|
| `tasks/get` | 7 |
| `input_required` | 5 |
| `resultType` | 0 |
| `server/discover` | 0 |
| `inputRequests` | 0 |
| `subscriptions/listen` | 0 |
| `cacheScope` | 0 |
| `Mcp-Method` | 0 |

The `tasks/*` and `input_required` hits are the **2025-11-25** experimental Tasks feature — which
2026-07-28 moved *out* of core into the `io.modelcontextprotocol/tasks` extension and redesigned.
None of the 2026-07-28 core has been started. Re-run the table before trusting it:

```bash
for s in resultType server/discover input_required inputRequests subscriptions/listen cacheScope Mcp-Method tasks/get; do
  printf '%-22s %s\n' "$s" "$(grep -rl "$s" node_modules/@modelcontextprotocol/sdk/dist/esm/ 2>/dev/null | wc -l)"
done
```

## What lands on us

Ordered by how much is our code rather than the SDK's.

### 1. Elicitation becomes Multi Round-Trip Requests — the big one

**Spec:** MRTR ([SEP-2322](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2322))
replaces server-initiated requests, `elicitation/create` included. The server returns an
`InputRequiredResult` (`resultType: "input_required"`) carrying `inputRequests`; the client answers
by **retrying the original request** with `inputResponses`.

**Us:** `src/guard/elicitation.ts` and `checkPolicyAndApprove` in `src/tools/pipeline.ts` block
*inside* a single tool call awaiting `server.elicitInput()`. MRTR inverts that: the call returns,
and a later call carries the answer.

Consequences worth knowing before touching this area:

- `approvalGrantTtlMs` stops being a convenience and becomes the mechanism that makes the retry
  cheap — a grant is what lets the second attempt through without asking again.
- The spec removed `notifications/elicitation/complete` and `elicitationId`, and says servers that
  need to correlate an elicitation across retries "encode their own identifier in `requestState`".
  We use neither today, so there is nothing to unwind.
- One decision already paid off: `elicitation.ts` uses the SDK's typed `elicitInput()` rather than a
  hand-built envelope, deliberately, so that "a protocol change breaks the build instead". This is
  the protocol change it was written for.

### 2. Protocol-level sessions are removed

**Spec:** [SEP-2567](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2567) removes
sessions and the `Mcp-Session-Id` header from Streamable HTTP; list endpoints no longer vary per
connection. Servers needing cross-call state use "explicit, server-minted handles passed as ordinary
tool arguments".

**Us:** `src/transport/http.ts` keeps a `Map<string, StreamableHTTPServerTransport>` keyed by
`mcp-session-id`, with `MAX_SESSIONS`, a DELETE path, and the `-32000`/`-32001` session errors. All
of it becomes dead weight.

**The design survives.** `open-session name=…` already *is* a server-minted handle passed as a tool
argument — the thing the new spec asks for. Only the transport plumbing goes.

### 3. The HTTP GET endpoint is replaced by `subscriptions/listen`

The GET endpoint and `resources/subscribe`/`unsubscribe` are gone, replaced by a single long-lived
POST-response stream. `src/transport/http.ts` matches `req.method === 'GET'` on `/` in the rate
limiter and for the health probe; the first needs revisiting, the second is ours and unaffected.

Note the spec is explicit that request-scoped notifications — `notifications/progress`, which we
send from `pipeline.ts` — **continue to flow on the response stream of their own request**, not the
subscription stream. Our progress path is unaffected.

### 4. `ttlMs` and `cacheScope` become required on list and read results

[SEP-2549](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2549) requires both on
`tools/list`, `prompts/list`, `resources/list`, `resources/read` and `resources/templates/list`.

**Do not confuse this with our own `ttlMs`** in `src/types.ts` — that is a session idle TTL and has
nothing to do with `CacheableResult`.

Our resources (`ssh://connections`, `ssh://connections/{profile}`, `ssh://sessions/{profile}/{session}`)
return live, caller-specific state. The honest answer is `cacheScope: "private"` with a short
`ttlMs`, and it is worth choosing deliberately rather than accepting whatever the SDK defaults to —
a shared intermediary caching a connection list would be a disclosure, not a papercut.

### 5. Required request headers

`Mcp-Method` and `Mcp-Name` become required on Streamable HTTP POSTs
([SEP-2243](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2243)), which touches
the auth and rate-limiting middleware in `src/transport/http.ts`.

### The SDK's problem, not ours

Statelessness and the removal of the `initialize` handshake; `server/discover` (a **MUST** for
servers); `resultType` on every result; the error-code renumbering.

## What we get for free

Not luck — most of these are positions we already took for other reasons.

- **Sampling, Roots and Logging are all deprecated, and we use none of them.** The suggested
  migration for Logging is "log to `stderr` (stdio) or use OpenTelemetry" — both of which we already
  do.
- **HTTP+SSE is now formally Deprecated**; we are on Streamable HTTP.
- **Our custom JSON-RPC codes are grandfathered.** The new allocation policy keeps `-32000`–`-32019`
  implementation-defined; our `-32000`/`-32001` sit inside it. (The spec renumbered its own
  `HeaderMismatch` from `-32001` to `-32020` for the same reason.)
- **We return no `structuredContent`**, so the `tools/call` result-shape redesign on the roadmap
  cannot break us. If we ever want structured output, that is the moment to adopt it — not before.
- We use neither `elicitationId` nor `notifications/elicitation/complete`, both removed.

## Roadmap items aimed at what we are

- **Agent Identity (priority 3).** The roadmap says, in as many words, that existing servers "lean on
  pasted API keys and long-lived refresh tokens". That is our HTTP bearer token. The direction is
  DPoP, Workload Identity Federation ([SEP-1933](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1933)),
  ID-JAG and RFC 8693 token exchange. None of it is implementable today — but it is reason enough not
  to invest further in the current auth path.
- **Tasks (priority 1, [SEP-2663](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2663)).**
  Background sessions + progress + cancellation is a hand-rolled version of this extension. The
  redesign polls via `tasks/get` and takes client input via `tasks/update`. Long term it may replace
  `open-session type="background"`.
- **HTTP over stdio (priority 2).** Streamable HTTP as the single binding, spoken over stdin/stdout.
  Would collapse our two transports into one. Nothing to do now, and an argument against writing more
  transport-specific code in the meantime.
- **Progressive discovery (priority 4).** For servers with large catalogues. We have 11 tools; not
  our problem yet.
- **Conformance test suite (priority 5).** Worth running against ourselves once it exists.

## What to do, and what not to

**Now:**

1. Keep this document current. It is the whole point of writing it.
2. **Do not build anything new on elicitation or on session-scoped transport state.** Both are being
   removed. This is the one action available today that actually saves work later.

**A decision, not code:** whether to track DPoP for the HTTP transport's bearer token. It determines
how much more we are willing to invest in the current auth path.

**Explicitly not now:** implementing 2026-07-28 against an SDK that does not support it. Our HTTP
transport is built on `StreamableHTTPServerTransport`; forking or shimming it would open a large,
high-risk surface for a spec whose SDK support has not started. When the SDK ships it, most of
sections 1–5 above become an SDK upgrade plus a focused change to `src/transport/http.ts` and the
approval path.

## Re-checking this document

```bash
npm view @modelcontextprotocol/sdk dist-tags --json          # is there a newer release or a prerelease?
grep -n "LATEST_PROTOCOL_VERSION\|SUPPORTED_PROTOCOL_VERSIONS" \
  node_modules/@modelcontextprotocol/sdk/dist/esm/types.js   # what does it actually speak?
```

The day `LATEST_PROTOCOL_VERSION` reads `2026-07-28`, this list stops being theory.
