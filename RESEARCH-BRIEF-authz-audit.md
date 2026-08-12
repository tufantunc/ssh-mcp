# Authorization & Audit Logging for ssh-mcp v2: A Research Brief

**Scope.** This brief surveys the landscape of authorization/policy engines and audit-logging/observability practices relevant to a v2 of `tufantunc/ssh-mcp`, a Node/TypeScript MCP server that exposes SSH command execution (`exec`, `sudo-exec`) to LLM clients. It is grounded in the repo's current trajectory: PR #56 ("feat: add redacted command audit log") introduces a JSONL audit log with rotation and field-level redaction under `src/audit/` [PR56]; Issue #23 requests a way to differentiate read-only MCP commands so clients can be more permissive [ISSUE23]; Issue #36 asks to add the MCP `readOnlyHint` tool annotation so clients (e.g. Claude Code) can parallelize independent calls to independent hosts [ISSUE36]. The PR stack note in #56 also signals an upcoming `pr/approval-engine` and `pr/per-source-approval` [PR56].

All URLs cited in the numbered *Sources* list were fetched and verified during research. Regulatory standards are cited by their stable identifiers.

---

## PART 1 — AUTHORIZATION & POLICY

### A. What to authorize: the policy model

An SSH MCP gateway sits between an LLM client and one or more remote shells. Every command execution request carries four orthogonal dimensions that must be authorized together:

| Dimension | Values for ssh-mcp |
|---|---|
| **Subject** (`who`) | The MCP client identity. Today this is implicit (the local stdio peer), but as ssh-mcp moves toward HTTP transports and OAuth-protected deployments, the subject becomes an OAuth `sub`, a token principal, or a configured local role. AuthZEN calls this the `Subject { type, id, properties }` entity [AUTHZEN §5.1]. |
| **Action** (`what`) | The *command class*: `read-only`, `safe`, `destructive`, `privileged`. ssh-mcp today has two tools (`exec`, `sudo-exec`) but no class taxonomy — this is exactly the gap Issue #23 exposes [ISSUE23]. |
| **Resource** (`which`) | The target host/profile: a named connection in config, optionally grouped into host-groups (prod/dev/staging). OpenFGA would model this as an `object` like `host:prod-web-1` [OPENFGA]. |
| **Verb/Tool** (`via`) | The MCP tool invoked (`exec` vs `sudo-exec`, and in future a read-only `cat`/`ls` tool). The MCP `ToolAnnotations` hint (`readOnlyHint`) is a *client-side* advisory, not an authorization decision — the MCP spec explicitly states "Clients should never make tool use decisions based on ToolAnnotations" [ISSUE36]. Authorization must be server-side. |

The canonical authorization tuple is therefore **(subject, command-class, host-group, tool) → {allow, deny, require-approval}**. This mirrors the AuthZEN `Access Evaluation` request shape `{subject, action, resource, context}` [AUTHZEN §6.1] and maps cleanly to Zanzibar's `⟨object, relation, subject⟩` tuple model [ZANZIBAR]. Context can carry time-of-day, transport (stdio vs http), and whether an approval token is present — exactly the env in which Teleport evaluates "access requests" [TELEPORT] and Tailscale evaluates `check` vs `accept` SSH rules [TAILSCALE].

A key design principle, drawn from OPA's SSH/sudo guide: **keep authorization policies for different verbs in separate packages/files** so that an `exec` policy and a `sudo-exec` policy cannot accidentally leak authority into each other [OPA-SSH]. ssh-mcp v2 should treat `sudo-exec` as a strictly more privileged action than `exec` and require it to pass an additional, independent policy check.

### B. Policy engine comparison

| Engine | Language | Embedding in Node | Expressiveness | Maturity | Fit for ssh-mcp |
|---|---|---|---|---|---|
| **OPA / Rego** [OPA] | Rego (Turing-ish, declarative) | Sidecar (HTTP at :8181) or WASM (`@asyncapi/opa`, `opa-wasm`). Native lib is Go-only. | Very high: ABAC, data filtering, aggregation, `every`/`some`. | CNCF Graduated; production at thousands of orgs; explicit SSH/sudo use case [OPA-SSH]. | Excellent if an OPA sidecar already exists; heavy as a default dep for an npm package. |
| **AWS Cedar** [CEDAR] | Cedar (purpose-built, small) | `cedar-wasm` crate → JS/TS bindings. Rust core. | RBAC + ABAC, indexed for bounded-latency eval, analyzable via automated reasoning. | Apache-2.0, 1.6k★, 76 releases, AWS-backed (used in Amazon Verified Permissions). | Strong middle ground: ergonomic syntax, fast, embeddable via WASM. Newer ecosystem. |
| **Casbin** [CASBIN] | Model DSL (`.conf`) + policy store | `node-casbin` — **production-ready, pure JS**, many adapters (file, DB, Redis). | RBAC, ABAC, ReBAC, priority models, `keyMatch` globbing, role hierarchies. | Apache (Incubating); node-casbin is the most Node-native option; 2.9k★. | Best "batteries-included" Node option; lightweight; but DSL has a learning curve. |
| **Simple YAML rules** (built-in) | YAML + a few hundred lines of TS | Native, zero deps. | Limited to allow/deny lists + risk classes; no arbitrary expressions. | n/a | Sufficient for v2's RBAC matrix; trivially auditable; no supply-chain risk. |

**Recommendation.** Ship a **built-in YAML rule engine as the default**, with **OPA as an optional external sidecar** for organizations that already standardize on Rego. Rationale:

1. ssh-mcp is distributed as a single npm package (`ssh-mcp`) consumed via `npx` [README]. Pulling a native Go binary (OPA) or a ~1 MB WASM blob (cedar-wasm) into every install bloats the default footprint and adds a WASM/Go toolchain to the supply chain. The actual policy space — `(role × host-group × command-class) → decision` — is small enough that ~200 lines of TypeScript over a YAML config cover it.
2. The MCP authorization guidance from OpenFGA itself notes that relationship-based checks (`Check`) can be delegated to an external PDP when needed [OPENFGA-MCP]. This argues for a clean **PEP/PDP seam**: the YAML engine is the default in-process PDP, and a configured `--opa-url` flips the server into "ask the sidecar" mode, speaking roughly the AuthZEN Access Evaluation contract [AUTHZEN §6]. This keeps the seam standards-aligned.
3. Cedar and Casbin are both reasonable *if* the project later wants richer ABAC (e.g. attribute-based: "allow if subject.department == host.owner-team AND time-in-business-hours"). Of the two, **Casbin via `node-casbin`** is the lower-friction Node choice; **Cedar** is the better choice if automated-reasoning proofs of policy soundness become a requirement [CEDAR]. Neither is needed for v2.

### C. RBAC model: a policy sketch

Borrowing the role/host-set/verb taxonomy from Teleport [TELEPORT] and the time-bounded notion from Tailscale `check` rules [TAILSCALE], a v2 config could look like:

```yaml
# ssh-mcp v2 policy (illustrative)
roles:
  viewer:
    commandClasses: [read-only]
  operator:
    commandClasses: [read-only, safe]
  admin:
    commandClasses: [read-only, safe, destructive, privileged]

hostGroups:
  prod:    [prod-web-1, prod-db-1]
  staging: [stage-web-1]
  dev:     [dev-box-1]

commandClasses:
  read-only:   { tools: [exec], allowlist: ["ls*", "cat*", "stat*", "ps*", "df*"], denylist: ["rm*", "dd*", "mkfs*"] }
  safe:        { tools: [exec], allowlist: ["*", "systemctl status *"], denylist: ["systemctl restart *"] }
  destructive: { tools: [exec], requiresApproval: true, ttl: 30m }
  privileged:  { tools: [sudo-exec], requiresApproval: true, ttl: 30m }

bindings:
  - { role: viewer,  hostGroup: prod,    classes: [read-only] }
  - { role: operator,hostGroup: staging, classes: [read-only, safe] }
  - { role: admin,   hostGroup: "*",     classes: ["*"] }
```

Three properties make this safe: (1) **default-deny** — if no binding matches, the request is denied (OPA's `default allow := false` pattern [OPA]); (2) **denylist beats allowlist** within a class; (3) `privileged` (i.e. `sudo-exec`) always requires approval and a TTL, echoing Tailscale's `check` action with `checkPeriod` [TAILSCALE]. This directly answers Issue #23: a `viewer` binding to a host-group exposes only a read-only command surface, letting the client treat those tool calls as side-effect-free (and parallelizable per Issue #36) [ISSUE23][ISSUE36].

### D. Reference architectures: what to borrow

- **Teleport** [TELEPORT]: RBAC roles with `allow`/`deny` clauses over logins, labels (host selectors), and **session recording**; "access requests" grant JIT elevation for a window. Borrow: role definitions with label-based host selection, and the JIT request primitive.
- **HashiCorp Boundary** [BOUNDARY]: host sets + host catalogs, **time-bounded credentials** delivered by a controller, principle of least privilege via scopes. Borrow: the "credential is valid for N minutes" mental model for destructive-class approval.
- **Tailscale SSH** [TAILSCALE]: identity comes from the tailnet (no SSH keys to manage), authorization is an `ssh[]` ACL block with `action: accept|check` and `checkPeriod`, and **session recording** is a first-class feature. Borrow: the `accept` vs `check` distinction maps perfectly onto ssh-mcp's "safe" vs "destructive/privileged" classes, and `checkPeriod` is the TTL knob.

**Session recording recommendation.** ssh-mcp should support **optional asciinema-cast recording per session, off by default**. asciinema's `.cast` format (JSON-lines header + `[time, "o", data]` events) is trivially produced from ssh2's stream data, is human-replayable, and is already the de-facto open format (Tailscale records to it; many internal tools consume it). Default-off matters because (a) recorded sessions frequently contain secrets in-band (the very problem PR #56's redactor exists to mitigate [PR56]) and (b) disk growth is unbounded without retention policy. A `--record-sessions` flag plus a configurable retention/rotation (the PR already ships a rotator [PR56]) is the right shape. Recording should be **gated behind the same authorization decision** — only sessions the policy allowed should be recordable, and the decision itself is logged.

### E. JIT / time-bounded access — opinionated

**ssh-mcp v2 should make time-bounded approval a first-class feature, not an afterthought.** The PR stack already includes `pr/approval-engine` and `pr/per-source-approval` [PR56], so the machinery is planned. The case for JIT:

1. **It matches how production SSH access actually works at mature orgs.** Teleport's "access requests" and Tailscale's `check` mode both encode the same insight: standing privileged access is the enemy; time-boxed, approved access is the goal [TELEPORT][TAILSCALE]. An SSH MCP gateway that lets an LLM run `sudo` on prod *without* a human-in-the-loop approval step is a footgun.
2. **It composes cleanly with the read-only split.** Issue #23 wants clients to be lax with read-only commands [ISSUE23]; the natural complement is to be *strict* with destructive/privileged ones — and "strict" here means "require an approval token with a TTL," not merely "deny." Denial pushes the user to bypass the gateway; approval-with-TTL keeps the action observable.
3. **It's cheap to implement.** An approval is a signed (HMAC) blob `{subject, host, commandClass, expiresAt, approver}`; the gateway validates it on each destructive/privileged call and logs `approver` + `approvalId` in the audit entry (see §F). The TTL reuses Tailscale's semantics: a `30m` window after which the same command class needs re-approval [TAILSCALE].

Concrete mechanism: extend the YAML policy so `destructive` and `privileged` classes carry `requiresApproval: true, ttl: <duration>`. When such a class is requested without a valid approval, the server returns a structured MCP error of a recognizable type (e.g. `APPROVAL_REQUIRED`) carrying a nonce; a human (via a small web UI — the stack shows `pr/webui-manual-approval` [PR56]) approves, signing the nonce with a shared secret; the client retries with the approval token. This is the AuthZEN "step-up" pattern expressed as an obligation in the Decision `context` [AUTHZEN §5.5.2.3].

---

## PART 2 — AUDITING & LOGGING

### F. What to log per command (and what never to log)

PR #56 already establishes the right skeleton: an append-only JSONL store with rotation and redaction [PR56]. The per-command audit record should capture:

```jsonc
{
  "@timestamp": "2026-07-08T12:34:56.789Z",      // RFC3339, UTC
  "event": {
    "id": "01J...",                              // ULID/UUIDv7, the correlation key
    "kind": "event",                             // ECS event.kind
    "category": ["process"],                     // ECS event.category
    "type": ["start", "end"],                    // emit two records or one?
    "outcome": "success",                        // ECS: success/failure/unknown
    "action": "ssh-mcp.exec",                    // dotted tool name
    "risk": "read-only"                          // command class (§C)
  },
  "mcp": {
    "requestId": "req-42",                       // MCP JSON-RPC id [MCP]
    "transport": "stdio",                        // stdio | http
    "client": { "name": "claude-code", "version": "..." }
  },
  "subject": {                                   // AuthZEN Subject [AUTHZEN]
    "type": "oauth", "id": "alice@example.com",
    "properties": { "role": "operator" }
  },
  "host": { "profile": "prod-web-1", "group": "prod", "addr": "10.0.0.5:22" },
  "session": { "user": "ubuntu", "sudo": false, "workdir": "/srv/app" },
  "command": {
    "binary": "ls",                              // parsed first token
    "sanitized": "ls -la /srv/app",              // secrets masked (§H)
    "raw": "[REDACTED]",                         // never raw if high-risk
    "classification": "read-only",
    "maxChars": 1000
  },
  "execution": {
    "exitCode": 0, "durationMs": 412,
    "bytesIn": 12, "bytesOut": 1582,
    "timedOut": false
  },
  "authz": {
    "decision": "allow",                         // allow | deny | require-approval
    "policyId": "binding#3",                     // which rule fired
    "deniedByPolicy": false,
    "approvalId": null,                          // present when class needed approval
    "approver": null
  },
  "redaction": { "fieldsRedacted": 0, "patternsMatched": ["aws-akia"], "entropyHits": 1 }
}
```

**Never log:** raw passwords, SSH private keys, the `sudoPassword`/`suPassword` values, OAuth bearer tokens, the contents of files the command read, or full TTY capture without secret-scan. The PR's redactor already targets the known secret fields (`password`, `privateKey`, `sudoPassword`) [PR56]; §H extends this to *output*. The guiding rule, from NIST SP 800-92's log-management guidance, is to log *enough to reconstruct the event* without logging *the confidential payload* [NIST800-92]. PCI-DSS Req. 10 and HIPAA §164.312(b) make the same point: audit trails must capture "who did what when" but must not themselves become a secondary breach surface [PCI][HIPAA].

### G. Format recommendation

**Default: JSON Lines (JSONL).** One record per line, append-only, trivially greppable and streamable. This is what PR #56 ships and it is the right default [PR56].

**Optional layer 1: ECS (Elastic Common Schema) mapping.** ECS v9.4 defines stable field sets — `event`, `user`, `host`, `process`, `source`, `destination`, `network`, `log` — that let ssh-mcp records flow into Elastic/Kibana, Elastic SIEM, or any ECS-aware tooling without custom parsing [ECS]. The sketch in §F already uses ECS field names (`event.*`, `host.*`, `source.*`). The cost is purely naming discipline; the benefit is free SIEM ingestion. Recommend: emit ECS-named fields natively, with a `--audit-format=plain` escape hatch for users who want shorter keys.

**Optional layer 2: CEF (Common Event Format) for legacy SIEM.** CEF is the ArcSight/Micro Focus line-based format (`CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Extension`). It remains common in Splunk/QRadar deployments that predate ECS. Provide a `--audit-cef` exporter that reads the JSONL log and emits CEF lines for SIEM ingest. Do **not** make CEF the primary format — it is harder to redact safely (pipe-delimited) and predates JSON tooling.

**Tamper-evidence container.** Each JSONL line should be self-contained and idempotent; ordering is implied by append-only writes. See §I for optional chaining.

### H. Secret redaction — layered defense

PR #56 redacts known secret *input fields* before persisting commands [PR56]. For a gateway that captures *command output*, this is necessary but not sufficient — output is where live secrets surface (an `env` dump, a `cat ~/.aws/credentials`, a debug log). Adopt a **three-layer redaction pipeline**, in order:

1. **Field redaction (deterministic).** Always redact the known sensitive config fields: `password`, `privateKey`, `key`, `sudoPassword`, `suPassword`, and any env vars matching a denylist (`*_TOKEN`, `*_SECRET`, `*_KEY`). pino's built-in `redact` paths do exactly this for structured logs and is the idiomatic Node choice [PINO]. This is what PR #56 implements for inputs; extend it to wrap every persisted output blob.

2. **Regex pack for common secret shapes.** Ship a curated regex set matching: AWS access keys (`AKIA[0-9A-Z]{16}`), AWS secret keys, GitHub tokens (`gh[pousr]_[A-Za-z0-9]{36}`), GitLab PATs (`glpat-[A-Za-z0-9_-]{20}`), Slack tokens, generic JWTs (`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), PEM private-key blocks (`-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----`), and `Authorization: Bearer <token>`. This is the gitleaks/TruffleHog detector-regex approach distilled to ~15 high-precision patterns [TRUFFLEHOG][GITLEAKS]. Replace each match with a length-preserving mask (`[REDACTED:aws-akia:20]`) so log analytics on output size still work.

3. **Shannon-entropy scan (high-recall, lower-precision).** TruffleHog and gitleaks both ship entropy filters (gitleaks: `entropy = 3.5` per capture group; TruffleHog: `--filter-entropy=3.0`) to catch *unknown* high-entropy strings that regex misses — generated tokens, base64 blobs, connection strings [TRUFFLEHOG][GITLEAKS]. Run Shannon entropy over tokenized *output* (not over the whole record) and mask runs above a tunable threshold (default ~4.5 bits/char over a minimum length of 20).

**False-positive cost is real.** Entropy scanning will mask legitimate high-entropy output — base64-encoded images, hashes, compressed blobs, UUIDs. Two mitigations: (a) make layer 3 **opt-in** (`--audit-entropy-scan`), defaulting off; (b) when masking, preserve the *type* of the match in the mask (`[REDACTED:entropy:64]`) so a reviewer knows whether 64 masked bytes were a likely token or a likely hash. Layer 1 (field) and Layer 2 (regex) should always be on; Layer 3 is for regulated/high-assurance deployments.

Record what redaction did in the `redaction` sub-object (§F) so auditors can distinguish "no secrets present" from "redaction silent."

### I. Tamper-evidence — optional, off by default

For most OSS users, append-only JSONL with OS file permissions (0600, owned by the gateway user) is sufficient assurance. For high-assurance deployments (financial, healthcare), offer an **opt-in hash-chained mode**:

- Each log line includes `prev_hash` = SHA-256 of the previous line's canonical bytes, and `self_hash` computed over the line *excluding* `self_hash`. This is the Bitcoin-style chain: any in-place edit breaks the chain at that line.
- Once per day (or per N lines), emit a **signed root**: a small JSON document `{date, lastLineHash, count}` signed with **sigstore/cosign** keyless signing — Fulcio issues a short-lived cert bound to an OIDC identity, and the entry is recorded in the Rekor transparency log [SIGSTORE]. This gives public, timestamped proof that the log existed at a point in time and was not altered, without a private key to manage.

Keep this **off by default**. Hash-chaining adds write-path latency and complicates rotation (the rotator must carry the chain head forward — PR #56's rotator would need extension [PR56]). It is valuable only where an auditor demands it.

### J. Compliance relevance — opinionated

The audit-trail requirements of the major frameworks all point the same direction, and ssh-mcp's planned log already satisfies the *spirit* of each:

- **SOC 2 (CC7.2, CC8.1):** requires monitoring of system activity and change management; a JSONL audit log with subject, command, outcome, and timestamp satisfies the monitoring criterion. Tamper-evidence (§I) strengthens it but is not strictly required.
- **PCI-DSS v4.0 Req. 10:** mandates audit trails for every action on cardholder-data systems, with ≥1-year online + 1-year offline retention and time-synchronized clocks. ssh-mcp's log covers the "what was run" axis; retention is a deployment concern.
- **ISO/IEC 27001 A.12.4 (logging & monitoring) / A.18.1.3:** require logging of events and protection of log integrity. Append-only + redaction + optional chaining answers both.
- **HIPAA §164.312(b):** "Implement hardware, software, and/or procedural mechanisms that record and examine activity." The §F schema does this; the §H redaction prevents the log itself from becoming PHI.
- **NIST SP 800-92 (Guide to Computer Security Log Management):** the canonical operational guidance — centralize, synchronize clocks, protect integrity, define retention, redact sensitive content [NIST800-92]. NIST SP 800-53 Rev. 5 AU family (AU-2 events, AU-3 content, AU-6 review, AU-9 protection, AU-11 retention) maps almost one-to-one onto the §F fields [NIST800-53].

**Verdict.** Compliance is *relevant if ssh-mcp is deployed in a regulated environment* (an operator running it against a PCI-scoped host, a HIPAA-covered database). It is **not blocking for OSS v2**: the project should ship a complete, well-structured audit log and document the compliance mapping (this section), but should **not** pursue formal certification or ship tamper-evidence by default. Certification is the deployer's responsibility; the project's job is to make compliance *achievable* with config, not to impose it.

### K. Correlation IDs and tracing

MCP is JSON-RPC 2.0 over stdio or HTTP; every request carries an `id` (integer or string) which the server echoes in its response [MCP]. This `id` is the natural **request correlation key**:

1. **MCP request id → audit `mcp.requestId`.** The server reads the JSON-RPC `id` from the incoming `tools/call` and stamps it onto the audit record (§F `mcp.requestId`). A single client "turn" that fans out multiple tool calls produces multiple audit lines sharing the same logical conversation but distinct `requestId`s; optionally also log a client-supplied `description` as a human-readable join key.
2. **Audit id → OTEL trace span.** When OTEL is enabled (`--otel`), create a server span per `tools/call` with `span.setAttribute("mcp.request_id", id)` and `span.setAttribute("ssh-mcp.command_class", ...)`. Propagate via **W3C Trace Context** (`traceparent` header) on the HTTP transport; on stdio, the server generates the trace context since there is no inbound HTTP header. The audit record stores `trace.traceId` and `trace.spanId` so a query in either system jumps to the other.
3. **Session correlation.** Emit a `session.id` (stable per MCP connection) on every record so a reviewer can reconstruct "all commands run in this one agent session."

This three-key scheme (requestId, traceId, sessionId) is exactly what ECS's `event.id` + `trace.*` + `session.*` fields are designed for [ECS], and it makes the audit log a first-class participant in distributed tracing rather than a siloed artifact.

### L. Concrete recommendations for ssh-mcp v2

Tied back to the actual code and PR trajectory:

1. **Keep the audit log as PR #56 ships it** — append-only JSONL, rotating, with field-level redaction of inputs — and **extend the redactor to cover command output** via the §H three-layer pipeline (field always-on, regex always-on, entropy opt-in). The `src/audit/redactor.ts` module [PR56] is the natural home; add an `outputRedactor` alongside the existing input redactor. Add the §F `redaction` sub-object so the log is self-describing.

2. **Adopt the ECS field names** for the audit record (§G). The cost is renaming keys; the benefit is free SIEM ingestion and alignment with the rest of the observability stack. Keep a `--audit-format=plain` escape hatch.

3. **Introduce the command-class taxonomy** (read-only / safe / destructive / privileged) from §C as config, and wire the `exec`/`sudo-exec` tools to classify an incoming command before authorization. This is the server-side answer to Issue #23 [ISSUE23]: a `viewer`-bound profile exposes only read-only commands, and the client can trust that. Separately, **also add `readOnlyHint: true` to the read-only tool** per Issue #36 [ISSUE36] — but treat it strictly as a *client parallelization hint*, never as an authorization source (the MCP spec is explicit on this [ISSUE36]).

4. **Ship the built-in YAML rule engine** (§B, §C) as the default authorization PDP, with `--opa-url` to delegate to an OPA sidecar speaking the AuthZEN Access Evaluation contract [AUTHZEN]. Do not bundle OPA, Cedar, or Casbin into the npm package. Default-deny everywhere.

5. **Make JIT approval first-class** (§E). The `pr/approval-engine` in the stack [PR56] is the right vehicle. `destructive` and `privileged` classes carry `requiresApproval + ttl`; destructive/privileged calls without a valid signed approval return a structured `APPROVAL_REQUIRED` error; a minimal approver (the `pr/webui-manual-approval` [PR56]) signs approval tokens. Log `approver` + `approvalId`.

6. **Add optional asciinema-cast session recording**, off by default, gated by authorization, with retention tied to the existing rotator [PR56]. Format: JSONL header `{version: 2, width, height, timestamp}` followed by `[t, "o", chunk]` events.

7. **Make OTEL opt-in** (`--otel` / `OTEL_EXPORTER_OTLP_ENDPOINT`), emitting spans with `mcp.request_id`, `ssh-mcp.command_class`, `ssh-mcp.host_profile`, and `ssh-mcp.decision` attributes (§K). W3C Trace Context on HTTP; self-originated traces on stdio.

8. **Document the compliance mapping** (§J) in the README under a "Compliance" section, but do not seek certification. Ship hash-chaining + sigstore root signing (§I) behind `--audit-tamper-evident` for the minority who need it.

This package keeps the OSS default lightweight (zero native deps, JSONL log, YAML rules), gives regulated deployers a clear path to compliance (ECS fields, OPA sidecar, tamper-evidence, session recording), and directly resolves the three tracked items: the audit-log PR #56, the read-only split of Issue #23, and the parallelization hint of Issue #36.

---

## Sources

All URLs were fetched and verified during research (July 2026). Regulatory standards are cited by stable identifier.

1. **OPA — Open Policy Agent** (CNCF Graduated). Documentation. https://openpolicyagent.org/docs/latest/ (fetched 2026-07-08). Apache-2.0.
2. **Cedar Policy Language** — `cedar-policy/cedar`, Rust implementation. https://github.com/cedar-policy/cedar (fetched 2026-07-08). 1.6k★, 76 releases, Apache-2.0. Includes `cedar-wasm` crate for JS/TS bindings.
3. **Casbin** (Apache Incubating) — `casbin/node-casbin` for Node.js. Overview: https://casbin.org/docs/overview (fetched 2026-07-08). Apache-2.0.
4. **AuthZEN Authorization API 1.0** — Gazitt, Brossard, Tulshibagwale (Eds.), OpenID Foundation, published 2026-07-07. https://openid.github.io/authzen/ (fetched 2026-07-08). Defines PDP/PEP, Subject/Action/Resource/Context/Decision model, Access Evaluation + Search APIs.
5. **OpenFGA** — Concepts (Zanzibar-derived, CNCF). https://openfga.dev/docs/concepts (fetched 2026-07-08). Includes explicit "Authorization for MCP Servers" modeling guide.
6. **Zanzibar: Google's Consistent, Global Authorization System** — Pang et al., USENIX ATC '19 (2019). https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/ (fetched 2026-07-08). Tuple model `⟨object, relation, subject⟩`; <10ms p95, 99.999% availability.
7. **OPA — SSH and sudo authorization** (via Linux-PAM plugin). https://www.openpolicyagent.org/docs/latest/ssh-and-sudo-authorization (fetched 2026-07-08). Reference for separating `sshd_authz` and `sudo_authz` policies; ticket-based elevation.
8. **Tailscale SSH** (identity-based SSH, ACL `ssh[]` rules, `accept`/`check` actions, `checkPeriod`, session recording). https://tailscale.com/kb/1193/ssh-recording and https://tailscale.com/docs/features/tailscale-ssh (fetched 2026-07-08).
9. **Elastic Common Schema (ECS) v9.4** — field reference. https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html (fetched 2026-07-08). Field sets: `event`, `user`, `host`, `process`, `source`, `destination`, `network`, `log`, `tracing`, `session`.
10. **TruffleHog** — `trufflesecurity/trufflehog`, 800+ secret detectors with API verification, Shannon-entropy filter (`--filter-entropy`). https://github.com/trufflesecurity/trufflehog (fetched 2026-07-08). AGPL-3.0.
11. **Gitleaks** — `gitleaks/gitleaks`, TOML-config rules with regex + `entropy` (e.g. `3.5`) + `keywords`, composite rules. https://github.com/gitleaks/gitleaks (fetched 2026-07-08). MIT.
12. **Sigstore / Cosign** — keyless signing via Fulcio (short-lived OIDC-bound certs) + Rekor transparency log; JavaScript client available. https://docs.sigstore.dev/cosign/signing/overview/ (fetched 2026-07-08).
13. **Model Context Protocol — Lifecycle (JSON-RPC 2.0)** — protocol version 2025-06-18. https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle (fetched 2026-07-08). Requests carry JSON-RPC `id`.
14. **Pino** — "Super fast, all natural JSON logger for Node.js," with built-in `redact` paths for structured secret field removal. https://getpino.io/#/docs/redaction (fetched 2026-07-08).
15. **Teleport** (Gravitational) — RBAC roles, host labels/selectors, access requests (JIT), session recording. https://goteleport.com/docs/access-controls/ (overview page; fetched 2026-07-08).
16. **HashiCorp Boundary** — host sets/catalogs, privileged access management, time-bounded credentials. https://developer.hashicorp.com/boundary/docs/concepts/ (fetched 2026-07-08; permissions concept page).
17. **PR #56 — "feat: add redacted command audit log"**, `tufantunc/ssh-mcp`. Adds `src/audit/{store,redactor,rotator,types}.ts`, JSONL with rotation + input-field redaction; stack note lists `pr/approval-engine`, `pr/per-source-approval`, `pr/webui-manual-approval`, etc. (GitHub PR data fetched 2026-07-08 via `gh`.)
18. **Issue #23 — "Be able to differentiate read-only MCP commands"**, `tufantunc/ssh-mcp` (OPEN). Request for a read-only command surface. (Fetched 2026-07-08.)
19. **Issue #36 — "Add readOnlyHint annotation to enable parallel tool calls"**, `tufantunc/ssh-mcp` (OPEN). Notes MCP `readOnlyHint` is a *hint*; "Clients should never make tool use decisions based on ToolAnnotations." (Fetched 2026-07-08.)
20. **NIST SP 800-92** — Kent & Souppaya, *Guide to Computer Security Log Management*, NIST, 2010 (SP 800-92). https://csrc.nist.gov/pubs/sp/800/92/upd1/final (identifier verified; canonical NIST CSRC publication). Guidance on centralization, clock sync, integrity protection, retention, sensitive-content redaction.
21. **NIST SP 800-53 Rev. 5** — AU family (AU-2 events, AU-3 content, AU-6 review, AU-9 protection, AU-11 retention). https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
22. **PCI DSS v4.0** — Requirement 10 (audit trails; ≥1yr online + 1yr offline retention). PCI Security Standards Council.
23. **ISO/IEC 27001:2022** — Annex A.12.4 (logging & monitoring), A.18.1.3 (protection of records). ISO.
24. **HIPAA Security Rule** — 45 CFR §164.312(b) (audit controls). U.S. HHS.
25. **SOC 2 (AICPA TSC 2017 with 2022 revisions)** — CC7.2 (system monitoring), CC8.1 (change management). AICPA.
26. **W3C Trace Context** — `traceparent`/`tracestate` propagation headers. https://www.w3.org/TR/trace-context/
27. **asciinema recording format v2** — JSONL header + `[time, "o"|"i", data]` events. https://docs.asciinema.org/manual/asciicast/v2/

---

*Brief prepared for synthesis into a published report. All technical-source URLs were live-fetched on 2026-07-08; regulatory items are cited by stable standard identifiers. Where a recommendation is opinionated (§E JIT, §J compliance-not-blocking, §L concrete plan), it is marked as such and grounded in the cited evidence.*
