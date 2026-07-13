# OTEL Tracing — Design Spec

**Date:** 2026-07-11
**Status:** Approved
**Goal:** Enterprise-grade observability via OpenTelemetry distributed tracing. Every layer (policy → SSH → session → audit → redaction) emits spans with attributes, correlatable via MCP requestId.

---

## Architecture

### Dependency strategy

`@opentelemetry/api`, `@opentelemetry/sdk-node`, `@opentelemetry/exporter-trace-otlp-http` are regular `dependencies`. OTEL packages add ~34MB to node_modules. This is acceptable for a standalone CLI tool — no version conflict risk since it runs in its own process.

### Module structure

One new file: `src/observability/tracer.ts`

Exports:
- `tracer` — the OpenTelemetry tracer instance (from `@opentelemetry/api`). Returns NoopSpan when tracing disabled.
- `initTracing(endpoint: string, serviceName: string)` — configures `NodeSDK` with `OTLPTraceExporter` pointing at endpoint. Called once at startup when `--otelEndpoint` is set.

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--otelEndpoint` | undefined | OTLP HTTP endpoint (e.g., `http://collector:4318`). Omitted = tracing disabled. |
| `--otelServiceName` | `ssh-mcp` | Service name in tracing backend |

### Startup flow (index.ts)

```typescript
if (argv.otelEndpoint) {
  const { initTracing } = await import('./observability/tracer.js');
  initTracing(argv.otelEndpoint as string, (argv.otelServiceName as string) || 'ssh-mcp');
}
```

When `--otelEndpoint` is not set: dynamic import never fires, SDK never loads, all `tracer.startSpan()` calls return NoopSpan — zero overhead.

## Spans

6 span types across 5 layers. Every span follows the same pattern:

```typescript
const span = tracer.startSpan('span.name');
span.setAttribute('key', value);
try {
  // existing code
  span.setAttribute('result.key', resultValue);
} finally {
  span.end();
}
```

### 1. `tool.{name}` — root span

**Location:** `src/tools/registry.ts` — wrapping each tool handler
**Duration:** handler start → handler return
**Attributes:**
- `mcp.requestId` (number)
- `tool.name` (string: read-command, run-command, etc.)
- `ssh.profile` (string)

### 2. `policy.evaluate`

**Location:** `src/tools/registry.ts` — inside `checkPolicyAndApprove()`
**Duration:** policy.evaluate → result
**Attributes:**
- `policy.decision` (string: allow/deny/require-approval)
- `command.class` (string: read-only/safe/destructive/privileged)
- `command.binary` (string)

### 3. `ssh.exec`

**Location:** `src/ssh/connection.ts` — inside `exec()`
**Duration:** stream open → stream close
**Attributes:**
- `ssh.host` (string)
- `ssh.port` (number)
- `ssh.command` (string — always passed through `redactText()` first)
- `ssh.exitCode` (number, set on close)
- `ssh.signal` (string, set if killed by signal)

### 4. `ssh.session.run`

**Location:** `src/ssh/session.ts` — inside `InteractiveSession.run()`
**Duration:** command write → sentinel match
**Attributes:**
- `session.id` (string)
- `session.name` (string)
- `ssh.exitCode` (number, set on completion)

### 5. `audit.record`

**Location:** `src/audit/store.ts` — inside `record()`
**Duration:** write start → write complete
**Attributes:**
- `audit.bytes` (number — JSON line byte count)
- `audit.tamperEvident` (boolean)

### 6. `guard.redact`

**Location:** `src/guard/redactor.ts` — inside `redactText()`
**Duration:** redaction pass
**Attributes:**
- `redact.input.length` (number)
- `redact.output.length` (number)
- `redact.entropy.enabled` (boolean)

## Redaction

Span attributes that contain command text are ALWAYS passed through `redactText()` before being set as attributes. This prevents secrets from leaking into the tracing backend (Jaeger/Tempo/Datadog).

## Exporter

Only OTLP HTTP (`@opentelemetry/exporter-trace-otlp-http`). Compatible with Jaeger, Tempo, Datadog, Grafana, Honeycomb, Lightstep — all major backends accept OTLP in 2026.

## Files

| File | Change |
|------|--------|
| `src/observability/tracer.ts` | **NEW** — tracer instance + initTracing() |
| `src/index.ts` | CLI flag parsing + initTracing() call |
| `src/tools/registry.ts` | tool.{name} + policy.evaluate spans |
| `src/ssh/connection.ts` | ssh.exec span |
| `src/ssh/session.ts` | ssh.session.run span |
| `src/audit/store.ts` | audit.record span |
| `src/guard/redactor.ts` | guard.redact span |
| `package.json` | 3 new dependencies |
