---
"ssh-mcp": patch
---

Update OpenTelemetry to 0.221 (`@opentelemetry/sdk-node`, `@opentelemetry/exporter-trace-otlp-http`; `@opentelemetry/core` and the `otlp-*` transitives follow to 2.10.0 / 0.221.0).

`patch` because nothing a consumer can observe changes. Tracing is off unless `--otelEndpoint` is set, and where it is on, the behaviour was measured identical: all four dynamic imports in `initTracing` resolve, `sdk.start()` succeeds, and a real span reaches a local collector with a byte-identical payload on both versions.

The reason this needed measuring rather than merging is `src/observability/tracer.ts`: the whole of `initTracing` sits inside a `try/catch` that only logs, so a renamed export in any of those four packages would have turned tracing off silently while the server carried on. Nothing in the test suite covers that path. The absent-package fallback the dynamic imports exist for was checked too — with the packages removed, `initTracing` takes the catch and the server still starts and serves all eleven tools.
