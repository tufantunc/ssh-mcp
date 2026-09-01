---
"ssh-mcp": patch
---

Update OpenTelemetry to 0.221, and cover the path that made the bump worth checking.

`@opentelemetry/sdk-node` and `@opentelemetry/exporter-trace-otlp-http` go from `^0.220.0` to `^0.221.0`. **`@opentelemetry/resources` follows to 2.10.0** — it is a direct dependency under an unpinned `^2.9.0`, and `resourceFromAttributes` comes from it, so it is on the path this change is about. `@opentelemetry/core`, `context-async-hooks`, `sdk-trace-base` and `api-logs` move to 2.10.0/0.221.0 alongside. The lockfile churn is larger than the version numbers suggest because 0.221 restructured its own dependency declarations; no package name is new, every entry still resolves to `registry.npmjs.org` with a `sha512` integrity, and `npm audit --omit=dev` reports nothing.

`patch` because nothing a consumer can observe changes. Tracing is off unless `--otelEndpoint` is set, and the package exposes no importable surface at all — `package.json` declares `bin` and `files` with no `main`, `exports` or `types` — so no OpenTelemetry type can reach a dependent.

**What made this worth checking.** `initTracing` loads all four packages with dynamic `import()` and wraps the body in a `try/catch` that only calls `console.error`. A renamed export is therefore invisible to `tsc`, and the failure is not a crash: tracing goes off, the server keeps serving, and CI stays green.

That path is now covered rather than described. A unit test calls `initTracing` against a discard port — no collector and no timers are needed, since `sdk.start()` does not connect — and asserts it reaches the success log, that a missing package still resolves through the catch without rejecting, and that it initialises once. Renaming `NodeSDK` in the source fails it. The existing strict-resolution probe in `test/e2e/packaging.e2e.test.ts` already guarded named exports for `resources` and `semantic-conventions`; it now guards `NodeSDK` and `OTLPTraceExporter` too, which were the two packages this bump actually moved.

Behaviour is unchanged where tracing is on. The decoded OTLP body is structurally identical across the two versions — same resource attribute keys, scope name, span fields and attribute value types — and the only difference on the wire is the exporter's own `User-Agent` version string. `NodeSDK` loads no default instrumentation on either version, so nothing new is collected or sent.
