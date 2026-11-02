---
"ssh-mcp": patch
---

Update OpenTelemetry to 0.300: `@opentelemetry/sdk-node` and `@opentelemetry/exporter-trace-otlp-http` go from `^0.223.0` to `^0.300.0`, and `@opentelemetry/resources` from `^2.9.0` to `^3.0.0` — a coordinated major, since sdk-node 0.300 depends on resources 3.0.0 exactly. These are the parts of this bump that change what `npm i ssh-mcp` resolves, because a caret on a 0.x version does not reach the next minor; the tree resolves `@opentelemetry/api` to 1.10.0 (was 1.9.1). Regenerating the lockfile also carries declared ranges forward: `@modelcontextprotocol/sdk` to 1.32.2, `@napi-rs/keyring` to 2.1.2, `@types/node` to 26.6.6, and the prod tree's transitive dependencies (express 5.3.0, hono 4.13.16, `@hono/node-server` 2.1.5 — past GHSA-rmxm-3fg6-px4f) within ranges this package or its dependencies already declared. `npm audit --omit=dev` reports nothing.
