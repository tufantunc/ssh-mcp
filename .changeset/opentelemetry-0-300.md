---
"ssh-mcp": patch
---

Update OpenTelemetry to 0.300: `@opentelemetry/sdk-node` and `@opentelemetry/exporter-trace-otlp-http` go from `^0.223.0` to `^0.300.0`, and `@opentelemetry/resources` from `^2.9.0` to `^3.0.0` — a coordinated major, since sdk-node 0.300 depends on resources 3.0.0 exactly. These are the parts of this bump that change what `npm i ssh-mcp` resolves, because a caret on a 0.x version does not reach the next minor; the tree resolves `@opentelemetry/api` to 1.10.0 (was 1.9.1). The lockfile also moves `@modelcontextprotocol/sdk` to 1.32.2 and `@napi-rs/keyring` to 2.1.2, both inside ranges this package already declared, and `@hono/node-server` to 2.1.5, past GHSA-rmxm-3fg6-px4f — `npm audit --omit=dev` reports nothing.
