---
"ssh-mcp": patch
---

Update OpenTelemetry to 0.222: `@opentelemetry/sdk-node` and `@opentelemetry/exporter-trace-otlp-http` go from `^0.221.0` to `^0.222.0`, the only part of this bump that changes what `npm i ssh-mcp` resolves, since a caret on a 0.x version does not reach the next minor. The lockfile also moves `@modelcontextprotocol/sdk` to 1.30.1, `@opentelemetry/resources` to 2.11.0, `smol-toml` to 1.9.0 and `zod` to 4.6.5, all inside ranges this package already declared. `npm audit --omit=dev` reports nothing.
