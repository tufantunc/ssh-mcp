import { trace, type Tracer, type Span } from '@opentelemetry/api';

let initialized = false;

const tracer: Tracer = trace.getTracer('ssh-mcp');

export { tracer };

export async function initTracing(endpoint: string, serviceName: string): Promise<void> {
  if (initialized) return;
  initialized = true;

  try {
    const { NodeSDK } = await import('@opentelemetry/sdk-node');
    const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-http');
    const { resourceFromAttributes } = await import('@opentelemetry/resources');
    const { ATTR_SERVICE_NAME } = await import('@opentelemetry/semantic-conventions');

    const exporter = new OTLPTraceExporter({ url: `${endpoint}/v1/traces` });
    const sdk = new NodeSDK({
      resource: resourceFromAttributes({
        [ATTR_SERVICE_NAME]: serviceName,
      }),
      traceExporter: exporter,
    });

    await sdk.start();
    console.error(`OpenTelemetry tracing enabled: ${endpoint} (service: ${serviceName})`);
  } catch (err) {
    console.error('Failed to initialize OpenTelemetry:', err);
  }
}
