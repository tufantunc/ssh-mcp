import type { Span, Tracer } from '@opentelemetry/api';

/** A span as a test sees it: its name, the attributes set on it, and whether it ended. */
export interface RecordedSpan {
  name: string;
  attributes: Record<string, unknown>;
  ended: boolean;
}

/**
 * A tracer that keeps every span it starts, for asserting what production records.
 *
 * Without the OpenTelemetry SDK registered, `trace.getTracer()` hands out no-op spans that
 * keep nothing, so an attribute like `ssh.unstopped` could be deleted without a test
 * noticing — measured, removing both of its `setAttribute` calls kept the suite green.
 * Covers the span methods src/ssh/connection.ts calls: `setAttribute` and `end`. An
 * attribute set after `end()` is dropped, as the real SDK drops it, so a test cannot pass
 * on a value no exporter would ever see.
 */
export function recordingTracer(): { tracer: Tracer; spans: RecordedSpan[] } {
  const spans: RecordedSpan[] = [];
  const tracer = {
    startSpan(name: string): Span {
      const record: RecordedSpan = { name, attributes: {}, ended: false };
      spans.push(record);
      const span = {
        setAttribute(key: string, value: unknown) {
          if (!record.ended) record.attributes[key] = value;
          return span;
        },
        end() { record.ended = true; },
      };
      return span as unknown as Span;
    },
  };
  return { tracer: tracer as unknown as Tracer, spans };
}
