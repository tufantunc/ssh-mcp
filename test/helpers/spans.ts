import type { AttributeValue, Span, Tracer } from '@opentelemetry/api';

/** A span as a test sees it: its name, the attributes set on it, and whether it ended. */
export interface RecordedSpan {
  name: string;
  attributes: Record<string, unknown>;
  ended: boolean;
}

/**
 * A tracer that records each span's name, attributes and end, for asserting what
 * production records — without the SDK registered, `trace.getTracer()` hands out spans
 * that keep nothing. Covers `startSpan`, `setAttribute` and `end`, the only span API src/
 * uses. Like the SDK it drops an attribute set after `end()` or with a null value, so a
 * test cannot pass on a value no exporter would see.
 */
export function recordingTracer(): { tracer: Tracer; spans: RecordedSpan[] } {
  const spans: RecordedSpan[] = [];
  const tracer = {
    startSpan(name: string): Span {
      const record: RecordedSpan = { name, attributes: {}, ended: false };
      spans.push(record);
      const span = {
        setAttribute(key: string, value: AttributeValue | null | undefined) {
          if (value != null && !record.ended) record.attributes[key] = value;
          return span;
        },
        end() { record.ended = true; },
      };
      return span as unknown as Span;
    },
  };
  return { tracer: tracer as unknown as Tracer, spans };
}
