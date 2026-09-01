import { describe, it, expect, vi, afterEach } from 'vitest';

/**
 * `initTracing` has to reach `sdk.start()`, and has to say so.
 *
 * The four OTEL packages it needs are loaded with dynamic `import()`, so a renamed
 * export is invisible to `tsc`. And the whole body sits inside a `try/catch` that
 * only calls `console.error`, so the failure is not a crash — tracing goes off, the
 * server carries on, and CI stays green. That is the failure mode every OTEL bump
 * carries, and nothing observed it before this file: the pnpm probe in
 * `test/e2e/packaging.e2e.test.ts` checks that the exports exist, which is the other
 * half, but never calls this function.
 *
 * No collector and no timers. `sdk.start()` does not connect — measured against a
 * discard port, `initTracing` reaches its success log in ~60ms — and
 * `BatchSpanProcessor`'s five-second flush is never awaited here. So this is a plain
 * unit test rather than the integration test the batching timer would have forced.
 */

const DISCARD = 'http://127.0.0.1:9';

/** Collect stderr for one `initTracing` call, on a freshly imported module. */
async function runInitTracing(endpoint = DISCARD, serviceName = 'test-service'): Promise<string> {
  // `initialized` is module-level, so without this the second call in a file is a
  // no-op and every test after the first would pass vacuously.
  vi.resetModules();
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map(String).join(' '));
  });
  try {
    const { initTracing } = await import('../../../src/observability/tracer.js');
    await initTracing(endpoint, serviceName);
  } finally {
    spy.mockRestore();
  }
  return lines.join('\n');
}

afterEach(() => {
  vi.doUnmock('@opentelemetry/sdk-node');
  vi.resetModules();
});

describe('initTracing', () => {
  it('starts the SDK and reports success', async () => {
    const stderr = await runInitTracing();

    // Both, and measured: either one alone already fails when an export is renamed,
    // so neither is load-bearing on its own. They are kept as a pair because they
    // fail differently — the first says success never happened, the second says a
    // failure was logged — and an edit that makes one vacuous leaves the other.
    expect(stderr).toContain('OpenTelemetry tracing enabled');
    expect(stderr).not.toContain('Failed to initialize');
  });

  it('reports the endpoint and service name it was given', async () => {
    const stderr = await runInitTracing('http://127.0.0.1:9', 'custom-name');

    expect(stderr).toContain('http://127.0.0.1:9');
    expect(stderr).toContain('custom-name');
  });

  it('takes the catch when a package it needs is not there', async () => {
    // The reason the imports are dynamic: OTEL is optional at runtime. A missing or
    // broken package must not stop the server, and must not be silent either.
    vi.resetModules();
    vi.doMock('@opentelemetry/sdk-node', () => {
      throw new Error('ERR_MODULE_NOT_FOUND: simulated');
    });

    const lines: string[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(' '));
    });
    try {
      const { initTracing } = await import('../../../src/observability/tracer.js');
      // Must resolve rather than reject: the caller in src/index.ts awaits this
      // during startup and does not catch.
      await expect(initTracing(DISCARD, 'svc')).resolves.toBeUndefined();
    } finally {
      spy.mockRestore();
    }

    const stderr = lines.join('\n');
    expect(stderr).toContain('Failed to initialize OpenTelemetry');
    expect(stderr).not.toContain('tracing enabled');
  });

  it('only initializes once', async () => {
    vi.resetModules();
    const lines: string[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(' '));
    });
    try {
      const { initTracing } = await import('../../../src/observability/tracer.js');
      await initTracing(DISCARD, 'first');
      await initTracing(DISCARD, 'second');
    } finally {
      spy.mockRestore();
    }

    expect(lines.filter((l) => l.includes('tracing enabled'))).toHaveLength(1);
    expect(lines.join('\n')).toContain('first');
    expect(lines.join('\n')).not.toContain('second');
  });
});
