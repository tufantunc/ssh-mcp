import { describe, it, expect } from 'vitest';

describe('zod compatibility with MCP SDK', async () => {
  it('app zod v3 compatibility schemas expose _parse expected by SDK (regression for issue #10)', async () => {
    const appZod = await import('zod/v3');

    // Create a schema using the v3 compatibility layer used by the app.
    const schema: any = (appZod as any).string();

    // The app intentionally imports from zod/v3 so the schema shape stays compatible
    // with consumers that still rely on the v3 internals.
    expect(typeof schema._parse).toBe('function');
  });
});

