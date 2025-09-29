import { describe, it, expect } from 'vitest';

describe('zod compatibility with MCP SDK', async () => {
  it('app zod schemas expose _parse expected by SDK (regression for issue #10)', async () => {
    const appZod = await import('zod');

    // Create a schema using our app's zod
    const schema: any = (appZod as any).string();

    // In zod v3, schemas have an internal _parse used by consumers like MCP SDK.
    // In zod v4, this internal differs, leading to `..._parse is not a function` at runtime.
    expect(typeof schema._parse).toBe('function');
  });
});


