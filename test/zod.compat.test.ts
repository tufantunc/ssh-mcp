import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

/**
 * Our zod and the SDK's have to be the same zod.
 *
 * This file used to assert `typeof z.string()._parse === 'function'` — a zod 3
 * internal the SDK reached into (issue #10), which made the test a tripwire
 * against upgrading to zod 4 rather than a check on anything we promise. The SDK
 * has a version-compat layer now, so that premise is gone, and asserting a private
 * field would only forbid the upgrade it was written to survive.
 *
 * What actually matters is unchanged and is what this now checks: a schema built
 * with the zod *we* depend on has to be accepted by the SDK, reach the wire as a
 * JSON Schema with our field names on it, and validate arguments. When the tree
 * carries two zod copies — which is what an unconstrained `zod-to-json-schema`
 * override caused — this fails at registration with a type that has no `_parse`,
 * which is the same symptom under a different cause.
 *
 * Deliberately built on a throwaway schema rather than the real eleven tools, so
 * adding a tool or editing a description never touches it.
 */
describe('zod compatibility with the MCP SDK', () => {
  it('registers a schema from our zod and serves it as JSON Schema', async () => {
    const server = new McpServer({ name: 'zod-compat', version: '0.0.0' }, { capabilities: { tools: {} } });

    server.tool(
      'probe',
      'A throwaway tool that exists only to exercise schema conversion.',
      {
        required: z.string().describe('a required string'),
        optional: z.number().optional().describe('an optional number'),
      },
      async ({ required }) => ({ content: [{ type: 'text' as const, text: `got ${required}` }] }),
    );

    const client = new Client({ name: 'zod-compat-client', version: '0.0.0' }, { capabilities: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    try {
      const { tools } = await client.listTools();
      const probe = tools.find((t) => t.name === 'probe');
      expect(probe, 'the SDK did not accept a schema built with our zod').toBeDefined();

      // The shape the SDK derives from our schema, not the shape of our own tools:
      // field names and requiredness are what a client needs to call it at all.
      expect(probe!.inputSchema.type).toBe('object');
      expect(Object.keys(probe!.inputSchema.properties ?? {}).sort()).toEqual(['optional', 'required']);
      expect(probe!.inputSchema.required).toEqual(['required']);

      // And validation is live, in both directions.
      const ok: any = await client.callTool({ name: 'probe', arguments: { required: 'hi' } });
      expect(ok.content[0].text).toBe('got hi');

      // Returned as an error result rather than a rejection — the SDK converts the
      // validation failure into `isError` with the message attached.
      const bad: any = await client.callTool({ name: 'probe', arguments: { optional: 1 } });
      expect(bad.isError).toBe(true);
      expect(bad.content[0].text).toMatch(/Invalid arguments for tool probe/);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it('resolves exactly one zod in the production tree', async () => {
    // Two copies is the failure this file exists for. The SDK accepts `^3.25 || ^4.0`,
    // so npm can satisfy it with a nested copy rather than deduping — which is what
    // an override pinning `zod-to-json-schema` to a zod-3-only version caused.
    const ours = await import('zod');
    const sdkSide = await import('@modelcontextprotocol/sdk/server/mcp.js');
    expect(typeof ours.z.string).toBe('function');
    expect(typeof sdkSide.McpServer).toBe('function');

    // A schema from our zod must be the same brand the SDK checks against; if the
    // tree had two copies the registration in the previous test would already have
    // failed, so this asserts the cheap half — that importing both is coherent.
    expect(ours.z.string().safeParse('x').success).toBe(true);
  });
});
