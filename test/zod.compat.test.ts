import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createRequire } from 'module';
import { realpathSync } from 'fs';
import { resolve } from 'path';

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
 * JSON Schema with our field names on it, and validate arguments.
 *
 * Note what this first test does *not* catch, because the earlier draft of this file
 * claimed it did: two zod copies in the tree. Planting a nested zod 3 under the SDK
 * and running this leaves it green — the SDK's compat layer makes mixed copies work
 * at run time, and the failure an unconstrained `zod-to-json-schema` override
 * actually produced was a `tsc` error, which no vitest test can raise. The second
 * test below is what covers that, by comparing resolution rather than behaviour.
 *
 * Deliberately built on a throwaway schema rather than the real eleven tools, so
 * adding a tool or editing a description never touches it.
 */
describe('zod compatibility with the MCP SDK', () => {
  it('registers a schema from our zod and serves it as JSON Schema', async () => {
    const server = new McpServer({ name: 'zod-compat', version: '0.0.0' }, { capabilities: { tools: {} } });
    let seen: unknown;

    server.tool(
      'probe',
      'A throwaway tool that exists only to exercise schema conversion.',
      {
        required: z.string().describe('a required string'),
        optional: z.number().optional().describe('an optional number'),
      },
      async (args) => {
        seen = args;
        return { content: [{ type: 'text' as const, text: `got ${args.required}` }] };
      },
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

      // The two client-visible facts the changeset states about this upgrade, pinned
      // here because nothing else covered them. zod 3 emitted
      // `additionalProperties: false`; zod 4 emits nothing, while the runtime keeps
      // stripping the extra argument either way — so the advertised contract loosened
      // and the actual behaviour did not. If a future bump starts advertising `true`,
      // or lets an undeclared argument reach a handler, that is a change clients see.
      expect(probe!.inputSchema.additionalProperties).toBeUndefined();

      const extra: any = await client.callTool({ name: 'probe', arguments: { required: 'hi', bogus: 1 } });
      expect(extra.isError).toBeFalsy();
      expect(seen, 'an undeclared argument reached the handler').toEqual({ required: 'hi' });

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

  it('resolves exactly one zod in the production tree', () => {
    // Resolution, not liveness. The previous version of this test imported both
    // packages and asserted `typeof z.string === 'function'` — which is true of any
    // zod, and true with two of them: planting zod 3 at
    // `node_modules/@modelcontextprotocol/sdk/node_modules/zod` left it passing while
    // naming the one property it was supposed to protect.
    //
    // `realpathSync` because a workspace or a linked install can reach the same
    // package through two paths without it being two copies.
    const projectRequire = createRequire(resolve(import.meta.dirname, '../package.json'));
    const sdkRequire = createRequire(projectRequire.resolve('@modelcontextprotocol/sdk/server/mcp.js'));

    const ours = realpathSync(projectRequire.resolve('zod/package.json'));
    const theirs = realpathSync(sdkRequire.resolve('zod/package.json'));

    expect(theirs, `the SDK resolves a different zod than we do:\n  ours:   ${ours}\n  theirs: ${theirs}`)
      .toBe(ours);
  });
});
