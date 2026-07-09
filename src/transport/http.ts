import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { randomUUID, timingSafeEqual } from 'crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { AuditStore } from '../audit/store.js';

export interface HttpTransportOpts {
  port: number;
  host?: string;
  bearerToken?: string;
  registry: ConnectionRegistry;
  audit: AuditStore;
}

export async function startHttpServer(
  server: McpServer,
  opts: HttpTransportOpts,
): Promise<void> {
  const { port, host = '127.0.0.1', bearerToken, registry, audit } = opts;

  if (!bearerToken) {
    throw new Error(
      'HTTP transport requires --bearerToken. Example: --transport=http --bearerToken=secret\n' +
      'Without authentication, any network client can execute SSH commands on your hosts.',
    );
  }

  const tokenBuf = Buffer.from(bearerToken);

  const httpServer = createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host}`);

    {
      const auth = req.headers.authorization || '';
      const expected = `Bearer ${bearerToken}`;
      const authBuf = Buffer.from(auth);
      const expectedBuf = Buffer.from(expected);
      const match = authBuf.length === expectedBuf.length &&
        timingSafeEqual(authBuf, expectedBuf);
      if (!match) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
    }

    if (req.method === 'POST' && url.pathname === '/') {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });
      await server.connect(transport);
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          const parsed = JSON.parse(body);
          await transport.handleRequest(req, res, parsed);
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/') {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    if (req.method === 'DELETE' && url.pathname === '/') {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'running',
        version: '2.0.0',
        connections: registry.listConnections(),
        profiles: registry.listAllProfiles().map((p) => ({
          name: p.name,
          host: p.host,
          user: p.user,
          role: p.role,
          readOnly: p.readOnly,
        })),
      }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ healthy: true }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  httpServer.listen(port, host, () => {
    console.error(`SSH MCP Server v2 (HTTP) listening on http://${host}:${port}`);
    console.error('Endpoints: POST / (MCP), GET /status, GET /health');
    if (!bearerToken) {
      console.error('WARNING: No bearer token set. Set --bearerToken to enable authentication.');
    }
  });
}
