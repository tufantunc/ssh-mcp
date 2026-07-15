import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { randomUUID, timingSafeEqual } from 'crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { AuditStore } from '../audit/store.js';

const MAX_BODY_SIZE = 1_048_576; // 1MB

class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private maxTokens: number;
  private refillIntervalMs: number;

  constructor(maxRequestsPerMinute: number) {
    this.maxTokens = maxRequestsPerMinute;
    this.tokens = maxRequestsPerMinute;
    this.lastRefill = Date.now();
    this.refillIntervalMs = 60_000;
  }

  tryConsume(): { allowed: boolean; retryAfterMs: number } {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const refilled = Math.floor((elapsed / this.refillIntervalMs) * this.maxTokens);
    if (refilled > 0) {
      this.tokens = Math.min(this.maxTokens, this.tokens + refilled);
      this.lastRefill += Math.round((refilled / this.maxTokens) * this.refillIntervalMs);
    }

    if (this.tokens > 0) {
      this.tokens--;
      return { allowed: true, retryAfterMs: 0 };
    }

    const retryAfterMs = Math.ceil(this.refillIntervalMs / this.maxTokens);
    return { allowed: false, retryAfterMs };
  }
}

export interface HttpTransportOpts {
  port: number;
  host?: string;
  bearerToken?: string;
  registry: ConnectionRegistry;
  audit: AuditStore;
  rateLimit?: number;
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
  const rateLimiter = opts.rateLimit && opts.rateLimit > 0
    ? new RateLimiter(opts.rateLimit)
    : null;

  const mcpTransport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });
  await server.connect(mcpTransport);

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

    const clientKey = bearerToken;

    if (rateLimiter && (req.method === 'POST' || req.method === 'GET' || req.method === 'DELETE')) {
      const { allowed, retryAfterMs } = rateLimiter.tryConsume();
      if (!allowed) {
        const retryAfterSec = Math.ceil(retryAfterMs / 1000);
        res.writeHead(429, {
          'Content-Type': 'application/json',
          'Retry-After': String(retryAfterSec),
        });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          error: {
            code: -32604,
            message: `Rate limit exceeded. Retry after ${retryAfterSec}s.`,
          },
        }));
        return;
      }
    }

    if (req.method === 'POST' && url.pathname === '/') {
      let body = '';
      let bodyTooLarge = false;
      req.on('data', (chunk) => {
        body += chunk;
        if (body.length > MAX_BODY_SIZE) {
          if (!bodyTooLarge) {
            bodyTooLarge = true;
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Request body too large (max 1MB)' }));
          }
          req.destroy();
        }
      });
      req.on('end', async () => {
        if (bodyTooLarge) return;
        try {
          const parsed = JSON.parse(body);
          await mcpTransport.handleRequest(req, res, parsed);
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/') {
      await mcpTransport.handleRequest(req, res);
      return;
    }

    if (req.method === 'DELETE' && url.pathname === '/') {
      await mcpTransport.handleRequest(req, res);
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
    if (rateLimiter) {
      console.error(`Rate limit: ${opts.rateLimit} req/min`);
    }
  });
}
