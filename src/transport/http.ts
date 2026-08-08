import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { randomUUID, timingSafeEqual } from 'crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import { SERVER_VERSION } from '../version.js';

const MAX_BODY_SIZE = 1_048_576; // 1MB
/** Cap on concurrent MCP sessions, so unauthenticated-adjacent churn can't grow the map without bound. */
const MAX_SESSIONS = 64;

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
  rateLimit?: number;
}

function jsonRpcError(res: ServerResponse, status: number, code: number, message: string): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }));
}

/**
 * @param createMcpServer Builds a fresh McpServer per MCP session. An McpServer
 *   binds to exactly one transport, so a shared instance would let only the
 *   first client initialize — and would stay unusable after that client left.
 */
export async function startHttpServer(
  createMcpServer: () => McpServer | Promise<McpServer>,
  opts: HttpTransportOpts,
): Promise<void> {
  const { port, host = '127.0.0.1', bearerToken, registry } = opts;

  if (!bearerToken) {
    throw new Error(
      'HTTP transport requires --bearerToken. Example: --transport=http --bearerToken=secret\n' +
      'Without authentication, any network client can execute SSH commands on your hosts.',
    );
  }

  const rateLimiter = opts.rateLimit && opts.rateLimit > 0
    ? new RateLimiter(opts.rateLimit)
    : null;

  const transports = new Map<string, StreamableHTTPServerTransport>();

  /** Route to the session's transport, or start a new session on `initialize`. */
  async function resolveTransport(
    req: IncomingMessage,
    res: ServerResponse,
    parsedBody?: unknown,
  ): Promise<StreamableHTTPServerTransport | null> {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;

    if (sessionId) {
      const existing = transports.get(sessionId);
      if (existing) return existing;
      jsonRpcError(res, 404, -32001, 'Session not found or expired. Re-initialize to obtain a new session.');
      return null;
    }

    const body = Array.isArray(parsedBody) ? parsedBody : [parsedBody];
    if (!body.some((m) => isInitializeRequest(m))) {
      jsonRpcError(res, 400, -32000, 'Missing mcp-session-id header. Send an initialize request first.');
      return null;
    }

    if (transports.size >= MAX_SESSIONS) {
      jsonRpcError(res, 503, -32000, `Server is at its session limit (${MAX_SESSIONS}). Close an existing session and retry.`);
      return null;
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => { transports.set(id, transport); },
      onsessionclosed: (id) => { transports.delete(id); },
    });
    // Covers transport teardown that isn't a DELETE (client disconnect, error).
    transport.onclose = () => {
      if (transport.sessionId) transports.delete(transport.sessionId);
    };

    const mcp = await createMcpServer();
    await mcp.connect(transport);
    return transport;
  }

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

    if (rateLimiter && url.pathname === '/' && (req.method === 'POST' || req.method === 'GET' || req.method === 'DELETE')) {
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
            // Connection: close is load-bearing, not cosmetic. Without it a
            // keep-alive client (Node's default agent since v19) returns this
            // socket to its pool, and the destroy below then kills the pooled
            // socket — so the client's *next* request fails with EPIPE.
            res.writeHead(413, {
              'Content-Type': 'application/json',
              'Connection': 'close',
            });
            // Destroy only once the 413 has flushed; destroying immediately
            // races the response and the client sees a bare connection reset
            // instead of the status telling it what went wrong.
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                error: { code: -32600, message: 'Request body too large (max 1MB)' },
                id: null,
              }),
              () => req.destroy(),
            );
          }
        }
      });
      req.on('end', async () => {
        if (bodyTooLarge) return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(body);
        } catch {
          jsonRpcError(res, 400, -32700, 'Parse error: invalid JSON');
          return;
        }
        const transport = await resolveTransport(req, res, parsed);
        if (!transport) return;
        await transport.handleRequest(req, res, parsed);
      });
      return;
    }

    if ((req.method === 'GET' || req.method === 'DELETE') && url.pathname === '/') {
      const transport = await resolveTransport(req, res);
      if (!transport) return;
      await transport.handleRequest(req, res);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'running',
        version: SERVER_VERSION,
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
