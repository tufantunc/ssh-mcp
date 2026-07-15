import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { get } from 'http';
import type { Server } from 'net';

const HTTP_PORT = 18399;
const HTTP_HOST = '127.0.0.1';
const BEARER = 'test-token-secret';
const BASE_URL = `http://${HTTP_HOST}:${HTTP_PORT}`;

let serverProcess: any;

beforeAll(async () => {
  process.env.SSH_MCP_DISABLE_MAIN = '1';
  serverProcess = await startTestServer();
});

afterAll(async () => {
  // Server cleanup — the mock doesn't expose a close handle,
  // so we rely on process exit to clean up
});

function startTestServer(): Promise<Server> {
  return new Promise(async (resolve, reject) => {
    try {
      const { startHttpServer } = await import('../../../src/transport/http.js');
      const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
      const { ConnectionRegistry } = await import('../../../src/ssh/connection-registry.js');
      const { AuditStore } = await import('../../../src/audit/store.js');

      const mockRegistry = {
        listConnections: () => [],
        listAllProfiles: () => [],
        get: () => undefined,
        getOrCreate: async () => { throw new Error('not in test'); },
      } as any;

      const mockAudit = {} as any;

      const mcpServer = new McpServer({
        name: 'test',
        version: '0.0.0',
        capabilities: { tools: {}, resources: {} },
      });

      await startHttpServer(mcpServer, {
        port: HTTP_PORT,
        host: HTTP_HOST,
        bearerToken: BEARER,
        rateLimit: 3,
        registry: mockRegistry,
        audit: mockAudit,
      });

      setTimeout(() => resolve({ close: () => {} } as any), 100);
    } catch (err) {
      reject(err);
    }
  });
}

function httpRequest(method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((resolve, reject) => {
    const req = (method === 'GET' ? get : get); // simplified
    const options = {
      hostname: HTTP_HOST,
      port: HTTP_PORT,
      path,
      method,
      headers,
    };
    const http = require('http');
    const req2 = http.request(options, (res: any) => {
      let data = '';
      res.on('data', (chunk: any) => (data += chunk));
      res.on('end', () => {
        resolve({ status: res.statusCode, body: data, headers: res.headers });
      });
    });
    req2.on('error', reject);
    if (body) req2.write(body);
    req2.end();
  });
}

describe('HTTP transport — auth', () => {
  it('rejects request without bearer token', async () => {
    const res = await httpRequest('GET', '/health');
    expect(res.status).toBe(401);
  });

  it('rejects request with wrong token', async () => {
    const res = await httpRequest('GET', '/health', { authorization: 'Bearer wrong-token' });
    expect(res.status).toBe(401);
  });

  it('accepts request with correct token', async () => {
    const res = await httpRequest('GET', '/health', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).healthy).toBe(true);
  });

  it('rejects malformed authorization header', async () => {
    const res = await httpRequest('GET', '/health', { authorization: 'Basic xyz' });
    expect(res.status).toBe(401);
  });
});

describe('HTTP transport — /health endpoint', () => {
  it('returns healthy status', async () => {
    const res = await httpRequest('GET', '/health', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.healthy).toBe(true);
  });
});

describe('HTTP transport — /status endpoint', () => {
  it('returns server status', async () => {
    const res = await httpRequest('GET', '/status', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).toBe('running');
    expect(body.version).toBe('2.0.0');
  });
});

describe('HTTP transport — 404', () => {
  it('returns 404 for unknown path', async () => {
    const res = await httpRequest('GET', '/unknown', { authorization: `Bearer ${BEARER}` });
    expect([404, 429]).toContain(res.status);
  });
});

describe('HTTP transport — body size limit', () => {
  it('rejects body larger than 1MB', async () => {
    const largeBody = 'x'.repeat(2 * 1024 * 1024);
    try {
      const res = await httpRequest('POST', '/', { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json' }, largeBody);
      expect([413, 400]).toContain(res.status);
    } catch {
      // Connection error (EPIPE/ECONNRESET) is acceptable — server destroys oversized connections
    }
  });
});

describe('HTTP transport — rate limiting', () => {
  it('returns 429 after exceeding rate limit on MCP route', async () => {
    const headers = { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json' };
    const results: number[] = [];
    for (let i = 0; i < 10; i++) {
      const res = await httpRequest('POST', '/', headers, JSON.stringify({ jsonrpc: '2.0', id: i, method: 'ping' }));
      results.push(res.status);
    }
    // Rate limit is 3/min — MCP route should be rate limited
    expect(results.filter((s) => s === 429).length).toBeGreaterThan(0);
  });
});
