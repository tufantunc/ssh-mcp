import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import * as httpModule from 'http';
import { clientKey } from '../../../src/transport/http.js';
import type { Server } from 'net';

const HTTP_PORT = 18399;
const HTTP_HOST = '127.0.0.1';
const BEARER = 'test-token-secret';

beforeAll(async () => {
  process.env.SSH_MCP_DISABLE_MAIN = '1';
  await startTestServer();
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

      const mockRegistry = {
        listConnections: () => [],
        listAllProfiles: () => [],
        get: () => undefined,
        getOrCreate: async () => { throw new Error('not in test'); },
      } as any;

      const mcpServer = new McpServer(
        { name: 'test', version: '0.0.0' },
        { capabilities: { tools: {}, resources: {} } },
      );

      await startHttpServer(() => mcpServer, {
        port: HTTP_PORT,
        host: HTTP_HOST,
        bearerToken: BEARER,
        rateLimit: 3,
        // Off on this server. The auth block below makes three failed attempts, and every
        // request in this file comes from 127.0.0.1, so one shared failure budget would
        // couple them: add a fourth 401 case and "accepts request with correct token"
        // starts answering 429 for a reason nobody reading it would guess. The limiter has
        // its own server at the bottom of the file.
        authFailureLimit: 0,
        registry: mockRegistry,
      });

      setTimeout(() => resolve({ close: () => {} } as any), 100);
    } catch (err) {
      reject(err);
    }
  });
}

function httpRequest(method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: HTTP_HOST,
      port: HTTP_PORT,
      path,
      method,
      headers,
      // Fresh socket per request: keep-alive pooling makes these tests
      // order-coupled, since a socket the server destroys stays in the pool.
      agent: false as const,
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
    const res = await httpRequest('GET', '/status');
    expect(res.status).toBe(401);
    // RFC 7235: a 401 has to tell the client how to authenticate.
    expect(res.headers['www-authenticate']).toMatch(/Bearer/);
    // Same JSON-RPC dialect as the 413/429 on this server.
    expect(JSON.parse(res.body).error.message).toBe('Unauthorized');
  });

  it('rejects request with wrong token', async () => {
    const res = await httpRequest('GET', '/status', { authorization: 'Bearer wrong-token' });
    expect(res.status).toBe(401);
  });

  it('accepts request with correct token', async () => {
    const res = await httpRequest('GET', '/status', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(200);
  });

  it('rejects malformed authorization header', async () => {
    const res = await httpRequest('GET', '/status', { authorization: 'Basic xyz' });
    expect(res.status).toBe(401);
  });

  // Load balancers probe /health unauthenticated, and it reveals nothing
  // beyond "the process is up".
  it('serves /health without authentication', async () => {
    const res = await httpRequest('GET', '/health');
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).healthy).toBe(true);
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
    // Version comes from package.json — no hardcoded literal to drift.
    const { SERVER_VERSION } = await import('../../../src/version.js');
    expect(body.version).toBe(SERVER_VERSION);
  });
});

describe('HTTP transport — 404', () => {
  it('returns 404 for unknown path', async () => {
    const res = await httpRequest('GET', '/unknown', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(404);
  });
});

describe('HTTP transport — body size limit', () => {
  // The 413 must actually arrive before the socket dies, and must announce
  // Connection: close so a keep-alive client discards the socket instead of
  // pooling one the server is about to destroy (that poisoned the next test).
  it('rejects body larger than 1MB with a 413 and closes the connection', async () => {
    // Just over the cap: large enough to trip the limit, small enough that the
    // client finishes writing before the server answers, so the assertion is
    // about the 413 rather than about upload timing.
    const largeBody = 'x'.repeat(1024 * 1024 + 1024);
    const res = await httpRequest(
      'POST',
      '/',
      { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json' },
      largeBody,
    );
    expect(res.status).toBe(413);
    expect(res.headers.connection).toBe('close');
    expect(JSON.parse(res.body).error.message).toMatch(/too large/i);
  });
});

describe('HTTP transport — sessions', () => {
  const headers = { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' };

  it('rejects a non-initialize POST that carries no session id', async () => {
    const res = await httpRequest('POST', '/', headers, JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }));
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.message).toMatch(/mcp-session-id/i);
  });

  it('rejects an unknown session id instead of silently starting a new one', async () => {
    const res = await httpRequest(
      'POST',
      '/',
      { ...headers, 'mcp-session-id': 'does-not-exist' },
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
    );
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body).error.message).toMatch(/session not found/i);
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
    // Rate limit is 3/min and the bucket is shared with earlier tests in this
    // file, so assert the shape rather than an exact split: throttling kicks in
    // and, once it does, it stays on for the rest of the burst.
    const firstThrottled = results.indexOf(429);
    expect(firstThrottled).toBeGreaterThanOrEqual(0);
    expect(results.slice(firstThrottled).every((s) => s === 429)).toBe(true);
    expect(results.filter((s) => s === 429).length).toBeGreaterThanOrEqual(7);
  });
});

function bareRequest(
  port: number,
  path: string,
  headers: Record<string, string> = {},
): Promise<{
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}> {
  return new Promise((resolve, reject) => {
    const req = httpModule.request(
      { hostname: HTTP_HOST, port, path, method: 'GET', headers, agent: false as const },
      (res) => {
        // Accumulated rather than discarded: both limiters answer 429 with the same
        // JSON-RPC code, so a status-only assertion cannot tell them apart.
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode || 0, headers: res.headers, body }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/**
 * F9: the auth check returned before the rate limiter was reached, so a wrong bearer token
 * consumed nothing and guessing ran at network speed — twelve 401s and zero 429s against
 * `--rateLimit=3`, measured. Its own server, because the budget is keyed by client address
 * and every request in this file shares one.
 */
describe('HTTP transport — failed authentication is throttled', () => {
  const PORT = 18402;
  const LIMIT = 3;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [],
      listAllProfiles: () => [],
      get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: 18402,
      host: HTTP_HOST,
      bearerToken: BEARER,
      authFailureLimit: 3,
      registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  const attempt = (token: string) =>
    bareRequest(PORT, '/status', { authorization: `Bearer ${token}` });

  it('spends the budget on failures and then answers 429', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < LIMIT + 3; i++) statuses.push((await attempt('wrong-guess')).status);

    expect(statuses.slice(0, LIMIT)).toEqual(Array(LIMIT).fill(401));
    expect(statuses.slice(LIMIT).every((s) => s === 429)).toBe(true);
  });

  it('says how long to wait', async () => {
    const res = await attempt('still-wrong');
    expect(res.status).toBe(429);
    // 60s / LIMIT — the interval one token takes to come back.
    expect(Number(res.headers['retry-after'])).toBe(Math.ceil(60 / LIMIT));
  });

  it('makes a correct token wait too, once the budget is spent', async () => {
    // Deliberate, and the reason the budget is checked before the token is compared:
    // gating only the 401 path would still evaluate the guess and still serve a correct
    // token, so the status code would tell an attacker which guess was right.
    expect((await attempt(BEARER)).status).toBe(429);
  });

  it('leaves the unauthenticated liveness probe alone', async () => {
    expect((await bareRequest(PORT, '/health')).status).toBe(200);
  });
});

/** The escape hatch, for a deployment that wants the previous behaviour back. */
describe('HTTP transport — the failure limit can be turned off', () => {
  const PORT = 18403;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [],
      listAllProfiles: () => [],
      get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: 18403,
      host: HTTP_HOST,
      bearerToken: BEARER,
      authFailureLimit: 0,
      registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  it('answers 401 for every attempt when the limit is 0', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) {
      statuses.push((await bareRequest(PORT, '/status', { authorization: 'Bearer wrong' })).status);
    }
    expect(statuses.every((s) => s === 401)).toBe(true);
  });
});

/** The default is the security property, so it is asserted rather than assumed. */
describe('HTTP transport — the failure limit is on without being asked for', () => {
  const PORT = 18404;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [],
      listAllProfiles: () => [],
      get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: 18404,
      host: HTTP_HOST,
      bearerToken: BEARER,
      // No authFailureLimit: the default is what is under test.
      registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  it('throttles after the default number of failures', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 14; i++) {
      statuses.push((await bareRequest(PORT, '/status', { authorization: 'Bearer wrong' })).status);
    }
    const firstThrottled = statuses.indexOf(429);
    expect(firstThrottled).toBeGreaterThan(0);
    expect(statuses.slice(0, firstThrottled).every((x) => x === 401)).toBe(true);
    expect(statuses.slice(firstThrottled).every((x) => x === 429)).toBe(true);
  });
});

/**
 * The budget is per client, and which client is a decision rather than a lookup:
 * `X-Forwarded-For` is read only when a proxy is trusted, because a client that can set
 * that header could otherwise pick its own key and opt out of the limit.
 */
describe('HTTP transport — the budget is keyed by client', () => {
  const TRUSTING = 18405;
  const PLAIN = 18406;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [],
      listAllProfiles: () => [],
      get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: 18405,
      host: HTTP_HOST,
      bearerToken: BEARER,
      authFailureLimit: 2,
      trustProxy: true,
      registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [],
      listAllProfiles: () => [],
      get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: 18406,
      host: HTTP_HOST,
      bearerToken: BEARER,
      authFailureLimit: 2,
      registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  const fail = (port: number, forwardedFor?: string) =>
    bareRequest(port, '/status', {
      authorization: 'Bearer wrong',
      ...(forwardedFor ? { 'x-forwarded-for': forwardedFor } : {}),
    });

  it('gives each forwarded client its own budget when a proxy is trusted', async () => {
    expect((await fail(TRUSTING, '1.2.3.4')).status).toBe(401);
    expect((await fail(TRUSTING, '1.2.3.4')).status).toBe(401);
    expect((await fail(TRUSTING, '1.2.3.4')).status).toBe(429);

    // A different client behind the same proxy has not spent anything.
    expect((await fail(TRUSTING, '5.6.7.8')).status).toBe(401);
  });

  it('ignores the header when no proxy is trusted, so it cannot be used to reset', async () => {
    expect((await fail(PLAIN, '1.1.1.1')).status).toBe(401);
    expect((await fail(PLAIN, '2.2.2.2')).status).toBe(401);
    // Both attempts were charged to the socket address, so the third is throttled
    // whatever the header claims.
    expect((await fail(PLAIN, '3.3.3.3')).status).toBe(429);
  });
});

/**
 * Keying is tested as a unit rather than over two sockets: distinguishing two client
 * addresses end-to-end needs two source IPs, and which loopback aliases exist differs by
 * platform, so that test would prove less than it costs.
 */
describe('clientKey', () => {
  // `clientKey` also reports whether a forwarded entry was ignored, which the handler
  // uses to warn. These cases are about the key.
  const clientKeyOf = (req: any, trustProxy: boolean, trusted?: string[]) =>
    clientKey(req, trustProxy, trusted).key;
  const ignoredFor = (req: any, trustProxy: boolean) => clientKey(req, trustProxy).forwardedIgnored;
  const fake = (remoteAddress: string | undefined, forwarded?: string | string[]) => ({
    socket: { remoteAddress },
    headers: forwarded === undefined ? {} : { 'x-forwarded-for': forwarded },
  }) as any;

  it('uses the socket address, which is the real client on a direct connection', async () => {
    expect(clientKeyOf(fake('203.0.113.7'), false)).toBe('203.0.113.7');
  });

  it('treats the IPv6-mapped form as the same client', async () => {
    expect(clientKeyOf(fake('::ffff:127.0.0.1'), false)).toBe('127.0.0.1');
    expect(clientKeyOf(fake('127.0.0.1'), false)).toBe('127.0.0.1');
  });

  it('ignores X-Forwarded-For unless a proxy is trusted', async () => {
    // Otherwise a client picks its own key and opts out of the limit.
    expect(clientKeyOf(fake('203.0.113.7', '9.9.9.9'), false)).toBe('203.0.113.7');
    // A loopback peer is the proxy in the deployment the README describes.
    expect(clientKeyOf(fake('127.0.0.1', '9.9.9.9'), true)).toBe('9.9.9.9');
  });

  it('reads the rightmost forwarded entry, which is the hop the proxy itself added', async () => {
    // Not the leftmost. A proxy appends the address it saw, so everything to the left of
    // the last entry came from the client — reading the leftmost let a client mint a fresh
    // budget per request, and let it burn a victim's budget by naming their address.
    expect(clientKeyOf(fake('127.0.0.1', '9.9.9.9, 10.0.0.5, 10.0.0.9'), true)).toBe('10.0.0.9');
    expect(clientKeyOf(fake('127.0.0.1', ['8.8.8.8', '7.7.7.7']), true)).toBe('7.7.7.7');
  });

  it('discards a forwarded value that is not an address', async () => {
    // Otherwise arbitrary client text becomes a map key.
    expect(clientKeyOf(fake('127.0.0.1', 'not-an-ip'), true)).toBe('127.0.0.1');
    expect(clientKeyOf(fake('127.0.0.1', '9.9.9.9, garbage'), true)).toBe('127.0.0.1');
  });

  it('normalises the forwarded value the same way as the socket address', async () => {
    expect(clientKeyOf(fake('127.0.0.1', '::ffff:203.0.113.9'), true)).toBe('203.0.113.9');
  });

  it('will not let a client that is not the proxy speak for others', () => {
    // The rightmost entry is proxy-authored only if a proxy appended one. On a direct
    // connection the client's single forged entry *is* the rightmost, so both attacks
    // this keying was written to stop came back alive until the peer was checked.
    expect(clientKeyOf(fake('203.0.113.50', '10.0.0.1'), true)).toBe('203.0.113.50');
    expect(ignoredFor(fake('203.0.113.50', '10.0.0.1'), true)).toBe(true);
    // Naming the proxy makes it trusted again.
    expect(clientKeyOf(fake('10.9.9.9', '198.51.100.42'), true, ['10.9.9.9']))
      .toBe('198.51.100.42');
  });

  it.each([
    ['[2001:db8::1]:443', '2001:db8::1'],
    ['[2001:db8::1]', '2001:db8::1'],
    ['198.51.100.5:51234', '198.51.100.5'],
    ['::1', '::1'],
  ])('reads %s as %s', (forwarded, expected) => {
    // `net.isIP` rejects the bracketed and port-suffixed spellings, which is how IPv6
    // usually appears here — and rejecting silently collapsed every client onto the
    // proxy's key, which is worse than not keying at all.
    expect(clientKeyOf(fake('127.0.0.1', forwarded), true)).toBe(expected);
  });

  it('says when a forwarded entry was ignored, so the handler can warn', () => {
    expect(ignoredFor(fake('127.0.0.1', 'garbage'), true)).toBe(true);
    expect(ignoredFor(fake('127.0.0.1', '9.9.9.9'), true)).toBe(false);
    expect(ignoredFor(fake('127.0.0.1'), true)).toBe(false);
  });

  it('falls back rather than throwing when there is no address', async () => {
    expect(clientKeyOf(fake(undefined), false)).toBe('unknown');
    // A trusted proxy that sent nothing useful must not produce an empty key.
    expect(clientKeyOf(fake('127.0.0.1', '   '), true)).toBe('127.0.0.1');
  });
});

/**
 * The properties the default rests on, each pinned because a mutation of it survived the
 * first version of these tests.
 */
describe('HTTP transport — the throttle only charges failures', () => {
  const PORT = 18407;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: PORT, host: HTTP_HOST, bearerToken: BEARER,
      authFailureLimit: 3, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  it('a working client never spends its own budget', async () => {
    // The whole justification for shipping this on by default. Charging the success path
    // too would lock every legitimate client out after N requests a minute, and the
    // previous version of this file could not tell.
    for (let i = 0; i < 8; i++) {
      expect((await bareRequest(PORT, '/status', { authorization: `Bearer ${BEARER}` })).status)
        .toBe(200);
    }
    // The budget is untouched, so a wrong token still gets its first 401 rather than a 429.
    expect((await bareRequest(PORT, '/status', { authorization: 'Bearer wrong' })).status)
      .toBe(401);
  });
});

describe('HTTP transport — a spent budget comes back', () => {
  const PORT = 18408;
  const LIMIT = 3;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: PORT, host: HTTP_HOST, bearerToken: BEARER,
      authFailureLimit: LIMIT, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  it('recovers after the interval Retry-After advertises', async () => {
    for (let i = 0; i < LIMIT; i++) {
      await bareRequest(PORT, '/status', { authorization: 'Bearer wrong' });
    }
    const throttled = await bareRequest(PORT, '/status', { authorization: 'Bearer wrong' });
    expect(throttled.status).toBe(429);
    const retryAfterSec = Number(throttled.headers['retry-after']);

    // Only Date is faked, so the server's own socket I/O keeps running. Without this the
    // refill could be broken outright — a bucket that never comes back — and the header
    // would still advertise a wait that never ends.
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + retryAfterSec * 1000 + 50 });
    try {
      expect((await bareRequest(PORT, '/status', { authorization: `Bearer ${BEARER}` })).status)
        .toBe(200);

      // And the limit still bites afterwards. Recovery alone is not enough to prove the
      // refill works on both sides: `peek` has its own refill, so a broken refill inside
      // `consume` lets every request through while the bucket sits at zero — the throttle
      // stops re-arming and nothing else notices.
      const again: number[] = [];
      for (let i = 0; i < LIMIT + 1; i++) {
        again.push((await bareRequest(PORT, '/status', { authorization: 'Bearer wrong' })).status);
      }
      expect(again[again.length - 1]).toBe(429);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('HTTP transport — the default limit is the documented one', () => {
  const PORT = 18409;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: PORT, host: HTTP_HOST, bearerToken: BEARER, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  it('allows exactly ten failures, the number the README documents', async () => {
    // The literal, not the imported constant. Asserting against
    // `DEFAULT_AUTH_FAILURE_LIMIT` is tautological — moving the constant moves the
    // expectation with it, so 2 and 13 both passed. This is the value README.md states
    // and the one operators size their clients against, so it is written out here and
    // the two have to be changed together.
    const expected = 10;
    const statuses: number[] = [];
    for (let i = 0; i < expected + 2; i++) {
      statuses.push((await bareRequest(PORT, '/status', { authorization: 'Bearer wrong' })).status);
    }
    expect(statuses.slice(0, expected)).toEqual(Array(expected).fill(401));
    expect(statuses[expected]).toBe(429);
  });

  it('and the constant agrees with it', async () => {
    const { DEFAULT_AUTH_FAILURE_LIMIT } = await import('../../../src/transport/http.js');
    expect(DEFAULT_AUTH_FAILURE_LIMIT).toBe(10);
  });
});

describe('AuthFailureLimiter', () => {
  it('keeps the tracked-client map bounded', async () => {
    const { AuthFailureLimiter, MAX_TRACKED_CLIENTS } = await import('../../../src/transport/http.js');
    const limiter = new AuthFailureLimiter(5) as any;
    for (let i = 0; i < MAX_TRACKED_CLIENTS + 50; i++) limiter.recordFailure(`10.0.${i >> 8}.${i & 255}`);
    // The only bound on this map, and the key is attacker-chosen under --trustProxy.
    expect(limiter.buckets.size).toBeLessThanOrEqual(MAX_TRACKED_CLIENTS);
  });

  it('gives an arriving client one attempt while every bucket is spent', async () => {
    const { AuthFailureLimiter, MAX_TRACKED_CLIENTS } = await import('../../../src/transport/http.js');
    const limiter = new AuthFailureLimiter(10);
    // Saturate the table with exhausted buckets, which is remotely reachable.
    for (let i = 0; i < MAX_TRACKED_CLIENTS; i++) {
      for (let n = 0; n < 10; n++) limiter.recordFailure(`atk-${i}`);
    }
    // `peek` allows a key it has never seen, so the first attempt is free; the bucket is
    // created by the failure and starts spent, so the second is refused. On an unsaturated
    // table the same client would have the full budget — that collapse is the cost of not
    // refunding, and it is asserted here so it cannot change unnoticed.
    expect(limiter.peek('arriving').allowed).toBe(true);
    limiter.recordFailure('arriving');
    expect(limiter.peek('arriving').allowed).toBe(false);

    const unsaturated = new AuthFailureLimiter(10);
    unsaturated.recordFailure('arriving');
    expect(unsaturated.peek('arriving').allowed).toBe(true);
  });

  it('does not refund a spent budget when the map is recycled', async () => {
    const { AuthFailureLimiter, MAX_TRACKED_CLIENTS } = await import('../../../src/transport/http.js');
    const limiter = new AuthFailureLimiter(2);
    for (let i = 0; i < 2; i++) limiter.recordFailure('victim');
    expect(limiter.peek('victim').allowed).toBe(false);

    // Evicting by age discarded the *blocked* bucket first — its lastRefill is frozen,
    // because peek does not mutate — and then handed the key a fresh full budget, so
    // cycling keys cleared a lockout.
    for (let i = 0; i < MAX_TRACKED_CLIENTS + 10; i++) limiter.recordFailure(`filler-${i}`);
    expect(limiter.peek('victim').allowed).toBe(false);
  });
});

describe('HTTP transport — the two 429s are distinguishable', () => {
  const PORT = 18410;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: PORT, host: HTTP_HOST, bearerToken: BEARER,
      authFailureLimit: 2, rateLimit: 3, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  it('the auth throttle says which throttle it is', async () => {
    for (let i = 0; i < 2; i++) await bareRequest(PORT, '/status', { authorization: 'Bearer x' });
    const res = await bareRequest(PORT, '/status', { authorization: 'Bearer x' });
    expect(res.status).toBe(429);
    // MCP clients parse this route, so the envelope is part of the contract.
    const parsed = JSON.parse(res.body);
    expect(parsed.jsonrpc).toBe('2.0');
    expect(parsed.error.code).toBe(-32604);
    expect(parsed.error.message).toMatch(/failed authentication/i);
  });

  it('a failed attempt never touches the global request budget', async () => {
    // The reason the request limiter was left above the auth check: that bucket is
    // global, so letting unauthenticated traffic drain it would starve every legitimate
    // client. Checked on its own server, with the failure budget deliberately left
    // unspent — once it is spent the auth throttle answers first, which is what the
    // sibling test above measures.
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    const port = 18412;
    await startHttpServer(() => mcpServer, {
      port, host: HTTP_HOST, bearerToken: BEARER,
      authFailureLimit: 5, rateLimit: 3, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));

    // Two failures — under the budget of 5, so nothing is throttled yet.
    for (let i = 0; i < 2; i++) {
      expect((await bareRequest(port, '/status', { authorization: 'Bearer x' })).status).toBe(401);
    }
    // The request budget of 3 is still whole.
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      statuses.push((await bareRequest(port, '/status', { authorization: `Bearer ${BEARER}` })).status);
    }
    expect(statuses).toEqual([200, 200, 200]);
  });
});

describe('HTTP transport — the request limiter admits exactly its limit', () => {
  const PORT = 18411;

  beforeAll(async () => {
    const { startHttpServer } = await import('../../../src/transport/http.js');
    const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
    const mockRegistry = {
      listConnections: () => [], listAllProfiles: () => [], get: () => undefined,
      getOrCreate: async () => { throw new Error('not in test'); },
    } as any;
    const mcpServer = new McpServer(
      { name: 'test', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    await startHttpServer(() => mcpServer, {
      port: PORT, host: HTTP_HOST, bearerToken: BEARER,
      rateLimit: 3, authFailureLimit: 0, registry: mockRegistry,
    });
    await new Promise((r) => setTimeout(r, 100));
  });

  it('three through, then throttled — a fresh bucket, so the boundary is exact', async () => {
    // The pre-existing test shares a bucket with the rest of the file and so can only
    // assert a shape. That was fine until this arithmetic became shared by both limiters:
    // an off-by-one in `consume` admits one extra request and nothing noticed.
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await new Promise<number>((resolve, reject) => {
        const req = httpModule.request(
          {
            hostname: HTTP_HOST, port: PORT, path: '/', method: 'POST',
            headers: { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json' },
            agent: false as const,
          },
          (r) => { r.resume(); r.on('end', () => resolve(r.statusCode || 0)); },
        );
        req.on('error', reject);
        req.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }));
      });
      statuses.push(res);
    }
    expect(statuses.filter((x) => x !== 429)).toHaveLength(3);
    expect(statuses.slice(3)).toEqual([429, 429]);
  });
});
