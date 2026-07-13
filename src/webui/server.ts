import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { WebUIOptions, WebUIHandle } from './types.js';
import { handleProfiles } from './routes/profiles.js';
import { handleExecutions } from './routes/executions.js';
import { handleListApprovals } from './routes/approvals.js';
import { SseHub } from './routes/sse.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STATIC_DIR = path.resolve(__dirname, 'static');

const STATIC_MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
};

function isLoopback(host: string): boolean {
  const normalized = host.replace(/^\[|\]$/g, '').toLowerCase();
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
}

function hostnameFromAuthority(authority: string | undefined): string | null {
  if (!authority) return null;
  try {
    return new URL(`http://${authority}`).hostname;
  } catch {
    return null;
  }
}

function isLoopbackHeaderValue(value: string | string[] | undefined): boolean {
  if (Array.isArray(value)) return false;
  const hostname = hostnameFromAuthority(value);
  return hostname !== null && isLoopback(hostname);
}

function hasLoopbackHostAndOrigin(req: http.IncomingMessage): boolean {
  // Tokenless mode is a local developer convenience. Do not let a DNS-rebound
  // page read loopback-only APIs by sending Host/Origin for an attacker domain.
  if (!isLoopbackHeaderValue(req.headers.host)) return false;
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  if (Array.isArray(origin)) return false;
  try {
    return isLoopback(new URL(origin).hostname);
  } catch {
    return false;
  }
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store',
  });
  res.end(text);
}

function sendText(res: http.ServerResponse, status: number, body: string, contentType = 'text/plain; charset=utf-8'): void {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

async function serveStatic(res: http.ServerResponse, urlPath: string): Promise<boolean> {
  let rel = urlPath === '/' || urlPath === '' ? '/index.html' : urlPath;
  // Prevent path traversal: resolve and ensure under STATIC_DIR.
  const target = path.resolve(STATIC_DIR, '.' + rel);
  if (!target.startsWith(STATIC_DIR + path.sep) && target !== STATIC_DIR) {
    return false;
  }
  try {
    const data = await fs.readFile(target);
    const ext = path.extname(target).toLowerCase();
    const ct = STATIC_MIME[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': ct,
      'Content-Length': data.byteLength,
      'Cache-Control': 'no-store',
    });
    res.end(data);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate auth token. Returns true iff request is allowed to proceed.
 * Token is optional on loopback when not configured; required everywhere else.
 */
function checkAuth(opts: { req: http.IncomingMessage; authToken?: string; bind: string; isSse?: boolean; urlObj: URL }): boolean {
  const loopback = isLoopback(opts.bind);
  if (!opts.authToken) {
    // No token configured. Allowed only on loopback (boot validation prevents
    // non-loopback bind without a token), and only when the request itself uses
    // a loopback Host/Origin so DNS rebinding cannot read loopback-only APIs.
    return loopback && hasLoopbackHostAndOrigin(opts.req);
  }
  if (opts.isSse) {
    const t = opts.urlObj.searchParams.get('token');
    if (t && t === opts.authToken) return true;
  }
  const hdr = opts.req.headers.authorization || '';
  if (typeof hdr === 'string' && hdr.startsWith('Bearer ')) {
    return hdr.slice(7) === opts.authToken;
  }
  // X-Auth-Token fallback for clients that can't set Authorization.
  const x = opts.req.headers['x-auth-token'];
  if (typeof x === 'string' && x === opts.authToken) return true;
  return false;
}

/**
 * Start the WebUI HTTP server.
 *
 * Throws synchronously (before listen) if configuration is invalid:
 *   - a provided authToken is empty after trimming
 *   - non-loopback host without authToken
 */
export async function startWebUI(opts: WebUIOptions): Promise<WebUIHandle> {
  const host = opts.host ?? '127.0.0.1';
  const port = opts.port ?? 0;
  const authToken = opts.authToken?.trim();

  if (opts.authToken !== undefined && !authToken) {
    throw new Error('[webui] auth_token must not be empty or whitespace-only');
  }
  if (!isLoopback(host) && !authToken) {
    throw new Error(
      `[webui] non-loopback bind (${host}) requires auth_token; refusing to start without one`,
    );
  }

  const hub = new SseHub(opts.queue, opts.audit);

  const server = http.createServer(async (req, res) => {
    try {
      const urlObj = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const pathname = urlObj.pathname;
      const method = (req.method || 'GET').toUpperCase();

      // --- SSE: /events --------------------------------------------------
      if (pathname === '/events') {
        if (method !== 'GET') {
          sendJson(res, 405, { error: 'method not allowed' });
          return;
        }
        if (!checkAuth({ req, authToken, bind: host, isSse: true, urlObj })) {
          sendJson(res, 401, { error: 'unauthorized' });
          return;
        }
        hub.attach(res);
        return;
      }

      // --- API gated by token -------------------------------------------
      if (pathname.startsWith('/api/')) {
        if (!checkAuth({ req, authToken, bind: host, urlObj })) {
          sendJson(res, 401, { error: 'unauthorized' });
          return;
        }

        if (pathname === '/api/profiles' && method === 'GET') {
          const r = handleProfiles(opts.registry, opts.getApprovalMode);
          sendJson(res, r.status, r.body);
          return;
        }

        if (pathname === '/api/executions' && method === 'GET') {
          const r = await handleExecutions(opts.audit, urlObj.searchParams);
          sendJson(res, r.status, r.body);
          return;
        }

        if (pathname === '/api/approvals' && method === 'GET') {
          const r = handleListApprovals(opts.queue);
          sendJson(res, r.status, r.body);
          return;
        }

        sendJson(res, 404, { error: 'not found' });
        return;
      }

      // --- Static UI -----------------------------------------------------
      if (method === 'GET' || method === 'HEAD') {
        // Static UI is also gated when an authToken is set, except for the
        // login page itself.  We allow GET / and assets without auth on
        // loopback when no token is set (dev mode).  On any token-protected
        // deployment, the index page reads the token from a hash fragment
        // (#token=...) or prompts; we don't enforce auth on the page itself
        // because the user has nothing to authenticate with yet.
        const served = await serveStatic(res, pathname);
        if (served) return;
        sendJson(res, 404, { error: 'not found' });
        return;
      }

      sendJson(res, 405, { error: 'method not allowed' });
    } catch (err: any) {
      try { sendJson(res, 500, { error: err?.message || 'internal error' }); } catch { /* ignore */ }
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : port;

  return {
    address: { host, port: actualPort },
    async close() {
      hub.closeAll();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}

// Silence unused import warning when only the type is referenced.
export type { WebUIOptions, WebUIHandle } from './types.js';
// Re-export sendText to keep tree-shaking happy in tests / future use.
export { sendText };
