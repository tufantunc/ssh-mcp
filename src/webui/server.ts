import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { WebUIOptions, WebUIHandle, ApprovalDecisionKind } from './types.js';
import { handleProfiles } from './routes/profiles.js';
import { handleExecutions } from './routes/executions.js';
import { handleListApprovals, handleDecideApproval } from './routes/approvals.js';
import { handleListModes, handleSetProfileMode, handleSetGlobalMode } from './routes/modes.js';
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

function isLoopbackHeaderValue(value: string | string[] | undefined): boolean {
  if (Array.isArray(value)) return false;
  // hostnameFromAuthority is declared below with the approval-mutation CSRF
  // helpers; function declarations hoist, so the shared helper is reused here.
  const hostname = hostnameFromAuthority(value);
  return hostname !== undefined && isLoopback(hostname);
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

/**
 * Read JSON body from a request, capped at 1 MiB. Returns null on parse error.
 */
function readJson(req: http.IncomingMessage, max = 1024 * 1024): Promise<any | null> {
  return new Promise(resolve => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > max) {
        req.destroy();
        resolve(null);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { resolve(null); }
    });
    req.on('error', () => resolve(null));
  });
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

function singleHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[|\]$/g, '');
}

function hostnameFromAuthority(authority: string | undefined): string | undefined {
  if (!authority) return undefined;
  try {
    return normalizeHostname(new URL(`http://${authority}`).hostname);
  } catch {
    return undefined;
  }
}

function headerOriginIsSameHost(value: string | undefined, hostHeader: string): boolean {
  if (!value) return true;
  try {
    const origin = new URL(value);
    return origin.host.toLowerCase() === hostHeader.toLowerCase()
      && isLoopback(normalizeHostname(origin.hostname));
  } catch {
    return false;
  }
}

/**
 * State-changing approval routes stay usable in loopback/no-token mode, but
 * reject browser cross-origin or DNS-rebinding requests. Token-protected
 * deployments already authenticate above with bearer/X-Auth-Token.
 */
function checkApprovalMutationAuth(opts: { req: http.IncomingMessage; authToken?: string }): boolean {
  if (opts.authToken) return true;

  const hostHeader = singleHeader(opts.req.headers.host);
  const hostName = hostnameFromAuthority(hostHeader);
  if (!hostHeader || !hostName || !isLoopback(hostName)) return false;

  const origin = singleHeader(opts.req.headers.origin);
  const referer = singleHeader(opts.req.headers.referer);
  if (!origin && !referer) return false;
  if (!headerOriginIsSameHost(origin, hostHeader)) return false;
  if (!headerOriginIsSameHost(referer, hostHeader)) return false;

  return true;
}

/**
 * Start the WebUI HTTP server.
 *
 * Throws synchronously (before listen) if configuration is invalid:
 *   - non-loopback host without authToken
 */
export async function startWebUI(opts: WebUIOptions): Promise<WebUIHandle> {
  const host = opts.host ?? '127.0.0.1';
  const port = opts.port ?? 0;

  if (!isLoopback(host) && !opts.authToken) {
    throw new Error(
      `[webui] non-loopback bind (${host}) requires auth_token; refusing to start without one`,
    );
  }

  const hub = new SseHub(opts.queue, opts.audit, opts.modeController);

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
        if (!checkAuth({ req, authToken: opts.authToken, bind: host, isSse: true, urlObj })) {
          sendJson(res, 401, { error: 'unauthorized' });
          return;
        }
        hub.attach(res);
        return;
      }

      // --- API gated by token -------------------------------------------
      if (pathname.startsWith('/api/')) {
        if (!checkAuth({ req, authToken: opts.authToken, bind: host, urlObj })) {
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

        const m = pathname.match(/^\/api\/approvals\/([^/]+)\/(allow|deny)$/);
        if (m && method === 'POST') {
          if (!checkApprovalMutationAuth({ req, authToken: opts.authToken })) {
            sendJson(res, 403, { error: 'approval mutation requires same-origin loopback request or auth token' });
            return;
          }
          let id: string;
          try {
            id = decodeURIComponent(m[1]);
          } catch {
            sendJson(res, 400, { error: 'malformed approval id' });
            return;
          }
          const kind = m[2] as ApprovalDecisionKind;
          const body = await readJson(req);
          if (body === null) {
            sendJson(res, 400, { error: 'invalid JSON body' });
            return;
          }
          const note = typeof body?.note === 'string' ? body.note : undefined;
          const decidedBy = `webui:${req.socket.remoteAddress || 'unknown'}`;
          const r = handleDecideApproval(opts.queue, id, kind, note, decidedBy);
          sendJson(res, r.status, r.body);
          return;
        }

        // --- Live approval-mode switching (PR-7, in-memory only) ----------
        if (pathname === '/api/approval-modes' && method === 'GET') {
          const r = handleListModes(opts.modeController);
          sendJson(res, r.status, r.body);
          return;
        }

        if (pathname === '/api/approval-mode' && method === 'PUT') {
          if (!checkApprovalMutationAuth({ req, authToken: opts.authToken })) {
            sendJson(res, 403, { error: 'approval mutation requires same-origin loopback request or auth token' });
            return;
          }
          const body = await readJson(req);
          if (body === null) {
            sendJson(res, 400, { error: 'invalid JSON body' });
            return;
          }
          const r = handleSetGlobalMode(opts.modeController, body);
          sendJson(res, r.status, r.body);
          return;
        }

        const modeMatch = pathname.match(/^\/api\/profiles\/([^/]+)\/approval-mode$/);
        if (modeMatch && method === 'PUT') {
          if (!checkApprovalMutationAuth({ req, authToken: opts.authToken })) {
            sendJson(res, 403, { error: 'approval mutation requires same-origin loopback request or auth token' });
            return;
          }
          let id: string;
          try {
            id = decodeURIComponent(modeMatch[1]);
          } catch {
            sendJson(res, 400, { error: 'malformed profile id' });
            return;
          }
          const profileExists = opts.registry.list().some(p => p.name === id);
          const body = await readJson(req);
          if (body === null) {
            sendJson(res, 400, { error: 'invalid JSON body' });
            return;
          }
          const r = handleSetProfileMode(opts.modeController, id, profileExists, body);
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
