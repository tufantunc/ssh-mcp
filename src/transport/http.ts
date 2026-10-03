import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { randomUUID, timingSafeEqual } from 'crypto';
import { isIP } from 'net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import { SERVER_VERSION } from '../version.js';
import { OperatorError } from '../errors.js';

const MAX_BODY_SIZE = 1_048_576; // 1MB
/** Cap on concurrent MCP sessions, so unauthenticated-adjacent churn can't grow the map without bound. */
const MAX_SESSIONS = 64;

/** How many failed auth attempts one client may make per minute. 0 disables the check. */
export const DEFAULT_AUTH_FAILURE_LIMIT = 10;

/** Cap on tracked clients, for the reason `MAX_SESSIONS` exists: churn must not grow a map. */
export const MAX_TRACKED_CLIENTS = 1024;

const REFILL_INTERVAL_MS = 60_000;

interface Bucket {
  tokens: number;
  lastRefill: number;
}

/** Whole tokens earned since `lastRefill`. Negative when the clock stepped back; callers clamp. */
function tokensEarned(bucket: Bucket, maxTokens: number): number {
  return Math.floor(((Date.now() - bucket.lastRefill) / REFILL_INTERVAL_MS) * maxTokens);
}

/** Tokens the bucket would hold if refilled now, without changing it. */
function availableTokens(bucket: Bucket, maxTokens: number): number {
  return Math.min(maxTokens, bucket.tokens + Math.max(tokensEarned(bucket, maxTokens), 0));
}

/**
 * How long until this bucket earns its next token, for `Retry-After`.
 *
 * Exact, where it used to be the fixed `REFILL_INTERVAL_MS / maxTokens`. That is how long
 * one token takes, so a client refused halfway through the interval was told to wait
 * twice as long as it had to. Bounded on both sides: below at a second, because
 * `Retry-After` is whole seconds and `0` reads as "retry now"; above at one token's
 * interval, because a clock that stepped backwards puts `lastRefill` in the future, and
 * the raw difference would then advertise an arbitrarily long wait. Rounded up to whole
 * milliseconds: a limit that does not divide a minute gives a fractional interval, and
 * rounding down would name a moment at which the token has not yet arrived.
 */
function nextTokenWaitMs(bucket: Bucket, maxTokens: number): number {
  const interval = REFILL_INTERVAL_MS / maxTokens;
  return Math.max(1000, Math.ceil(Math.min(interval, bucket.lastRefill + interval - Date.now())));
}

/**
 * The tracked key whose bucket holds the most tokens *after refill*: the entry with the
 * least worth remembering, so the one to evict.
 *
 * Refilled, not stored. A key that stops sending keeps its stored count forever, so
 * ranking by `tokens` treated a bucket spent an hour ago as still spent. A table that
 * was saturated once was then judged saturated for good, which was measured.
 *
 * Linear in the table, and left that way: it runs only when a new key arrives at a full
 * table, and stops early at the first full bucket. The worst case, every bucket partly
 * spent, measured about 46µs per new key at 1024 entries (Apple M4 Max, Node 24), and
 * the same for both limiters.
 */
function fullestBucket(
  buckets: Map<string, Bucket>,
  maxTokens: number,
): { key: string; available: number } | undefined {
  let fullest: { key: string; available: number } | undefined;
  for (const [key, bucket] of buckets) {
    const available = availableTokens(bucket, maxTokens);
    if (fullest === undefined || available > fullest.available) fullest = { key, available };
    if (available === maxTokens) break;
  }
  return fullest;
}

/**
 * One token-bucket step, shared by the two limiters so the refill arithmetic exists once.
 *
 * Mutates the bucket. Refills proportionally to elapsed time rather than on a timer, so an
 * idle server costs nothing and there is no interval to clean up.
 */
function consume(bucket: Bucket, maxTokens: number): { allowed: boolean; retryAfterMs: number } {
  const refilled = tokensEarned(bucket, maxTokens);
  if (refilled > 0) {
    bucket.tokens = Math.min(maxTokens, bucket.tokens + refilled);
    bucket.lastRefill += Math.round((refilled / maxTokens) * REFILL_INTERVAL_MS);
  }

  if (bucket.tokens > 0) {
    bucket.tokens--;
    return { allowed: true, retryAfterMs: 0 };
  }

  return { allowed: false, retryAfterMs: nextTokenWaitMs(bucket, maxTokens) };
}

/**
 * A request bucket per client, so `--rateLimit` means N requests per minute *per caller*.
 *
 * It was one bucket for the process: one client spent `--rateLimit` for every other, and
 * a client that had sent nothing was refused (#187, measured). Keyed by `clientKey()`,
 * the same key the failure budget uses, and charged only after the token check passes,
 * so unauthenticated traffic cannot create entries or drain anyone's budget.
 *
 * Bounded like `AuthFailureLimiter`, and it evicts the fullest bucket for the same reason.
 * Where it differs: an arriving key always starts full, even when every tracked bucket is
 * spent. Saturating this table takes 1024 addresses that hold the token, and a token
 * holder with that many addresses already has that many budgets. The refund opens nothing
 * new, while starting empty would refuse a legitimate client's first request because of
 * other clients' traffic.
 */
export class ClientRateLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(private maxTokens: number) {}

  tryConsume(key: string): { allowed: boolean; retryAfterMs: number } {
    let bucket = this.buckets.get(key);
    if (bucket === undefined) {
      if (this.buckets.size >= MAX_TRACKED_CLIENTS) {
        const fullest = fullestBucket(this.buckets, this.maxTokens);
        if (fullest !== undefined) this.buckets.delete(fullest.key);
      }
      bucket = { tokens: this.maxTokens, lastRefill: Date.now() };
      this.buckets.set(key, bucket);
    }
    return consume(bucket, this.maxTokens);
  }
}

/**
 * A bucket per client, for throttling failed authentication.
 *
 * Separate from the request limiter on purpose. The auth check returned before the request
 * limiter was reached, so a wrong bearer token consumed nothing and guessing ran at network
 * speed with no backoff — measured as twelve 401s and zero 429s against `--rateLimit=3`.
 * Moving the request limiter above the auth check would have closed that and opened
 * something worse: its 429 would answer a guess without evaluating it, and unauthenticated
 * traffic reaching a request bucket could spend a victim's budget under a spoofable key.
 *
 * Only failures consume a token, so a working client never builds a budget up and is never
 * throttled by its own traffic — which is what makes this safe to have on by default. It
 * is not a promise that a correct token always passes: once an address has spent its
 * budget, everything from that address waits, correct tokens included. That is the whole
 * point. Charging only after the comparison would leave the guess itself evaluated and the
 * status code would still tell the attacker which token was right.
 */
export class AuthFailureLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(private maxTokens: number) {}

  /** Whether this client may make another attempt. Does not consume. */
  peek(key: string): { allowed: boolean; retryAfterMs: number } {
    const bucket = this.buckets.get(key);
    if (bucket === undefined) return { allowed: true, retryAfterMs: 0 };
    if (availableTokens(bucket, this.maxTokens) > 0) return { allowed: true, retryAfterMs: 0 };
    return { allowed: false, retryAfterMs: nextTokenWaitMs(bucket, this.maxTokens) };
  }

  /** Charge this client for a failed attempt. */
  recordFailure(key: string): void {
    let bucket = this.buckets.get(key);
    if (bucket === undefined) {
      bucket = { tokens: this.maxTokens, lastRefill: Date.now() };
      if (this.buckets.size >= MAX_TRACKED_CLIENTS) {
        // Evict the *fullest* entry, not the oldest. An exhausted bucket has the oldest
        // `lastRefill` by construction, so evicting by age evicted the locked-out client
        // first and then handed its key a fresh budget: minting enough keys cleared a
        // lockout, which was measured end to end. A full bucket is the one with nothing
        // worth remembering.
        const fullest = fullestBucket(this.buckets, this.maxTokens);
        if (fullest !== undefined) this.buckets.delete(fullest.key);
        // Every tracked client is spent, so the table itself is the signal and a new key
        // does not get a full budget.
        //
        // The cost, stated because it is real and cannot be softened here: while the table
        // is saturated an arriving client has one attempt rather than the full budget, so
        // a first typo leaves its correct token waiting. Seeding one token instead of zero
        // looks like it would help and does not — `consume` spends it immediately, and
        // `peek` already allows a key it has never seen, so the first attempt is free
        // either way and the second is refused either way. Measured both, identical.
        // Giving an arriving key a real budget is the refund this rule exists to stop.
        // Saturation needs 1024 addresses that have each spent a full budget *recently*:
        // `fullestBucket` ranks by refilled tokens, so the condition ends once they refill.
        if (fullest === undefined || fullest.available <= 0) bucket = { tokens: 0, lastRefill: Date.now() };
      }
      this.buckets.set(key, bucket);
    }
    consume(bucket, this.maxTokens);
  }
}

/**
 * Which client an attempt is charged to.
 *
 * The socket's remote address, which is the real client on a direct connection — how this
 * server is normally run. `X-Forwarded-For` is read only when a proxy is explicitly
 * trusted: honouring it unconditionally would let any client forge its own key and so opt
 * out of the limit entirely.
 *
 * When it is read, the **rightmost** entry is the one taken, not the leftmost. A proxy
 * appends the address it saw, so the rightmost entry is what the nearest trusted proxy
 * observed while every entry to its left came from the client. Reading the leftmost was
 * worse than having no limit: a client sending `X-Forwarded-For: 10.0.0.1` minted a fresh
 * budget per request — measured as nine wrong tokens and zero 429s — and sending a
 * victim's address burned *their* budget instead, locking out a correct token.
 *
 * This assumes exactly one trusted proxy in front, which is what `--trustProxy` means. A
 * chain of two would need the second-from-right, and this does not try to guess the depth.
 * Anything that is not an IP address is discarded rather than used as a map key.
 */
export function clientKey(
  req: IncomingMessage,
  trustProxy: boolean,
  trustedProxies?: string[],
): { key: string; forwardedIgnored: boolean } {
  const peer = canonicalAddress(req.socket.remoteAddress ?? 'unknown');
  const forwarded = req.headers['x-forwarded-for'];
  if (!trustProxy || forwarded === undefined) return { key: keyOf(peer), forwardedIgnored: false };

  // The rightmost entry is proxy-authored only if a proxy actually appended one. Nothing
  // about the header says whether it did, so the *peer* has to be the proxy — otherwise a
  // client reaching the listener directly sends one forged entry, that entry is the
  // rightmost, and it picks its own key. Both attacks this keying was fixed to stop came
  // back alive in exactly that configuration.
  if (!isTrustedPeer(peer, trustedProxies)) {
    return { key: keyOf(peer), forwardedIgnored: true };
  }

  const raw = Array.isArray(forwarded) ? forwarded.join(',') : forwarded;
  const entries = raw.split(',').map((e) => e.trim()).filter(Boolean);
  const nearest = entries[entries.length - 1];
  const address = nearest === undefined ? undefined : forwardedAddress(nearest);
  if (address === undefined) return { key: keyOf(peer), forwardedIgnored: true };
  return { key: keyOf(address), forwardedIgnored: false };
}

/**
 * The budget an address is charged to: itself for IPv4, its /64 for IPv6.
 *
 * Applied to the returned key only. Trust is still decided on the exact peer, or every host
 * in a proxy's /64 could speak for other clients.
 */
function keyOf(address: string): string {
  if (isIP(address) !== 6 || address === '::1') return address;
  return ipv6Prefix64(address);
}

/**
 * The /64 an IPv6 address belongs to, spelled one way.
 *
 * A /64 is the smallest block a subscriber is handed, so the address inside it is the
 * client's own to choose; keyed by full address, each choice was a fresh budget. The
 * spelling is fixed — zone dropped, `::` expanded, a dotted IPv4 tail counted as two
 * groups, leading zeros and case removed by reading each group as a number — so rewriting
 * the address does not reach a new key. Only the first four groups are kept, so the tail
 * never needs converting.
 */
function ipv6Prefix64(address: string): string {
  const bare = address.split('%')[0];
  const dotted = bare.includes('.');
  const [head, tail] = bare.split('::');
  const headGroups = head === '' ? [] : head.split(':');
  const tailGroups = tail === undefined || tail === '' ? [] : tail.split(':');
  // A dotted tail is one written group standing for two.
  const written = headGroups.length + tailGroups.length + (dotted ? 1 : 0);
  const groups = tail === undefined
    ? headGroups
    : [...headGroups, ...Array(8 - written).fill('0'), ...tailGroups];
  const prefix = groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16));
  return `${prefix.join(':')}::/64`;
}

/**
 * Whether the peer may speak for other clients.
 *
 * Bare `--trustProxy` means a loopback peer, which is the deployment the README asks for:
 * the server binds to 127.0.0.1 and a proxy on the same host terminates TLS. A proxy
 * somewhere else has to be named, because "trust whoever connected" is the assumption that
 * made the header forgeable again.
 */
function isTrustedPeer(peer: string, trustedProxies?: string[]): boolean {
  if (trustedProxies !== undefined && trustedProxies.length > 0) {
    return trustedProxies.includes(peer);
  }
  return peer === '127.0.0.1' || peer === '::1' || peer.startsWith('127.');
}

/**
 * One `X-Forwarded-For` entry as an address, or undefined if it is not one.
 *
 * `net.isIP` rejects the bracketed and port-suffixed spellings, which is how IPv6 usually
 * appears in this header — and rejecting silently collapsed every client onto the proxy's
 * key, which is worse than not keying at all.
 */
function forwardedAddress(entry: string): string | undefined {
  let candidate = entry;
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(candidate);
  if (bracketed) candidate = bracketed[1];
  // A trailing `:port` only when what is left is not itself an IPv6 literal: `::1` has
  // colons of its own and must not be truncated.
  else if (isIP(candidate) === 0 && /^[^:]+:\d+$/.test(candidate)) {
    candidate = candidate.slice(0, candidate.lastIndexOf(':'));
  }
  candidate = canonicalAddress(candidate);
  return isIP(candidate) === 0 ? undefined : candidate;
}

/**
 * `::ffff:127.0.0.1` and `127.0.0.1` are the same client; key them the same way. Case is
 * folded first: a forwarded `::FFFF:` spelling otherwise stayed IPv6.
 */
function canonicalAddress(address: string): string {
  const folded = address.toLowerCase();
  return folded.startsWith('::ffff:') ? folded.slice(7) : folded;
}

export interface HttpTransportOpts {
  port: number;
  host?: string;
  bearerToken?: string;
  registry: ConnectionRegistry;
  /**
   * Authenticated requests allowed per client per minute, on every route but
   * `GET /health`. 0 or unset disables the limit. Clients are keyed as for
   * `authFailureLimit`.
   */
  rateLimit?: number;
  /**
   * Failed bearer-auth attempts allowed per client per minute. Defaults to
   * `DEFAULT_AUTH_FAILURE_LIMIT`; 0 disables the check. A correct token never consumes from
   * this budget, so a working client never throttles itself; a client sharing an address
   * with a failing one does wait, which is what the limit is for.
   */
  authFailureLimit?: number;
  /**
   * Whether to read the client address from `X-Forwarded-For`. Off by default, because a
   * client that can set that header can otherwise choose its own rate-limit key.
   */
  trustProxy?: boolean;
  /**
   * Peer addresses allowed to speak for other clients via `X-Forwarded-For`. Empty means
   * a loopback peer only, which is the deployment the README describes.
   */
  trustedProxies?: string[];
  /**
   * Host headers accepted by the DNS-rebinding guard. Defaults to the bind
   * address and localhost; set this when running behind a reverse proxy that
   * presents a different hostname.
   */
  allowedHosts?: string[];
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
    throw new OperatorError(
      'HTTP transport requires --bearerToken. Example: --transport=http --bearerToken=secret\n' +
      'Without authentication, any network client can execute SSH commands on your hosts.',
    );
  }

  const authFailureLimit = opts.authFailureLimit ?? DEFAULT_AUTH_FAILURE_LIMIT;
  const authFailureLimiter = authFailureLimit > 0
    ? new AuthFailureLimiter(authFailureLimit)
    : null;

  // Said once, when it turns out to matter. Behind a proxy with `--trustProxy` off, every
  // client is keyed on the proxy's socket address and so shares one failure budget and one
  // request budget — ten failures from anyone locks out everyone, and one busy client
  // starves the rest. The README tells operators to terminate TLS at a proxy, so this is
  // the configuration it recommends, and the collapse is invisible until a legitimate
  // client is refused.
  let warnedSharedBudget = false;
  const warnSharedBudget = () => {
    if (warnedSharedBudget) return;
    warnedSharedBudget = true;
    console.error(
      'POLICY WARNING: X-Forwarded-For is present but not being used to tell clients ' +
      'apart, so every client is charged to one key: one failed-auth budget and one ' +
      'request budget between them, for whichever of the two is on, and one client can ' +
      'lock out or starve the rest. Either --trustProxy is off, or the peer is not a ' +
      'trusted proxy (bare --trustProxy trusts a loopback peer; name others with ' +
      '--trustedProxies), or the rightmost entry is not an address this server can read.',
    );
  };

  const rateLimiter = opts.rateLimit && opts.rateLimit > 0
    ? new ClientRateLimiter(opts.rateLimit)
    : null;

  // DNS rebinding: a page the user visits can make their browser POST to a
  // localhost server, and the bearer token does not help if the browser is
  // tricked into attaching it. Validating the Host header is what stops it.
  // GHSA-w48q-cv73-mx4w is exactly this, and the SDK leaves it to the caller.
  const allowedHosts = opts.allowedHosts?.length
    ? opts.allowedHosts
    : [`${host}:${port}`, `localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`];

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
      enableDnsRebindingProtection: true,
      allowedHosts,
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

    // Liveness probes are conventionally unauthenticated, and the README lists
    // /health without an auth caveat. It exposes "process is up" and whether any profile
    // is configured — see the handler below for why that second bit is not a secret.
    const isHealthProbe = req.method === 'GET' && url.pathname === '/health';

    if (!isHealthProbe) {
      let key = '';
      if (authFailureLimiter || rateLimiter) {
        const resolved = clientKey(req, opts.trustProxy === true, opts.trustedProxies);
        key = resolved.key;
        // Warned in both directions. Without `--trustProxy` a proxied deployment shares
        // one budget; *with* it, an entry that could not be read leaves the same collapse
        // in place, and that case used to be the silent one — the operator had set the
        // flag and had no way to know it was not taking effect.
        // Resolved for either limiter: with only `--rateLimit` on, skipping this charged
        // every client to one key and kept the warning silent.
        if (resolved.forwardedIgnored || (opts.trustProxy !== true && req.headers['x-forwarded-for'])) {
          warnSharedBudget();
        }
      }
      // Checked before the token is compared, not after — so an exhausted budget answers
      // 429 without evaluating the guess. Gating only the 401 path instead would throttle
      // nothing: the comparison would still happen and a correct token would still be
      // served, so the status code would still tell an attacker which guess was right.
      if (authFailureLimiter) {
        const { allowed, retryAfterMs } = authFailureLimiter.peek(key);
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
              message: `Too many failed authentication attempts. Retry after ${retryAfterSec}s.`,
            },
            id: null,
          }));
          return;
        }
      }

      const auth = req.headers.authorization || '';
      const expected = `Bearer ${bearerToken}`;
      const authBuf = Buffer.from(auth);
      const expectedBuf = Buffer.from(expected);
      const match = authBuf.length === expectedBuf.length &&
        timingSafeEqual(authBuf, expectedBuf);
      if (!match) {
        authFailureLimiter?.recordFailure(key);
        // RFC 7235: a 401 must say how to authenticate. MCP clients also parse
        // JSON-RPC envelopes on this route, so 401 speaks the same dialect as
        // the 429 and 413 responses rather than a bare {error}.
        res.writeHead(401, {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer realm="ssh-mcp"',
        });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32001, message: 'Unauthorized' },
          id: null,
        }));
        return;
      }

      // Charged after the token check, never before: a request bucket is per client, but
      // unauthenticated traffic reaching it could still spend a victim's budget under a
      // spoofable key, and its 429 would answer a guess without evaluating it. Every
      // authenticated route spends from it, `/status` and 404s included: `/status` was
      // unlimited, so a token holder could poll it without bound.
      if (rateLimiter) {
        const { allowed, retryAfterMs } = rateLimiter.tryConsume(key);
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
            id: null,
          }));
          return;
        }
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
      // `configured` is liveness telling the truth about readiness. Since the server
      // learned to start with nothing configured, an HTTP deployment whose config bind
      // mount silently did not attach comes up, binds the port, and fails 100% of tool
      // calls — while this probe said `healthy: true` and the explaining stderr warning
      // scrolled past at boot. The status stays 200 so an existing probe does not start
      // failing on upgrade; the field is what an operator can alert on.
      //
      // It widens what this unauthenticated route discloses by exactly one bit, and that
      // bit is worth little to anyone: a server with no profile is one that cannot reach
      // any host. `/status` carries the profile list itself and stays behind the token.
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ healthy: true, configured: registry.listAllProfiles().length > 0 }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  // Previously listen() had no error handler, so EADDRINUSE surfaced as an
  // unhandled 'error' event and a raw stack — and startHttpServer resolved
  // immediately regardless, so the caller carried on as if the server was up.
  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', (err: NodeJS.ErrnoException) => {
      // OperatorError, not Error: every listen failure at this point is about how the
      // server was invoked — a port already taken, a privileged port, a mistyped
      // --httpHost. Leaving them on the defect path printed a stack and exited 1, which
      // under this codebase's rule invites the operator to report their own port choice
      // as a bug.
      reject(new OperatorError(
        err.code === 'EADDRINUSE'
          ? `Cannot bind ${host}:${port} — address already in use.`
          : `Cannot bind ${host}:${port}: ${err.message}`,
      ));
    });
    httpServer.listen(port, host, () => {
      console.error(`SSH MCP Server v2 (HTTP) listening on http://${host}:${port}`);
      console.error('Endpoints: POST / (MCP), GET /status, GET /health');
      if (rateLimiter) {
        console.error(`Rate limit: ${opts.rateLimit} req/min per client`);
      }
      if (authFailureLimiter) {
        console.error(`Auth failure limit: ${authFailureLimit}/min per client`);
      }
      resolve();
    });
  });
}
