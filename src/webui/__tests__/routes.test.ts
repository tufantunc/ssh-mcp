import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import http from 'node:http';

import { startWebUI } from '../server.js';
import type {
  WebUIHandle,
  ManualApprovalQueue,
  AuditTail,
  RegistrySnapshot,
  PendingApproval,
  ApprovalDecision,
  AuditRecord,
} from '../types.js';

// ----- in-memory stub queue -------------------------------------------------

class FakeQueue extends EventEmitter implements ManualApprovalQueue {
  private items = new Map<string, PendingApproval>();
  private resolvers = new Map<string, (d: ApprovalDecision) => void>();

  enqueue(p: PendingApproval): Promise<ApprovalDecision> {
    this.items.set(p.id, p);
    this.emit('enqueue', p);
    return new Promise<ApprovalDecision>(resolve => {
      this.resolvers.set(p.id, resolve);
    });
  }

  list(): PendingApproval[] {
    return Array.from(this.items.values());
  }

  resolve(id: string, decision: ApprovalDecision): boolean {
    const p = this.items.get(id);
    const r = this.resolvers.get(id);
    if (!p || !r) return false;
    this.items.delete(id);
    this.resolvers.delete(id);
    this.emit('resolve', p, decision);
    r(decision);
    return true;
  }
}

class FakeAudit extends EventEmitter implements AuditTail {
  records: AuditRecord[] = [];
  async tail(opts: { profile?: string; limit: number }): Promise<AuditRecord[]> {
    let rs = this.records;
    if (opts.profile) rs = rs.filter(r => r.profile === opts.profile);
    return rs.slice(-opts.limit);
  }
  push(r: AuditRecord): void {
    this.records.push(r);
    this.emit('execution', r);
  }
}

const fakeRegistry: RegistrySnapshot = {
  list: () => ([
    {
      name: 'prod',
      description: 'production bastion',
      host: 'bastion.example.com',
      port: 22,
      username: 'admin',
      transport: 'openssh',
      authMode: 'kerberos',
      connected: true,
      isDefault: true,
      password: 'super-secret-password',
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----',
      keytab: '/etc/krb5.keytab',
    },
    {
      name: 'lab',
      description: 'lab jump host',
      host: 'lab.internal',
      port: 22,
      username: 'root',
      transport: 'ssh2',
      authMode: 'key',
      connected: false,
      isDefault: false,
    },
  ] as any),
};

// ----- helpers --------------------------------------------------------------

async function get(handle: WebUIHandle, p: string, headers: Record<string, string> = {}) {
  const url = `http://${handle.address.host}:${handle.address.port}${p}`;
  return fetch(url, { headers });
}

async function rawGet(
  handle: WebUIHandle,
  p: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: handle.address.host,
        port: handle.address.port,
        path: p,
        method: 'GET',
        headers,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', chunk => { body += chunk; });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

// ----- tests ----------------------------------------------------------------

describe('WebUI server', () => {
  let handle: WebUIHandle;
  let queue: FakeQueue;
  let audit: FakeAudit;

  beforeEach(async () => {
    queue = new FakeQueue();
    audit = new FakeAudit();
    handle = await startWebUI({
      host: '127.0.0.1',
      port: 0,
      registry: fakeRegistry,
      queue,
      audit,
      getApprovalMode: name => (name === 'prod' ? 'manual' : 'yolo'),
    });
  });

  afterEach(async () => {
    await handle.close();
  });

  it('GET /api/profiles returns registry snapshot with approval mode', async () => {
    const r = await get(handle, '/api/profiles');
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j.profiles).toHaveLength(2);
    const prod = j.profiles.find((p: any) => p.id === 'prod');
    expect(prod).toMatchObject({
      name: 'prod',
      description: 'production bastion',
      host: 'bastion.example.com',
      auth: 'kerberos',
      transport: 'openssh',
      connected: true,
      default: true,
      approval_mode_effective: 'manual',
    });
    const serialized = JSON.stringify(prod);
    expect(serialized).not.toContain('super-secret-password');
    expect(serialized).not.toContain('OPENSSH PRIVATE KEY');
    expect(serialized).not.toContain('krb5.keytab');
  });

  it('GET /api/executions returns audit tail and respects limit', async () => {
    for (let i = 0; i < 5; i++) {
      audit.push({
        ts: new Date().toISOString(),
        id: `id-${i}`,
        profile: i % 2 === 0 ? 'prod' : 'lab',
        tool: 'exec',
        command: `echo ${i}`,
        approval: { mode: 'yolo', decision: 'allow', reason: 'ok', decided_at: '', decided_by: 'yolo' },
      });
    }
    const r = await get(handle, '/api/executions?limit=3');
    const j = await r.json();
    expect(j.executions).toHaveLength(3);

    const r2 = await get(handle, '/api/executions?profile=prod');
    const j2 = await r2.json();
    expect(j2.executions.every((e: any) => e.profile === 'prod')).toBe(true);
  });

  it('GET /api/approvals lists pending items', async () => {
    queue.enqueue({
      id: 'a-1',
      profile: 'prod',
      tool: 'exec',
      command: 'systemctl restart nginx',
      enqueuedAt: new Date().toISOString(),
    });
    const r = await get(handle, '/api/approvals');
    const j = await r.json();
    expect(j.approvals).toHaveLength(1);
    expect(j.approvals[0].id).toBe('a-1');
  });


  it('static index page is served on loopback without token', async () => {
    const r = await get(handle, '/');
    expect(r.status).toBe(200);
    const text = await r.text();
    expect(text).toContain('ssh-mcp');
    expect(r.headers.get('content-type') || '').toMatch(/text\/html/);
  });

  it('unknown api route returns 404', async () => {
    const r = await get(handle, '/api/does-not-exist');
    expect(r.status).toBe(404);
  });
});

describe('WebUI auth', () => {
  let handle: WebUIHandle;
  let queue: FakeQueue;

  afterEach(async () => {
    if (handle) await handle.close();
  });

  it('refuses non-loopback bind without auth_token', async () => {
    await expect(
      startWebUI({ host: '0.0.0.0', port: 0, registry: fakeRegistry }),
    ).rejects.toThrow(/auth_token/i);
  });

  it('refuses a whitespace-only auth_token on a non-loopback bind', async () => {
    await expect(
      startWebUI({ host: '0.0.0.0', port: 0, registry: fakeRegistry, authToken: ' \t\n ' }),
    ).rejects.toThrow(/auth_token/i);
  });

  it('refuses a provided whitespace-only auth_token on a loopback bind', async () => {
    await expect(
      startWebUI({ host: '127.0.0.1', port: 0, registry: fakeRegistry, authToken: ' \t\n ' }),
    ).rejects.toThrow(/auth_token/i);
  });

  it('loopback without token allows api access (no token configured)', async () => {
    handle = await startWebUI({ host: '127.0.0.1', port: 0, registry: fakeRegistry });
    const r = await get(handle, '/api/profiles');
    expect(r.status).toBe(200);
  });

  it('tokenless loopback rejects DNS-rebinding Host/Origin for APIs and SSE', async () => {
    handle = await startWebUI({ host: '127.0.0.1', port: 0, registry: fakeRegistry });

    const badHost = await rawGet(handle, '/api/profiles', { Host: 'evil.example' });
    expect(badHost.status).toBe(401);

    const badOrigin = await rawGet(handle, '/api/profiles', {
      Host: `127.0.0.1:${handle.address.port}`,
      Origin: 'http://evil.example',
    });
    expect(badOrigin.status).toBe(401);

    const badSseHost = await rawGet(handle, '/events', { Host: 'evil.example' });
    expect(badSseHost.status).toBe(401);

    const good = await rawGet(handle, '/api/profiles', {
      Host: `localhost:${handle.address.port}`,
      Origin: `http://localhost:${handle.address.port}`,
    });
    expect(good.status).toBe(200);
  });

  it('with auth_token, /api requires Bearer token', async () => {
    queue = new FakeQueue();
    handle = await startWebUI({
      host: '127.0.0.1', port: 0, registry: fakeRegistry, queue,
      authToken: 'secret-shibboleth',
    });

    const bad = await get(handle, '/api/profiles');
    expect(bad.status).toBe(401);

    const good = await get(handle, '/api/profiles', { Authorization: 'Bearer secret-shibboleth' });
    expect(good.status).toBe(200);
  });

  it('trims configured auth_token before authenticating requests', async () => {
    handle = await startWebUI({
      host: '127.0.0.1', port: 0, registry: fakeRegistry,
      authToken: '  secret-shibboleth  ',
    });

    const good = await get(handle, '/api/profiles', { Authorization: 'Bearer secret-shibboleth' });
    expect(good.status).toBe(200);
  });

  it('SSE /events accepts ?token= query', async () => {
    handle = await startWebUI({
      host: '127.0.0.1', port: 0, registry: fakeRegistry,
      authToken: 'tok-1',
    });
    // Without token -> 401
    const bad = await get(handle, '/events');
    expect(bad.status).toBe(401);

    // With token -> upgrade to event-stream. We don't fully read the stream;
    // just confirm the 200 + content-type and abort.
    const ac = new AbortController();
    const ok = await fetch(`http://${handle.address.host}:${handle.address.port}/events?token=tok-1`, {
      signal: ac.signal,
    });
    expect(ok.status).toBe(200);
    expect(ok.headers.get('content-type') || '').toMatch(/event-stream/);
    ac.abort();
  });
});

describe('WebUI SSE round-trip', () => {
  it('broadcasts pending-approval events to subscribed clients', async () => {
    const queue = new FakeQueue();
    const audit = new FakeAudit();
    const handle = await startWebUI({
      host: '127.0.0.1', port: 0, registry: fakeRegistry, queue, audit,
    });

    const ac = new AbortController();
    const url = `http://${handle.address.host}:${handle.address.port}/events`;
    const resp = await fetch(url, { signal: ac.signal });
    expect(resp.status).toBe(200);

    // Read first chunk(s) until we see our event.
    const reader = resp.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    const seen = (async () => {
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        if (buffer.includes('event: pending-approval')) return true;
      }
      return false;
    })();

    // Give the client a moment to attach.
    await new Promise(r => setTimeout(r, 50));
    queue.enqueue({
      id: 'sse-1', profile: 'prod', tool: 'exec', command: 'whoami', enqueuedAt: new Date().toISOString(),
    });

    const got = await seen;
    ac.abort();
    expect(got).toBe(true);
    await handle.close();
  });
});
