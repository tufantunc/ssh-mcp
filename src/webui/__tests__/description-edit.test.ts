/**
 * WebUI live description-edit route + SSE (PR-8).
 *
 * Exercises the HTTP surface end-to-end against a fake SourceController:
 *   - PUT  /api/sources/:id/description        (set + blank + revert)
 *   - SSE  source-updated broadcast on an edit
 *   - GET  /api/profiles exposes source_edit_enabled
 *   - 503 when no controller is wired; 404 unknown source; 400 bad body
 *
 * In-memory only (Decision D3): the fake controller holds state in a JS map,
 * exactly like the real TransportRegistry override path — no disk surface.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { startWebUI } from '../server.js';
import type {
  WebUIHandle,
  RegistrySnapshot,
  SourceController,
  SourceUpdatedEvent,
} from '../types.js';

const fakeRegistry: RegistrySnapshot = {
  list: () => [
    {
      name: 'prod', description: 'production bastion', host: 'h', port: 22,
      username: 'u', transport: 'openssh', authMode: 'kerberos', connected: true, isDefault: true,
    },
    {
      name: 'lab', description: '', host: 'h2', port: 22,
      username: 'r', transport: 'ssh2', authMode: 'key', connected: false, isDefault: false,
    },
  ],
};

/** In-memory fake mirroring the registry override semantics. */
class FakeSourceController implements SourceController {
  private overrides = new Map<string, string>();
  private listeners = new Set<(e: SourceUpdatedEvent) => void>();
  private readonly boot: Record<string, string>;
  constructor(boot: Record<string, string> = { prod: 'production bastion', lab: '' }) {
    this.boot = boot;
  }
  hasSource(id: string): boolean { return id in this.boot; }
  getEffectiveDescription(id: string): string {
    return this.overrides.has(id) ? this.overrides.get(id)! : (this.boot[id] ?? '');
  }
  setDescription(id: string, description: string | null): SourceUpdatedEvent {
    if (!(id in this.boot)) throw new Error(`unknown source: ${id}`);
    if (description === null) this.overrides.delete(id);
    else this.overrides.set(id, description);
    const ev: SourceUpdatedEvent = {
      id, description: this.getEffectiveDescription(id), at: new Date().toISOString(),
    };
    for (const l of this.listeners) l(ev);
    return ev;
  }
  on(_event: 'source-updated', listener: (e: SourceUpdatedEvent) => void): void {
    this.listeners.add(listener);
  }
  off(_event: 'source-updated', listener: (...args: any[]) => void): void {
    this.listeners.delete(listener as any);
  }
}

async function req(handle: WebUIHandle, path: string, init?: RequestInit) {
  const origin = `http://${handle.address.host}:${handle.address.port}`;
  const nextInit: RequestInit | undefined = init ? { ...init } : undefined;
  if (nextInit?.method && nextInit.method.toUpperCase() !== 'GET') {
    const headers = new Headers(nextInit.headers);
    if (!headers.has('Origin')) headers.set('Origin', origin);
    nextInit.headers = headers;
  }
  return fetch(`${origin}${path}`, nextInit);
}
const putJson = (body: unknown): RequestInit => ({
  method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});

describe('WebUI description-edit routes (controller wired)', () => {
  let handle: WebUIHandle;
  let controller: FakeSourceController;

  beforeEach(async () => {
    controller = new FakeSourceController();
    handle = await startWebUI({
      host: '127.0.0.1', port: 0, registry: fakeRegistry,
      sourceController: controller,
    });
  });
  afterEach(async () => { await handle.close(); });

  it('GET /api/profiles advertises source_edit_enabled=true', async () => {
    const r = await req(handle, '/api/profiles');
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j.source_edit_enabled).toBe(true);
  });

  it('PUT /api/sources/:id/description sets a live override', async () => {
    const r = await req(handle, '/api/sources/prod/description', putJson({ description: 'LIVE: locked down' }));
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j).toMatchObject({ ok: true, id: 'prod', description: 'LIVE: locked down' });
    expect(controller.getEffectiveDescription('prod')).toBe('LIVE: locked down');
    // Other sources untouched.
    expect(controller.getEffectiveDescription('lab')).toBe('');
  });

  it('PUT with empty string blanks the description', async () => {
    const r = await req(handle, '/api/sources/prod/description', putJson({ description: '' }));
    expect(r.status).toBe(200);
    expect(controller.getEffectiveDescription('prod')).toBe('');
  });

  it('PUT with description:null reverts to the boot/config value', async () => {
    await req(handle, '/api/sources/prod/description', putJson({ description: 'temp' }));
    expect(controller.getEffectiveDescription('prod')).toBe('temp');
    const r = await req(handle, '/api/sources/prod/description', putJson({ description: null }));
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j.description).toBe('production bastion');
    expect(controller.getEffectiveDescription('prod')).toBe('production bastion');
  });

  it('returns 404 for an unknown source', async () => {
    const r = await req(handle, '/api/sources/ghost/description', putJson({ description: 'x' }));
    expect(r.status).toBe(404);
    const j = await r.json();
    expect(j.error).toMatch(/unknown source/);
  });

  it('rejects a malformed body (no description key) with 400', async () => {
    const r = await req(handle, '/api/sources/prod/description', putJson({ nope: 1 }));
    expect(r.status).toBe(400);
    // State untouched.
    expect(controller.getEffectiveDescription('prod')).toBe('production bastion');
  });

  it('rejects a non-string, non-null description with 400', async () => {
    const r = await req(handle, '/api/sources/prod/description', putJson({ description: 42 }));
    expect(r.status).toBe(400);
  });

  it('rejects cross-origin description-edit mutations before changing state', async () => {
    const evilPut = (body: unknown): RequestInit => ({
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example' },
      body: JSON.stringify(body),
    });
    const r = await req(handle, '/api/sources/prod/description', evilPut({ description: 'hijacked' }));
    expect(r.status).toBe(403);
    const j = await r.json();
    expect(j.error).toMatch(/same-origin loopback/);
    // State untouched.
    expect(controller.getEffectiveDescription('prod')).toBe('production bastion');
  });

  it('rejects description-edit mutations with no Origin/Referer and no token', async () => {
    // Bypass the same-origin helper: send a raw PUT with neither header set.
    const r = await fetch(
      `http://${handle.address.host}:${handle.address.port}/api/sources/prod/description`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: 'no-origin' }),
      },
    );
    expect(r.status).toBe(403);
    // State untouched.
    expect(controller.getEffectiveDescription('prod')).toBe('production bastion');
  });

  it('returns 400 for a malformed percent-encoded source id', async () => {
    const r = await req(handle, '/api/sources/%E0%A4%A/description', putJson({ description: 'x' }));
    expect(r.status).toBe(400);
    const j = await r.json();
    expect(j.error).toMatch(/malformed source id/);
  });

  it('rejects an over-long description with 400', async () => {
    const huge = 'x'.repeat(8193);
    const r = await req(handle, '/api/sources/prod/description', putJson({ description: huge }));
    expect(r.status).toBe(400);
    const j = await r.json();
    expect(j.max).toBe(8192);
    expect(controller.getEffectiveDescription('prod')).toBe('production bastion');
  });

  it('broadcasts a source-updated SSE event when an edit is applied', async () => {
    const ac = new AbortController();
    const resp = await req(handle, '/events', { signal: ac.signal });
    expect(resp.status).toBe(200);
    const reader = resp.body!.getReader();
    const dec = new TextDecoder();
    let buffer = '';

    const seen = (async () => {
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += dec.decode(value, { stream: true });
        if (buffer.includes('event: source-updated')) return true;
      }
      return false;
    })();

    await new Promise(r => setTimeout(r, 50));
    await req(handle, '/api/sources/prod/description', putJson({ description: 'edited via SSE path' }));

    const got = await seen;
    try { reader.cancel(); } catch { /* ignore */ }
    ac.abort();
    expect(got).toBe(true);
    expect(buffer).toContain('"id":"prod"');
    expect(buffer).toContain('"description":"edited via SSE path"');
  });
});

describe('WebUI description-edit routes (no controller wired)', () => {
  let handle: WebUIHandle;
  beforeEach(async () => {
    handle = await startWebUI({ host: '127.0.0.1', port: 0, registry: fakeRegistry });
  });
  afterEach(async () => { await handle.close(); });

  it('PUT /api/sources/:id/description returns 503 when editing disabled', async () => {
    const r = await req(handle, '/api/sources/prod/description', putJson({ description: 'x' }));
    expect(r.status).toBe(503);
  });

  it('GET /api/profiles advertises source_edit_enabled=false', async () => {
    const r = await req(handle, '/api/profiles');
    const j = await r.json();
    expect(j.source_edit_enabled).toBe(false);
  });
});
