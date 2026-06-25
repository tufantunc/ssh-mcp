/**
 * WebUI live mode-switch routes + SSE (PR-7).
 *
 * Exercises the HTTP surface end-to-end against a fake ModeController:
 *   - GET  /api/approval-modes
 *   - PUT  /api/profiles/:id/approval-mode        (per-profile override + clear)
 *   - PUT  /api/approval-mode                      (global)
 *   - SSE  mode-changed broadcast on a switch
 *   - 503 when no controller is wired; 400 on bad mode / malformed body
 *
 * In-memory only (Decision D3): the fake controller holds state in JS maps,
 * exactly like the real ApprovalModeStore — there is no disk surface.
 */
import { EventEmitter } from 'node:events';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { startWebUI } from '../server.js';
import type {
  WebUIHandle,
  RegistrySnapshot,
  ModeController,
  ModeChangedEvent,
} from '../types.js';

const fakeRegistry: RegistrySnapshot = {
  list: () => [
    {
      name: 'prod', description: 'production bastion', host: 'h', port: 22,
      username: 'u', transport: 'openssh', authMode: 'kerberos', connected: true, isDefault: true,
    },
    {
      name: 'lab', description: 'lab', host: 'h2', port: 22,
      username: 'r', transport: 'ssh2', authMode: 'key', connected: false, isDefault: false,
    },
  ],
};

/** In-memory fake mirroring ApprovalModeStore semantics. */
class FakeModeController extends EventEmitter implements ModeController {
  private global = 'yolo';
  private overrides = new Map<string, string>();
  private readonly armed: string[];
  constructor(armed: string[] = ['yolo', 'manual']) {
    super();
    this.armed = armed;
  }
  availableModes(): string[] { return [...this.armed]; }
  getGlobalMode(): string { return this.global; }
  getEffectiveMode(profileId: string): string {
    return this.overrides.get(profileId) ?? this.global;
  }
  setProfileMode(profileId: string, mode: string | null): ModeChangedEvent {
    if (mode === null) this.overrides.delete(profileId);
    else {
      if (!this.armed.includes(mode)) throw new Error(`mode "${mode}" not available`);
      this.overrides.set(profileId, mode);
    }
    const ev: ModeChangedEvent = {
      scope: 'profile', profileId, mode: mode ?? this.getEffectiveMode(profileId),
      effective: this.getEffectiveMode(profileId), at: new Date().toISOString(),
    };
    this.emit('mode-changed', ev);
    return ev;
  }
  setGlobalMode(mode: string): ModeChangedEvent {
    if (!this.armed.includes(mode)) throw new Error(`mode "${mode}" not available`);
    this.global = mode;
    const ev: ModeChangedEvent = {
      scope: 'global', mode, effective: mode, at: new Date().toISOString(),
    };
    this.emit('mode-changed', ev);
    return ev;
  }
}

async function req(handle: WebUIHandle, path: string, init?: RequestInit) {
  return fetch(`http://${handle.address.host}:${handle.address.port}${path}`, init);
}
const putJson = (body: unknown): RequestInit => ({
  method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});

describe('WebUI mode-switch routes (controller wired)', () => {
  let handle: WebUIHandle;
  let controller: FakeModeController;

  beforeEach(async () => {
    controller = new FakeModeController(['yolo', 'manual']);
    handle = await startWebUI({
      host: '127.0.0.1', port: 0, registry: fakeRegistry,
      modeController: controller,
      getApprovalMode: name => controller.getEffectiveMode(name),
    });
  });
  afterEach(async () => { await handle.close(); });

  it('GET /api/approval-modes returns armed modes + global', async () => {
    const r = await req(handle, '/api/approval-modes');
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j.modes).toEqual(['yolo', 'manual']);
    expect(j.global).toBe('yolo');
  });

  it('PUT /api/profiles/:id/approval-mode sets a per-profile override', async () => {
    const r = await req(handle, '/api/profiles/prod/approval-mode', putJson({ mode: 'manual' }));
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j).toMatchObject({ ok: true, scope: 'profile', profileId: 'prod', effective: 'manual' });
    expect(controller.getEffectiveMode('prod')).toBe('manual');
    expect(controller.getEffectiveMode('lab')).toBe('yolo');
  });

  it('PUT with mode:null clears the override', async () => {
    await req(handle, '/api/profiles/prod/approval-mode', putJson({ mode: 'manual' }));
    expect(controller.getEffectiveMode('prod')).toBe('manual');
    const r = await req(handle, '/api/profiles/prod/approval-mode', putJson({ mode: null }));
    expect(r.status).toBe(200);
    expect(controller.getEffectiveMode('prod')).toBe('yolo');
  });

  it('PUT /api/approval-mode switches the global default', async () => {
    const r = await req(handle, '/api/approval-mode', putJson({ mode: 'manual' }));
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j).toMatchObject({ ok: true, scope: 'global', mode: 'manual' });
    expect(controller.getGlobalMode()).toBe('manual');
  });

  it('rejects an unavailable mode with 400 and the available list', async () => {
    const r = await req(handle, '/api/profiles/prod/approval-mode', putJson({ mode: 'smart' }));
    expect(r.status).toBe(400);
    const j = await r.json();
    expect(j.available).toEqual(['yolo', 'manual']);
    // State untouched.
    expect(controller.getEffectiveMode('prod')).toBe('yolo');
  });

  it('rejects a malformed body (no mode key) with 400', async () => {
    const r = await req(handle, '/api/profiles/prod/approval-mode', putJson({ nope: 1 }));
    expect(r.status).toBe(400);
  });

  it('broadcasts a mode-changed SSE event when a switch is applied', async () => {
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
        if (buffer.includes('event: mode-changed')) return true;
      }
      return false;
    })();

    await new Promise(r => setTimeout(r, 50));
    await req(handle, '/api/profiles/prod/approval-mode', putJson({ mode: 'manual' }));

    const got = await seen;
    try { reader.cancel(); } catch { /* ignore */ }
    ac.abort();
    expect(got).toBe(true);
    expect(buffer).toContain('"scope":"profile"');
    expect(buffer).toContain('"effective":"manual"');
  });
});

describe('WebUI mode-switch routes (no controller wired)', () => {
  let handle: WebUIHandle;
  beforeEach(async () => {
    handle = await startWebUI({ host: '127.0.0.1', port: 0, registry: fakeRegistry });
  });
  afterEach(async () => { await handle.close(); });

  it('GET /api/approval-modes returns 503 when mode switching disabled', async () => {
    const r = await req(handle, '/api/approval-modes');
    expect(r.status).toBe(503);
  });

  it('PUT /api/profiles/:id/approval-mode returns 503 when disabled', async () => {
    const r = await req(handle, '/api/profiles/prod/approval-mode', putJson({ mode: 'manual' }));
    expect(r.status).toBe(503);
  });
});
