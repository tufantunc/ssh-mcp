/**
 * WebUI config-reload SSE wiring (PR-9).
 *
 * Proves the boot path's reloadController -> SseHub -> /events fan-out: when the
 * ConfigReloader emits `config-reloaded`, every open dashboard receives the SSE
 * frame and can re-fetch server truth. Uses a fake EventEmitter-shaped
 * controller (exactly the adapter src/index.ts builds around the real
 * ConfigReloader) so no SSH host / disk config is involved.
 */
import { EventEmitter } from 'node:events';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { startWebUI } from '../server.js';
import type { WebUIHandle, RegistrySnapshot, ConfigReloadController, ConfigReloadedEvent } from '../types.js';

const fakeRegistry: RegistrySnapshot = {
  list: () => [
    {
      name: 'prod', description: 'production bastion', host: 'h', port: 22,
      username: 'u', transport: 'openssh', authMode: 'kerberos', connected: true, isDefault: true,
    },
  ],
};

/** Minimal EventEmitter-backed controller mirroring the real reloader adapter. */
class FakeReloadController extends EventEmitter implements ConfigReloadController {
  fire(e: ConfigReloadedEvent) { this.emit('config-reloaded', e); }
}

describe('WebUI config-reloaded SSE (controller wired)', () => {
  let handle: WebUIHandle;
  let controller: FakeReloadController;

  beforeEach(async () => {
    controller = new FakeReloadController();
    handle = await startWebUI({
      host: '127.0.0.1', port: 0, registry: fakeRegistry,
      reloadController: controller,
    });
  });
  afterEach(async () => { await handle.close(); });

  it('broadcasts a config-reloaded SSE event when the reloader fires', async () => {
    const ac = new AbortController();
    const resp = await fetch(`http://${handle.address.host}:${handle.address.port}/events`, { signal: ac.signal });
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
        if (buffer.includes('event: config-reloaded')) return true;
      }
      return false;
    })();

    // Give the SseHub a moment to subscribe, then fire a reload event.
    await new Promise(r => setTimeout(r, 50));
    controller.fire({ sources: ['prod', 'lab'], defaultName: 'prod', at: new Date().toISOString() });

    const got = await seen;
    try { reader.cancel(); } catch { /* ignore */ }
    ac.abort();
    expect(got).toBe(true);
    expect(buffer).toContain('"sources":["prod","lab"]');
    expect(buffer).toContain('"defaultName":"prod"');
  });
});

describe('WebUI config-reloaded SSE (no controller wired)', () => {
  it('starts fine and serves /events without a reload controller', async () => {
    const handle = await startWebUI({ host: '127.0.0.1', port: 0, registry: fakeRegistry });
    try {
      const ac = new AbortController();
      const resp = await fetch(`http://${handle.address.host}:${handle.address.port}/events`, { signal: ac.signal });
      expect(resp.status).toBe(200);
      ac.abort();
    } finally {
      await handle.close();
    }
  });
});
