/**
 * SSE producer integration: verifies that the WebUI's SSE stream emits
 *   - `execution` events when the real AuditStore.append succeeds
 *   - `pending-approval` enqueue events when a real ManualApproval engine
 *     enqueues a request
 *   - `pending-approval` resolve events when the request is resolved
 *
 * These wire the AuditStore + ApprovalDispatcher through the same adapter
 * functions src/index.ts uses at boot.
 */
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { startWebUI } from '../server.js';
import type {
  WebUIHandle,
  AuditTail,
  RegistrySnapshot,
} from '../types.js';
import { AuditStore } from '../../audit/store.js';
import { ApprovalDispatcher } from '../../approval/engine.js';
import { buildWebUIApprovalQueueAdapter } from '../../index.js';

const fakeRegistry: RegistrySnapshot = {
  list: () => [
    {
      name: 'prod',
      description: 'production bastion',
      host: 'h',
      port: 22,
      username: 'u',
      transport: 'openssh',
      authMode: 'kerberos',
      connected: true,
      isDefault: true,
    },
  ],
};

function buildAuditAdapter(store: AuditStore): AuditTail {
  return {
    tail: async (opts) => {
      const records = await store.tail(opts);
      return records.map((r: any) => ({
        ts: r.ts,
        id: r.id,
        profile: r.profile,
        tool: r.tool,
        command: r.command,
        description: r.description,
        approval: r.approval,
        exec: r.exec
          ? {
              exit_code: r.exec.exit_code ?? undefined,
              duration_ms: r.exec.duration_ms,
              stdout_truncated: r.exec.stdout_truncated,
              stderr_truncated: r.exec.stderr_truncated,
              stdout: r.exec.stdout,
              stderr: r.exec.stderr,
            }
          : undefined,
      }));
    },
    on: (event, listener) => { store.on(event, (r: any) => listener(r)); },
    off() { /* not exercised */ },
  };
}

async function readUntil(reader: ReadableStreamDefaultReader<Uint8Array>, buf: { value: string }, marker: string, timeoutMs = 3000): Promise<string> {
  const dec = new TextDecoder();
  const deadline = Date.now() + timeoutMs;
  if (buf.value.includes(marker)) return buf.value;
  while (Date.now() < deadline) {
    const { value, done } = await reader.read();
    if (done) break;
    buf.value += dec.decode(value, { stream: true });
    if (buf.value.includes(marker)) return buf.value;
  }
  return buf.value;
}

describe('WebUI SSE producers (boot-wired adapters)', () => {
  let dir: string;
  let store: AuditStore;
  let engine: ApprovalDispatcher;
  let handle: WebUIHandle;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'ssh-mcp-sse-'));
    store = new AuditStore({ auditDir: dir, auditMaxBytes: 1024 });
    engine = new ApprovalDispatcher({
      defaultMode: 'manual',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });
    handle = await startWebUI({
      host: '127.0.0.1',
      port: 0,
      registry: fakeRegistry,
      queue: buildWebUIApprovalQueueAdapter(engine),
      audit: buildAuditAdapter(store),
    });
  });

  afterEach(async () => {
    await handle.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('emits SSE "execution" event when AuditStore.append succeeds', async () => {
    const ac = new AbortController();
    const resp = await fetch(
      `http://${handle.address.host}:${handle.address.port}/events`,
      { signal: ac.signal },
    );
    expect(resp.status).toBe(200);
    const reader = resp.body!.getReader();
    const buf = { value: '' };

    // Give the SseHub a moment to subscribe.
    await new Promise(r => setTimeout(r, 50));

    // Trigger an audit append — should fire 'execution' to SSE subscribers.
    store.append({
      profile: 'prod',
      tool: 'exec',
      command: 'uptime',
      approval: {
        mode: 'smart',
        decision: 'allow',
        reason: 'ok',
        decided_at: new Date().toISOString(),
        decided_by: 'smart-llm',
      },
      exec: { stdout: 'load 0.1', stderr: '', exitCode: 0, durationMs: 5 },
    });

    const seen = await readUntil(reader, buf, 'event: execution');
    try { reader.cancel(); } catch { /* ignore */ }
    ac.abort();
    expect(seen).toContain('event: execution');
    expect(seen).toContain('"profile":"prod"');
    expect(seen).toContain('"decided_by":"smart-llm"');
  });

  it('emits SSE pending-approval enqueue event on manual gateApproval enqueue', async () => {
    const ac = new AbortController();
    const resp = await fetch(
      `http://${handle.address.host}:${handle.address.port}/events`,
      { signal: ac.signal },
    );
    expect(resp.status).toBe(200);
    const reader = resp.body!.getReader();
    const buf = { value: '' };
    await new Promise(r => setTimeout(r, 50));

    const decisionPromise = engine.decide({
      profile: { id: 'prod' },
      tool: 'exec',
      command: 'systemctl restart nginx --token=test-credential',
      description: 'password another-test-credential',
    });
    await Promise.resolve();

    const approvalsResponse = await fetch(
      `http://${handle.address.host}:${handle.address.port}/api/approvals`,
    );
    const approvals = await approvalsResponse.json();
    expect(approvals.approvals[0].command).toBe('systemctl restart nginx --token=<redacted>');
    expect(approvals.approvals[0].description).toBe('password <redacted>');

    const seen = await readUntil(reader, buf, 'event: pending-approval');
    expect(seen).toContain('"action":"enqueue"');
    expect(seen).toContain('systemctl restart nginx --token=<redacted>');
    expect(seen).toContain('password <redacted>');
    expect(seen).not.toContain('test-credential');
    expect(seen).not.toContain('another-test-credential');

    // Resolve via the dispatcher and verify the resolve event also flows.
    const pending = engine.listPending();
    expect(pending).toHaveLength(1);
    engine.resolvePending(pending[0].id, 'allow', 'ok', 'webui:test');
    await decisionPromise;

    const seen2 = await readUntil(reader, buf, '"action":"resolve"');
    try { reader.cancel(); } catch { /* ignore */ }
    ac.abort();
    expect(seen2).toContain('"action":"resolve"');
    expect(seen2).toContain('"decided_by":"webui:test"');

    // Listing now empty.
    const r = await fetch(`http://${handle.address.host}:${handle.address.port}/api/approvals`);
    const j = await r.json();
    expect(j.approvals).toHaveLength(0);
  });

  it('GET /api/executions reads the AuditStore rolling tail', async () => {
    for (let i = 0; i < 3; i++) {
      store.append({
        profile: i === 0 ? 'prod' : 'lab',
        tool: 'exec',
        command: `echo ${i}`,
        approval: {
          mode: 'yolo',
          decision: 'allow',
          reason: 'yolo',
          decided_at: new Date().toISOString(),
          decided_by: 'yolo',
        },
        exec: { stdout: `${i}`, stderr: '', exitCode: 0, durationMs: 1 },
      });
    }
    const r = await fetch(`http://${handle.address.host}:${handle.address.port}/api/executions?limit=10`);
    const j = await r.json();
    expect(j.executions).toHaveLength(3);
    expect(j.executions[0].profile).toBe('prod');

    const r2 = await fetch(`http://${handle.address.host}:${handle.address.port}/api/executions?profile=lab`);
    const j2 = await r2.json();
    expect(j2.executions.every((e: any) => e.profile === 'lab')).toBe(true);
  });
});
