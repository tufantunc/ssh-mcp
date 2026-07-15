/**
 * buildApprovalEngineFromConfig — boot-time wiring tests.
 *
 * For each mode (yolo/smart/manual), assert that:
 *   1. The dispatcher built from a [approval]-shaped config object actually
 *      dispatches to the requested engine (no fall-through to legacy yolo).
 *   2. The returned ApprovalDecision carries the right mode + decided_by so
 *      audit records the truth.
 *   3. ManualApproval without WebUI is fatal at boot (gate-12 invariant).
 */
import { describe, it, expect, vi } from 'vitest';

import { buildApprovalEngineFromConfig } from '../engine.js';
import { gateApproval, setApprovalEngine } from '../gate.js';
import { ManualApprovalDisabledError } from '../manual.js';
import { ApprovalContext } from '../types.js';

const baseCtx: ApprovalContext = {
  profile: { id: 'prod' },
  tool: 'exec',
  command: 'uptime',
};

describe('buildApprovalEngineFromConfig — mode dispatch', () => {
  it('mode=yolo wires YoloApproval, decisions carry mode=yolo / decided_by=yolo', async () => {
    const dispatcher = buildApprovalEngineFromConfig(
      { defaultMode: 'yolo' },
      { manualOpts: { webuiEnabled: false } },
    );
    setApprovalEngine(dispatcher);
    try {
      const d = await gateApproval(baseCtx);
      expect(d.decision).toBe('allow');
      expect(d.mode).toBe('yolo');
      expect(d.decided_by).toBe('yolo');
      // Not the legacy:no-engine path.
      expect(d.decided_by).not.toBe('legacy:no-engine');
    } finally {
      setApprovalEngine(null);
    }
  });

  it('mode=smart wires SmartApproval with stubbed fetch (no real LLM call)', async () => {
    const fetchStub = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        choices: [{ message: { content: '{"allow": true, "reason": "stub allowed"}' } }],
      }),
    }));

    const dispatcher = buildApprovalEngineFromConfig(
      {
        defaultMode: 'smart',
        llm: { endpoint: 'http://stub/llm', model: 'stub-model', api_key: 'fake' },
      },
      { manualOpts: { webuiEnabled: false }, smartFetchImpl: fetchStub as any },
    );
    setApprovalEngine(dispatcher);
    try {
      const d = await gateApproval(baseCtx);
      expect(fetchStub).toHaveBeenCalledTimes(1);
      expect(d.decision).toBe('allow');
      expect(d.mode).toBe('smart');
      expect(d.decided_by).toBe('smart-llm');
      expect(d.reason).toBe('stub allowed');
    } finally {
      setApprovalEngine(null);
    }
  });

  it('mode=smart without llm.endpoint/model is fatal at construction', () => {
    expect(() =>
      buildApprovalEngineFromConfig(
        { defaultMode: 'smart' },
        { manualOpts: { webuiEnabled: false } },
      ),
    ).toThrow(/\[approval\.llm\]/);
  });

  it('mode=manual wires ManualApproval when WebUI is enabled', async () => {
    const dispatcher = buildApprovalEngineFromConfig(
      { defaultMode: 'manual' },
      { manualOpts: { webuiEnabled: true, timeout_ms: 5000 } },
    );
    setApprovalEngine(dispatcher);
    try {
      const p = gateApproval(baseCtx);
      await Promise.resolve();
      const pending = dispatcher.listPending();
      expect(pending).toHaveLength(1);
      dispatcher.resolvePending(pending[0].id, 'allow', 'ok', 'webui:test');
      const d = await p;
      expect(d.mode).toBe('manual');
      expect(d.decision).toBe('allow');
      expect(d.decided_by).toBe('webui:test');
    } finally {
      setApprovalEngine(null);
    }
  });

  it('mode=manual without WebUI is FATAL at boot (gate-12 invariant)', () => {
    expect(() =>
      buildApprovalEngineFromConfig(
        { defaultMode: 'manual' },
        { manualOpts: { webuiEnabled: false } },
      ),
    ).toThrow(ManualApprovalDisabledError);
  });

  it('omitted mode defaults to documented manual mode when [approval] is present', async () => {
    const dispatcher = buildApprovalEngineFromConfig(
      {},
      { manualOpts: { webuiEnabled: true, timeout_ms: 5000 } },
    );
    setApprovalEngine(dispatcher);
    try {
      const p = gateApproval(baseCtx);
      await Promise.resolve();
      const pending = dispatcher.listPending();
      expect(pending).toHaveLength(1);
      dispatcher.resolvePending(pending[0].id, 'allow', 'default manual ok', 'webui:test');
      const d = await p;
      expect(d.mode).toBe('manual');
      expect(d.decided_by).toBe('webui:test');
    } finally {
      setApprovalEngine(null);
    }
  });

  it('omitted mode still enforces manual mode WebUI requirement', () => {
    expect(() =>
      buildApprovalEngineFromConfig(
        {},
        { manualOpts: { webuiEnabled: false } },
      ),
    ).toThrow(ManualApprovalDisabledError);
  });

  it('per-source override forces the right sub-engine to be built', async () => {
    // default=yolo, but a per-source override declares manual mode — the
    // dispatcher must construct ManualApproval at boot, not lazily on first use.
    const dispatcher = buildApprovalEngineFromConfig(
      { defaultMode: 'yolo', perSourceModes: ['manual'] },
      { manualOpts: { webuiEnabled: true, timeout_ms: 5000 } },
    );
    setApprovalEngine(dispatcher);
    try {
      // Default profile → yolo allow.
      const yoloDecision = await gateApproval(baseCtx);
      expect(yoloDecision.mode).toBe('yolo');

      // Override profile → manual queues.
      const ctxManual: ApprovalContext = {
        ...baseCtx,
        profile: { id: 'lab', approval: { mode: 'manual' } },
      };
      const p = gateApproval(ctxManual);
      await Promise.resolve();
      const pending = dispatcher.listPending();
      expect(pending).toHaveLength(1);
      dispatcher.resolvePending(pending[0].id, 'allow');
      const d = await p;
      expect(d.mode).toBe('manual');
    } finally {
      setApprovalEngine(null);
    }
  });
});

describe('buildApprovalEngineFromConfig — dispatcher emits queue events', () => {
  it('manual enqueue/resolve are emitted on the dispatcher (for WebUI SSE)', async () => {
    const dispatcher = buildApprovalEngineFromConfig(
      { defaultMode: 'manual' },
      { manualOpts: { webuiEnabled: true, timeout_ms: 5000 } },
    );
    const enq: any[] = [];
    const res: any[] = [];
    dispatcher.on('enqueue', (p: any) => enq.push(p));
    dispatcher.on('resolve', (p: any, d: any) => res.push({ p, d }));
    setApprovalEngine(dispatcher);
    try {
      const promise = dispatcher.decide(baseCtx);
      await Promise.resolve();
      expect(enq).toHaveLength(1);
      expect(enq[0].id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);

      const id = enq[0].id;
      dispatcher.resolvePending(id, 'deny', 'nope', 'webui:bob');
      const d = await promise;
      expect(d.decision).toBe('deny');
      expect(res).toHaveLength(1);
      expect(res[0].d.decision).toBe('deny');
      expect(res[0].d.decided_by).toBe('webui:bob');
    } finally {
      setApprovalEngine(null);
    }
  });
});
