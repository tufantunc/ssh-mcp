import { describe, it, expect } from 'vitest';
import { YoloApproval } from '../yolo.js';
import { ApprovalDispatcher } from '../engine.js';
import { ApprovalContext } from '../types.js';

const baseCtx: ApprovalContext = {
  profile: { id: 'prod', description: 'production host' },
  tool: 'exec',
  command: 'uptime',
};

describe('YoloApproval', () => {
  it('always allows', async () => {
    const y = new YoloApproval();
    const d = await y.decide(baseCtx);
    expect(d.decision).toBe('allow');
    expect(d.mode).toBe('yolo');
    expect(d.decided_by).toBe('yolo');
    expect(d.decided_at).toMatch(/T/);
  });
});

describe('ApprovalDispatcher', () => {
  it('dispatches to yolo when defaultMode=yolo', async () => {
    const d = new ApprovalDispatcher({ defaultMode: 'yolo' });
    const r = await d.decide(baseCtx);
    expect(r.decision).toBe('allow');
    expect(r.mode).toBe('yolo');
  });

  it('uses per-source override when provided', async () => {
    const d = new ApprovalDispatcher({ defaultMode: 'yolo' });
    // override to "yolo" again (no smart/manual configured) just to prove the
    // override branch is hit without needing the other engines.
    const ctx: ApprovalContext = {
      ...baseCtx,
      profile: { id: 'lab', approval: { mode: 'yolo' } },
    };
    const r = await d.decide(ctx);
    expect(r.decision).toBe('allow');
  });

  it('throws when smart mode requested but llm options missing', () => {
    expect(() => new ApprovalDispatcher({ defaultMode: 'smart' })).toThrow(
      /\[approval\.llm\] is not configured/,
    );
  });

  it('throws when manual mode requested but options missing', () => {
    expect(() => new ApprovalDispatcher({ defaultMode: 'manual' })).toThrow(
      /WebUI\/manual options/,
    );
  });

  it('rejects per-source override pointing at unconfigured mode', async () => {
    const d = new ApprovalDispatcher({ defaultMode: 'yolo' });
    const ctx: ApprovalContext = {
      ...baseCtx,
      profile: { id: 'prod', approval: { mode: 'smart' } },
    };
    await expect(d.decide(ctx)).rejects.toThrow(/\[approval\.llm\] is not configured/);
  });

  it('listPending returns [] when manual not configured', () => {
    const d = new ApprovalDispatcher({ defaultMode: 'yolo' });
    expect(d.listPending()).toEqual([]);
    expect(d.resolvePending('nonexistent', 'allow')).toBe(false);
  });
});
