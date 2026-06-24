import { describe, it, expect, vi } from 'vitest';
import {
  ManualApproval,
  ManualApprovalDisabledError,
} from '../manual.js';
import { ApprovalContext } from '../types.js';

const ctx: ApprovalContext = {
  profile: { id: 'prod' },
  tool: 'exec',
  command: 'uptime',
};

describe('ManualApproval — boot guard', () => {
  it('throws when WebUI is disabled', () => {
    expect(() => new ManualApproval({ webuiEnabled: false })).toThrow(
      ManualApprovalDisabledError,
    );
  });

  it('constructs when WebUI is enabled', () => {
    const m = new ManualApproval({ webuiEnabled: true });
    expect(m.listPending()).toEqual([]);
  });
});

describe('ManualApproval — external resolve', () => {
  it('allows when resolved with `allow`', async () => {
    const m = new ManualApproval({ webuiEnabled: true, timeout_ms: 5000 });
    const p = m.decide(ctx);

    // Tick the microtask queue so the queue entry is registered before we
    // attempt to resolve it.
    await Promise.resolve();
    const pending = m.listPending();
    expect(pending).toHaveLength(1);
    const id = pending[0].id;
    expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);

    const ok = m.resolvePending(id, 'allow', 'looks good', 'webui:alice');
    expect(ok).toBe(true);

    const decision = await p;
    expect(decision.decision).toBe('allow');
    expect(decision.reason).toBe('looks good');
    expect(decision.decided_by).toBe('webui:alice');
    expect(decision.mode).toBe('manual');
    expect(m.listPending()).toHaveLength(0);
  });

  it('denies when resolved with `deny`', async () => {
    const m = new ManualApproval({ webuiEnabled: true, timeout_ms: 5000 });
    const p = m.decide(ctx);
    await Promise.resolve();
    const id = m.listPending()[0].id;
    expect(m.resolvePending(id, 'deny', 'not now')).toBe(true);
    const d = await p;
    expect(d.decision).toBe('deny');
    expect(d.reason).toBe('not now');
  });

  it('resolvePending on unknown id returns false', () => {
    const m = new ManualApproval({ webuiEnabled: true });
    expect(m.resolvePending('does-not-exist', 'allow')).toBe(false);
  });

  it('keeps multiple pending entries independent', async () => {
    const m = new ManualApproval({ webuiEnabled: true, timeout_ms: 5000 });
    const p1 = m.decide(ctx);
    const p2 = m.decide({ ...ctx, command: 'whoami' });
    await Promise.resolve();
    const pending = m.listPending();
    expect(pending).toHaveLength(2);
    m.resolvePending(pending[0].id, 'allow');
    m.resolvePending(pending[1].id, 'deny');
    const [d1, d2] = await Promise.all([p1, p2]);
    expect(d1.decision).toBe('allow');
    expect(d2.decision).toBe('deny');
  });
});

describe('ManualApproval — timeout', () => {
  it('times out and denies with "approval timed out"', async () => {
    vi.useFakeTimers();
    try {
      const m = new ManualApproval({ webuiEnabled: true, timeout_ms: 100 });
      const p = m.decide(ctx);
      // Let the constructor enqueue
      await Promise.resolve();
      expect(m.listPending()).toHaveLength(1);

      vi.advanceTimersByTime(150);
      const d = await p;
      expect(d.decision).toBe('deny');
      expect(d.reason).toBe('approval timed out');
      expect(d.decided_by).toBe('manual:timeout');
      expect(m.listPending()).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('resolve after timeout is a no-op', async () => {
    vi.useFakeTimers();
    try {
      const m = new ManualApproval({ webuiEnabled: true, timeout_ms: 50 });
      const p = m.decide(ctx);
      await Promise.resolve();
      const id = m.listPending()[0].id;
      vi.advanceTimersByTime(100);
      await p;
      expect(m.resolvePending(id, 'allow')).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});
