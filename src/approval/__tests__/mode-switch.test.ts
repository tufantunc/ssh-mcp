/**
 * ApprovalDispatcher — live mode-switch (hot-swap) behaviour (PR-7).
 *
 * Covers:
 *   - setGlobalMode / setProfileMode change which engine NEW decisions use
 *   - the swap is atomic: a rejected switch (unarmed engine) leaves state intact
 *   - an IN-FLIGHT manual approval is unaffected when the mode flips underneath
 *     it (no race: the engine was sampled once at decide() time)
 *   - mode-changed events carry the right scope / effective mode
 *   - clearing a profile override reverts to static/global
 */
import { describe, it, expect, vi } from 'vitest';
import { ApprovalDispatcher, ModeUnavailableError, buildApprovalEngineFromConfig } from '../engine.js';
import type { ApprovalContext, ModeChangedPayload } from '../types.js';

const ctxFor = (id: string, command = 'uptime'): ApprovalContext => ({
  profile: { id },
  tool: 'exec',
  command,
});

describe('ApprovalDispatcher — availableModes', () => {
  it('reports only armed sub-engines', () => {
    const yoloOnly = new ApprovalDispatcher({ defaultMode: 'yolo' });
    expect(yoloOnly.availableModes()).toEqual(['yolo']);

    const full = new ApprovalDispatcher({
      defaultMode: 'yolo',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
      smart: {
        llm: { endpoint: 'http://stub/llm', model: 'm' },
        fetchImpl: (async () => ({ ok: true, status: 200, text: async () => '{}' })) as any,
      },
    });
    expect(full.availableModes().sort()).toEqual(['manual', 'smart', 'yolo']);
  });
});

describe('ApprovalDispatcher — global hot-swap', () => {
  it('switches which engine new decisions use; decision reflects the new mode', async () => {
    const d = new ApprovalDispatcher({
      defaultMode: 'yolo',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });

    // Initially yolo -> allow immediately.
    expect(d.defaultMode).toBe('yolo');
    const first = await d.decide(ctxFor('lab'));
    expect(first.mode).toBe('yolo');

    // Live-switch global to manual.
    const ev = d.setGlobalMode('manual');
    expect(ev.scope).toBe('global');
    expect(ev.mode).toBe('manual');
    expect(d.getGlobalMode()).toBe('manual');
    expect(d.defaultMode).toBe('manual');

    // Now a new decision queues (manual) instead of auto-allowing.
    const pending = d.decide(ctxFor('lab'));
    await Promise.resolve();
    const queue = d.listPending();
    expect(queue).toHaveLength(1);
    d.resolvePending(queue[0].id, 'allow', 'ok', 'webui:test');
    const resolved = await pending;
    expect(resolved.mode).toBe('manual');
  });

  it('rejects a switch to an unarmed engine WITHOUT mutating state (atomic)', () => {
    const d = new ApprovalDispatcher({ defaultMode: 'yolo' });
    expect(() => d.setGlobalMode('smart')).toThrow(ModeUnavailableError);
    // State untouched: still yolo.
    expect(d.getGlobalMode()).toBe('yolo');
  });
});

describe('ApprovalDispatcher — per-profile hot-swap', () => {
  it('per-profile override beats global and is reported by getEffectiveMode', async () => {
    const d = new ApprovalDispatcher({
      defaultMode: 'yolo',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });
    const ev = d.setProfileMode('prod', 'manual');
    expect(ev.scope).toBe('profile');
    expect(ev.profileId).toBe('prod');
    expect(ev.effective).toBe('manual');

    expect(d.getEffectiveMode('prod')).toBe('manual');
    expect(d.getEffectiveMode('lab')).toBe('yolo'); // untouched profile follows global

    // prod queues; lab auto-allows.
    const labDecision = await d.decide(ctxFor('lab'));
    expect(labDecision.mode).toBe('yolo');

    const prodPending = d.decide(ctxFor('prod'));
    await Promise.resolve();
    expect(d.listPending()).toHaveLength(1);
  });

  it('clearing a profile override (null) reverts to global', () => {
    const d = new ApprovalDispatcher({
      defaultMode: 'yolo',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });
    d.setProfileMode('prod', 'manual');
    expect(d.getEffectiveMode('prod')).toBe('manual');
    const ev = d.setProfileMode('prod', null);
    expect(ev.effective).toBe('yolo');
    expect(d.getEffectiveMode('prod')).toBe('yolo');
  });

  it('seeds static overrides; clearing a live override reveals the static one', () => {
    const d = new ApprovalDispatcher({
      defaultMode: 'yolo',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
      staticOverrides: { prod: 'manual' },
    });
    expect(d.getEffectiveMode('prod')).toBe('manual'); // static
    d.setProfileMode('prod', 'yolo'); // live override
    expect(d.getEffectiveMode('prod')).toBe('yolo');
    d.setProfileMode('prod', null);   // clear -> reveal static
    expect(d.getEffectiveMode('prod')).toBe('manual');
  });
});

describe('ApprovalDispatcher — in-flight approval is race-free across a switch', () => {
  it('an enqueued manual approval still resolves after the mode flips to yolo', async () => {
    const d = new ApprovalDispatcher({
      defaultMode: 'manual',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });

    // Start a manual decision — it enqueues and awaits resolution.
    const inFlight = d.decide(ctxFor('prod', 'systemctl restart nginx'));
    await Promise.resolve();
    const pending = d.listPending();
    expect(pending).toHaveLength(1);

    // Flip the GLOBAL mode to yolo WHILE the approval is mid-flight.
    d.setGlobalMode('yolo');
    expect(d.getGlobalMode()).toBe('yolo');

    // The in-flight request is unaffected: it is still pending and still
    // resolves through the manual queue (it committed to manual at decide()).
    expect(d.listPending()).toHaveLength(1);
    d.resolvePending(pending[0].id, 'allow', 'late approval', 'webui:test');
    const resolved = await inFlight;
    expect(resolved.mode).toBe('manual');
    expect(resolved.decision).toBe('allow');
    expect(resolved.reason).toBe('late approval');

    // A brand-new decision now takes the yolo path.
    const after = await d.decide(ctxFor('prod'));
    expect(after.mode).toBe('yolo');
  });
});

describe('ApprovalDispatcher — mode-changed events', () => {
  it('emits mode-changed on global and profile switches', () => {
    const d = new ApprovalDispatcher({
      defaultMode: 'yolo',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });
    const events: ModeChangedPayload[] = [];
    d.on('mode-changed', (e: ModeChangedPayload) => events.push(e));

    d.setGlobalMode('manual');
    d.setProfileMode('prod', 'yolo');

    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ scope: 'global', mode: 'manual', effective: 'manual' });
    expect(events[1]).toMatchObject({ scope: 'profile', profileId: 'prod', effective: 'yolo' });
    expect(events[0].at).toMatch(/T/);
  });

  // Finding: clearing a profile override must be distinguishable from setting a
  // live override to the fallback mode. The payload carries an explicit
  // `override` field (the REQUESTED value) so clients can mirror a cleared
  // override instead of keeping a phantom one.
  it('reports the requested override verbatim: mode string on set, null on clear', () => {
    const d = new ApprovalDispatcher({
      defaultMode: 'yolo',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });
    const set = d.setProfileMode('prod', 'manual');
    expect(set.override).toBe('manual');
    expect(set.mode).toBe('manual');
    expect(set.effective).toBe('manual');

    // Clearing reveals the yolo fallback. `mode`/`effective` are the fallback,
    // but `override` MUST be null so the clear is not mistaken for a set-to-yolo.
    const cleared = d.setProfileMode('prod', null);
    expect(cleared.override).toBeNull();
    expect(cleared.mode).toBe('yolo');       // fallback effective
    expect(cleared.effective).toBe('yolo');
  });

  it('global switches carry no override field (profile-only concept)', () => {
    const d = new ApprovalDispatcher({
      defaultMode: 'yolo',
      manual: { webuiEnabled: true, timeout_ms: 5000 },
    });
    const ev = d.setGlobalMode('manual');
    expect(ev.override).toBeUndefined();
  });

  it('does NOT emit when a switch is rejected (no half-applied event)', () => {
    const d = new ApprovalDispatcher({ defaultMode: 'yolo' });
    const spy = vi.fn();
    d.on('mode-changed', spy);
    expect(() => d.setGlobalMode('manual')).toThrow(ModeUnavailableError);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('buildApprovalEngineFromConfig — pre-arms engines for live switching', () => {
  it('pre-arms manual when WebUI is active even if default=yolo (so a live switch to manual works)', () => {
    const d = buildApprovalEngineFromConfig(
      { defaultMode: 'yolo' },
      { manualOpts: { webuiEnabled: true, timeout_ms: 5000 } },
    );
    expect(d.availableModes()).toContain('manual');
    // And the live switch actually succeeds (no ModeUnavailableError).
    expect(() => d.setGlobalMode('manual')).not.toThrow();
    expect(d.getGlobalMode()).toBe('manual');
  });

  it('does NOT pre-arm manual when WebUI is off and manual is unused (gate-12 stays tight)', () => {
    const d = buildApprovalEngineFromConfig(
      { defaultMode: 'yolo' },
      { manualOpts: { webuiEnabled: false } },
    );
    expect(d.availableModes()).toEqual(['yolo']);
    expect(() => d.setGlobalMode('manual')).toThrow(ModeUnavailableError);
  });

  it('pre-arms smart whenever the LLM is fully configured', () => {
    const d = buildApprovalEngineFromConfig(
      { defaultMode: 'yolo', llm: { endpoint: 'http://stub/llm', model: 'm' } },
      {
        manualOpts: { webuiEnabled: false },
        smartFetchImpl: (async () => ({ ok: true, status: 200, text: async () => '{}' })) as any,
      },
    );
    expect(d.availableModes()).toContain('smart');
  });

  it('seeds static overrides from config into the mode store', () => {
    const d = buildApprovalEngineFromConfig(
      { defaultMode: 'yolo', perSourceModes: ['manual'], staticOverrides: { prod: 'manual' } },
      { manualOpts: { webuiEnabled: true, timeout_ms: 5000 } },
    );
    expect(d.getEffectiveMode('prod')).toBe('manual'); // static
    expect(d.getEffectiveMode('lab')).toBe('yolo');     // global
  });

  // Finding: modes declared ONLY in staticOverrides (never in defaultMode or
  // perSourceModes) must still drive sub-engine arming/validation. Otherwise a
  // static-only mode surfaces as an effective mode whose engine was never
  // armed, and the FIRST decision for that profile throws in requireEngineFor.
  // The fix folds Object.values(staticOverrides) into the used-modes set, so
  // such a config now fails FAST at build instead of at first decision.
  it('validates a static-only smart mode: fails fast at build when [approval.llm] is absent', () => {
    expect(() =>
      buildApprovalEngineFromConfig(
        { defaultMode: 'yolo', staticOverrides: { prod: 'smart' } }, // no llm, smart not in perSourceModes
        { manualOpts: { webuiEnabled: true, timeout_ms: 5000 } },
      ),
    ).toThrow(/smart.*requires.*\[approval\.llm\]\.endpoint/i);
  });

  it('validates a static-only manual mode: fails fast at build when WebUI is off (gate-12)', () => {
    expect(() =>
      buildApprovalEngineFromConfig(
        { defaultMode: 'yolo', staticOverrides: { prod: 'manual' } }, // manual not in perSourceModes
        { manualOpts: { webuiEnabled: false } },
      ),
    ).toThrow(); // ManualApprovalDisabledError — manual sub-engine cannot arm without WebUI
  });

  it('arms a static-only smart mode when the LLM is configured (effective mode stays available)', () => {
    const d = buildApprovalEngineFromConfig(
      { defaultMode: 'yolo', staticOverrides: { prod: 'smart' }, llm: { endpoint: 'http://stub/llm', model: 'm' } },
      {
        manualOpts: { webuiEnabled: false },
        smartFetchImpl: (async () => ({ ok: true, status: 200, text: async () => '{}' })) as any,
      },
    );
    expect(d.getEffectiveMode('prod')).toBe('smart');
    // The armed set includes smart, so the static effective mode is switch-able
    // and a decision for that profile will not throw in requireEngineFor.
    expect(d.availableModes()).toContain('smart');
  });
});
