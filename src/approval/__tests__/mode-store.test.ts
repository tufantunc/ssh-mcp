/**
 * ApprovalModeStore — in-memory mutable approval-mode store (Decision D3).
 *
 * These tests pin the precedence rules (live > static > global), the
 * clear-to-reveal semantics, and the in-memory-only guarantee (no fs surface).
 */
import { describe, it, expect } from 'vitest';
import { ApprovalModeStore } from '../mode-store.js';

describe('ApprovalModeStore — precedence', () => {
  it('falls back to the global default when nothing overrides', () => {
    const s = new ApprovalModeStore('yolo');
    expect(s.effective('anything')).toBe('yolo');
    expect(s.effective()).toBe('yolo');
    expect(s.getGlobal()).toBe('yolo');
  });

  it('static override beats global', () => {
    const s = new ApprovalModeStore('yolo', { prod: 'manual' });
    expect(s.effective('prod')).toBe('manual');
    expect(s.effective('lab')).toBe('yolo');
  });

  it('live override beats static and global', () => {
    const s = new ApprovalModeStore('yolo', { prod: 'manual' });
    s.setOverride('prod', 'smart');
    expect(s.effective('prod')).toBe('smart');
    // a profile with no static still picks up its live override
    s.setOverride('lab', 'manual');
    expect(s.effective('lab')).toBe('manual');
  });

  it('clearing a live override (null) reveals the static beneath it', () => {
    const s = new ApprovalModeStore('yolo', { prod: 'manual' });
    s.setOverride('prod', 'smart');
    expect(s.effective('prod')).toBe('smart');
    s.setOverride('prod', null);
    expect(s.effective('prod')).toBe('manual'); // static revealed
  });

  it('clearing a live override with no static reveals the global', () => {
    const s = new ApprovalModeStore('yolo');
    s.setOverride('lab', 'manual');
    expect(s.effective('lab')).toBe('manual');
    s.setOverride('lab', null);
    expect(s.effective('lab')).toBe('yolo'); // global revealed
  });
});

describe('ApprovalModeStore — global mutation', () => {
  it('setGlobal changes the default for every non-overridden profile', () => {
    const s = new ApprovalModeStore('yolo', { prod: 'manual' });
    s.setGlobal('smart');
    expect(s.getGlobal()).toBe('smart');
    expect(s.effective('lab')).toBe('smart');   // no override -> follows global
    expect(s.effective('prod')).toBe('manual');  // static still wins over global
  });
});

describe('ApprovalModeStore — snapshot + introspection', () => {
  it('snapshot exposes only live mutable state (global + live overrides)', () => {
    const s = new ApprovalModeStore('yolo', { prod: 'manual' });
    s.setOverride('lab', 'smart');
    const snap = s.snapshot();
    expect(snap.global).toBe('yolo');
    expect(snap.overrides).toEqual({ lab: 'smart' });
    // The static override is NOT a live override and must not appear here.
    expect(snap.overrides.prod).toBeUndefined();
  });

  it('getLiveOverride / getStaticOverride read the right layer', () => {
    const s = new ApprovalModeStore('yolo', { prod: 'manual' });
    expect(s.getStaticOverride('prod')).toBe('manual');
    expect(s.getLiveOverride('prod')).toBeUndefined();
    s.setOverride('prod', 'smart');
    expect(s.getLiveOverride('prod')).toBe('smart');
    expect(s.getStaticOverride('prod')).toBe('manual'); // static is immutable
  });

  it('is purely in-memory — no fs/path/file surface on the instance', () => {
    const s = new ApprovalModeStore('yolo') as any;
    // Guard against accidental disk write-back being added later (D3).
    for (const k of Object.keys(s)) {
      expect(k.toLowerCase()).not.toMatch(/path|file|fs|disk|toml|persist|write/);
    }
  });
});
