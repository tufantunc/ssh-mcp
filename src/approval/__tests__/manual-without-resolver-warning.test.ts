/**
 * manualWithoutResolverWarning — non-fatal boot advisory.
 *
 * The approval-engine lane ships the manual-approval queue primitive but no
 * driver that settles it (the WebUI manual-approval server lands in the child
 * lane pr/webui-manual-approval). When this build boots `manual` mode with the
 * WebUI enabled but no resolver present, every command queues until it times
 * out and is denied. That is a legitimate stacked-PR state, NOT fatal — boot
 * still succeeds — so the warning is the only signal. These tests pin exactly
 * when it fires and when it stays silent.
 */
import { describe, it, expect } from 'vitest';

import { manualWithoutResolverWarning } from '../engine.js';

describe('manualWithoutResolverWarning', () => {
  it('fires: default manual + WebUI enabled + no resolver wired', () => {
    const w = manualWithoutResolverWarning({
      webuiEnabled: true,
      defaultMode: 'manual',
      resolverWired: false,
    });
    expect(w).toContain('manual');
    expect(w).toContain('pr/webui-manual-approval');
    expect(w).toMatch(/no approval resolver is wired/);
  });

  it('fires: omitted default mode (documented manual) + WebUI + no resolver', () => {
    // defaultMode omitted resolves to manual (mirrors buildApprovalEngineFromConfig).
    const w = manualWithoutResolverWarning({
      webuiEnabled: true,
      resolverWired: false,
    });
    expect(w).not.toBeNull();
    expect(w).toContain('manual');
  });

  it('fires: manual only via a per-source override, global default yolo', () => {
    const w = manualWithoutResolverWarning({
      webuiEnabled: true,
      defaultMode: 'yolo',
      perSourceModes: ['manual'],
      resolverWired: false,
    });
    expect(w).not.toBeNull();
  });

  it('silent: resolver IS wired (child WebUI lane present)', () => {
    expect(
      manualWithoutResolverWarning({
        webuiEnabled: true,
        defaultMode: 'manual',
        resolverWired: true,
      }),
    ).toBeNull();
  });

  it('silent: WebUI disabled (manual mode is already fatal-at-boot, gate-12)', () => {
    expect(
      manualWithoutResolverWarning({
        webuiEnabled: false,
        defaultMode: 'manual',
        resolverWired: false,
      }),
    ).toBeNull();
  });

  it('silent: manual mode not in use (yolo default, no manual override)', () => {
    expect(
      manualWithoutResolverWarning({
        webuiEnabled: true,
        defaultMode: 'yolo',
        perSourceModes: ['smart'],
        resolverWired: false,
      }),
    ).toBeNull();
  });

  it('silent: smart-only deployment with WebUI enabled', () => {
    expect(
      manualWithoutResolverWarning({
        webuiEnabled: true,
        defaultMode: 'smart',
        resolverWired: false,
      }),
    ).toBeNull();
  });
});
