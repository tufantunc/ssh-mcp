import type { ModeController, ModeChangedEvent } from '../types.js';

/**
 * GET /api/approval-modes — list the modes available for live switching plus
 * the current global default. The UI uses this to populate mode dropdowns
 * with only the modes whose sub-engine is actually armed.
 */
export function handleListModes(
  controller: ModeController | undefined,
): { status: number; body: unknown } {
  if (!controller) {
    return { status: 503, body: { error: 'approval-mode controller not configured' } };
  }
  return {
    status: 200,
    body: {
      modes: controller.availableModes(),
      global: controller.getGlobalMode(),
    },
  };
}

/**
 * PUT /api/profiles/:id/approval-mode — live-switch a profile's approval mode
 * (in-memory only, Decision D3).
 *
 * Body: `{ "mode": "yolo" | "smart" | "manual" | null }`.
 *   - a recognized mode string sets a per-profile live override
 *   - `null` clears the override, reverting to the static/global mode
 *
 * Returns 400 on a malformed body or a mode whose engine is not armed (the
 * controller throws; the store is left untouched — the switch is atomic).
 * Returns 404 when the profile id is not registered.
 * Returns 503 when no controller is wired (mode switching disabled).
 */
export function handleSetProfileMode(
  controller: ModeController | undefined,
  profileId: string,
  profileExists: boolean,
  body: any,
): { status: number; body: unknown; event?: ModeChangedEvent } {
  if (!controller) {
    return { status: 503, body: { error: 'approval-mode controller not configured' } };
  }
  if (!profileId) {
    return { status: 400, body: { error: 'missing profile id' } };
  }
  if (!profileExists) {
    return { status: 404, body: { error: 'profile not found', profileId } };
  }
  if (body === null || typeof body !== 'object' || !('mode' in body)) {
    return { status: 400, body: { error: 'body must be {"mode": "<mode>" | null}' } };
  }

  const requested: unknown = body.mode;
  const isClear = requested === null;
  if (!isClear && typeof requested !== 'string') {
    return { status: 400, body: { error: 'mode must be a string or null' } };
  }
  // Validate against the armed set before delegating so an unknown/unavailable
  // mode is a clean 400, never a 500 (and never half-applied).
  if (!isClear && !controller.availableModes().includes(requested as string)) {
    return {
      status: 400,
      body: {
        error: `mode "${requested}" is not available`,
        available: controller.availableModes(),
      },
    };
  }

  try {
    const event = controller.setProfileMode(profileId, isClear ? null : (requested as string));
    return {
      status: 200,
      // `override` mirrors the REQUESTED value (null on a clear) so the client
      // can distinguish a cleared override from one set to the fallback mode.
      // `mode` stays the resolved effective mode for backward compatibility.
      body: {
        ok: true,
        scope: 'profile',
        profileId,
        mode: event.mode,
        effective: event.effective,
        override: isClear ? null : (requested as string),
      },
      event,
    };
  } catch (err: any) {
    return { status: 400, body: { error: err?.message ?? 'mode switch failed' } };
  }
}

/**
 * PUT /api/approval-mode — live-switch the GLOBAL default mode (in-memory only).
 * Body: `{ "mode": "yolo" | "smart" | "manual" }`. `null` is not accepted for
 * the global default (there is nothing to revert to).
 */
export function handleSetGlobalMode(
  controller: ModeController | undefined,
  body: any,
): { status: number; body: unknown; event?: ModeChangedEvent } {
  if (!controller) {
    return { status: 503, body: { error: 'approval-mode controller not configured' } };
  }
  if (body === null || typeof body !== 'object' || typeof body.mode !== 'string') {
    return { status: 400, body: { error: 'body must be {"mode": "<mode>"}' } };
  }
  if (!controller.availableModes().includes(body.mode)) {
    return {
      status: 400,
      body: { error: `mode "${body.mode}" is not available`, available: controller.availableModes() },
    };
  }
  try {
    const event = controller.setGlobalMode(body.mode);
    return {
      status: 200,
      body: { ok: true, scope: 'global', mode: event.mode, effective: event.effective },
      event,
    };
  } catch (err: any) {
    return { status: 400, body: { error: err?.message ?? 'mode switch failed' } };
  }
}
