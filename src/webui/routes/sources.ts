import type { SourceController, SourceUpdatedEvent } from '../types.js';

/** Max accepted description length. Keeps a runaway paste from bloating the
 * in-memory store / SSE payloads; the smart-mode LLM prompt is the consumer and
 * 8 KiB of policy text is already generous. */
const MAX_DESCRIPTION_LEN = 8192;

/**
 * PUT /api/sources/:id/description — live-edit a source's description
 * (in-memory only, Decision D3).
 *
 * Body: `{ "description": "<text>" | null }`.
 *   - a string sets a live runtime override (the empty string blanks it)
 *   - `null` clears the override, reverting to the TOML-seeded description
 *
 * The approval engine re-reads the effective description on its NEXT decision,
 * so the edit applies live without a restart and WITHOUT writing to disk.
 *
 * Returns 400 on a malformed body or an over-long description; 404 on an
 * unknown source id; 503 when no controller is wired (editing disabled).
 */
export function handleSetSourceDescription(
  controller: SourceController | undefined,
  sourceId: string,
  body: any,
): { status: number; body: unknown; event?: SourceUpdatedEvent } {
  if (!controller) {
    return { status: 503, body: { error: 'source description controller not configured' } };
  }
  if (!sourceId) {
    return { status: 400, body: { error: 'missing source id' } };
  }
  if (body === null || typeof body !== 'object' || !('description' in body)) {
    return { status: 400, body: { error: 'body must be {"description": "<text>" | null}' } };
  }

  const requested: unknown = body.description;
  const isClear = requested === null;
  if (!isClear && typeof requested !== 'string') {
    return { status: 400, body: { error: 'description must be a string or null' } };
  }
  if (!isClear && (requested as string).length > MAX_DESCRIPTION_LEN) {
    return {
      status: 400,
      body: { error: `description exceeds ${MAX_DESCRIPTION_LEN} characters`, max: MAX_DESCRIPTION_LEN },
    };
  }
  // Unknown source -> clean 404 (never a 500 from the controller throwing).
  if (!controller.hasSource(sourceId)) {
    return { status: 404, body: { error: `unknown source: ${sourceId}` } };
  }

  try {
    const event = controller.setDescription(sourceId, isClear ? null : (requested as string));
    return {
      status: 200,
      body: { ok: true, id: event.id, description: event.description },
      event,
    };
  } catch (err: any) {
    return { status: 400, body: { error: err?.message ?? 'description edit failed' } };
  }
}
