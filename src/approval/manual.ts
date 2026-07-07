/**
 * manual mode: enqueue PendingApproval, await external resolve (typically a
 * external WebUI resolver). The WebUI surface lives in a separate card; this module only
 * cares about the queue and the resolve callback.
 *
 * Fatal-at-boot when WebUI is disabled — there's no UI to resolve the queue.
 *
 * The default timeout is 5 minutes; on timeout the queued entry is dropped
 * and the decide() promise resolves with `decision: 'deny', reason: "approval
 * timed out"`.
 */

import { EventEmitter } from 'node:events';
import { randomInt } from 'node:crypto';
import {
  ApprovalContext,
  ApprovalDecision,
  ApprovalEngine,
  ManualApprovalOptions,
  PendingApproval,
} from './types.js';

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

// Crockford base32 alphabet (no I L O U) — ULID-compatible character set.
const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * Generate a 26-character ULID-like identifier without pulling in a dep.
 * The 10-char timestamp prefix is genuine ULID; the 16-char random tail uses
 * a cryptographically strong CSPRNG (node:crypto randomInt). These ids gate
 * the WebUI resolve endpoint, so a predictable tail (e.g. Math.random) would
 * let an attacker who can reach that endpoint guess pending ids and
 * approve/deny commands — hence CSPRNG rather than Math.random.
 */
function generateUlid(): string {
  let now = Date.now();
  let ts = '';
  for (let i = 9; i >= 0; i--) {
    ts = ULID_ALPHABET[now % 32] + ts;
    now = Math.floor(now / 32);
  }
  let rand = '';
  for (let i = 0; i < 16; i++) {
    rand += ULID_ALPHABET[randomInt(32)];
  }
  return ts + rand;
}

interface QueueEntry extends PendingApproval {
  settle: (decision: ApprovalDecision) => void;
  timer: NodeJS.Timeout;
}

export class ManualApprovalDisabledError extends Error {
  constructor(message = 'manual approval mode requires WebUI to be enabled — set [webui].enabled = true or pass --webui') {
    super(message);
    this.name = 'ManualApprovalDisabledError';
  }
}

export class ManualApproval extends EventEmitter implements ApprovalEngine {
  private readonly timeoutMs: number;
  private readonly pending = new Map<string, QueueEntry>();

  constructor(opts: ManualApprovalOptions) {
    super();
    if (!opts.webuiEnabled) {
      throw new ManualApprovalDisabledError();
    }
    this.timeoutMs = opts.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  }

  async decide(ctx: ApprovalContext): Promise<ApprovalDecision> {
    return new Promise<ApprovalDecision>((resolve) => {
      const id = generateUlid();
      const enqueued_at = new Date().toISOString();

      const settle = (decision: ApprovalDecision) => {
        const entry = this.pending.get(id);
        if (!entry) return;
        clearTimeout(entry.timer);
        this.pending.delete(id);
        // Emit resolve event before settling the promise so SSE clients see
        // the resolution before the caller's next tick observes the result.
        try {
          this.emit('resolve', { id, enqueued_at, context: ctx }, decision);
        } catch { /* listener errors must not affect the gate */ }
        resolve(decision);
      };

      const timer = setTimeout(() => {
        settle({
          decision: 'deny',
          reason: 'approval timed out',
          decided_by: 'manual:timeout',
          decided_at: new Date().toISOString(),
          mode: 'manual',
        });
      }, this.timeoutMs);
      // Don't keep the event loop alive solely waiting on this timer.
      if (typeof (timer as any).unref === 'function') (timer as any).unref();

      const entry: QueueEntry = {
        id,
        enqueued_at,
        context: ctx,
        settle,
        timer,
        resolve: (decision, note, decided_by) => {
          const live = this.pending.get(id);
          if (!live) return false;
          live.settle({
            decision,
            reason: note ?? (decision === 'allow' ? 'manually approved' : 'manually denied'),
            decided_by: decided_by ?? 'manual:webui',
            decided_at: new Date().toISOString(),
            mode: 'manual',
          });
          return true;
        },
      };
      this.pending.set(id, entry);
      try {
        this.emit('enqueue', { id, enqueued_at, context: ctx });
      } catch { /* listener errors must not affect the gate */ }
    });
  }

  listPending(): PendingApproval[] {
    return Array.from(this.pending.values()).map(({ id, enqueued_at, context, resolve }) => ({
      id,
      enqueued_at,
      context,
      resolve,
    }));
  }

  resolvePending(id: string, decision: 'allow' | 'deny', note?: string, decided_by?: string): boolean {
    const entry = this.pending.get(id);
    if (!entry) return false;
    return entry.resolve(decision, note, decided_by);
  }
}
