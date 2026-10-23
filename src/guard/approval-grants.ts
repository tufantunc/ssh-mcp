import { createHash } from 'crypto';
import type { CommandClass } from '../types.js';

/**
 * Short-lived approval grants ("JIT tokens").
 *
 * Approving the same destructive command every few seconds during an iterative
 * task trains the operator to click through prompts, which is worse for safety
 * than a bounded grant. After one explicit approval, an identical command on the
 * same profile re-runs without prompting until the grant expires.
 *
 * The plan called these HMAC-signed tokens. They are not signed here because
 * nothing hands a token to anyone: the grant never leaves this process, is not
 * persisted, and is not shared between processes. A signature would protect
 * against tampering by a holder that does not exist. Keeping it as an in-memory
 * cache keyed by a hash of the exact command removes a signing key — and the
 * question of where to store it — from the design entirely.
 *
 * Off by default. Auto-approval weakens the gate that makes destructive
 * commands safe, so it has to be a decision the operator makes explicitly.
 */
export class ApprovalGrants {
  private grants = new Map<string, { expiry: number; generation: number }>();
  private readonly ttl: () => number;

  /**
   * @param ttlMs Lifetime of a grant. 0 (the default) disables grants entirely:
   *   every destructive command prompts, as if this feature were not here. A
   *   function is read at every call, so a config reload changes it live.
   * @param generation The config generation. A grant counts only under the
   *   generation it was recorded in: one given under the rules before a reload
   *   must not outlive them, and checking here means it stops counting the
   *   moment the generation moves, with nobody having to remember to clear it.
   */
  constructor(ttlMs: number | (() => number) = 0, private readonly generation: () => number = () => 0) {
    this.ttl = typeof ttlMs === 'function' ? ttlMs : () => ttlMs;
  }

  get enabled(): boolean {
    return this.ttl() > 0;
  }

  /**
   * Bound to the exact command text, not a prefix or a binary: approving
   * `rm -rf /tmp/build` must not also approve `rm -rf /tmp/build-prod`.
   */
  private key(profile: string, command: string, commandClass: CommandClass): string {
    return createHash('sha256')
      .update(`${profile} ${commandClass} ${command}`)
      .digest('hex');
  }

  /** True if this exact command still holds a live grant from the current generation. */
  has(profile: string, command: string, commandClass: CommandClass, now = Date.now()): boolean {
    if (!this.enabled) return false;
    const k = this.key(profile, command, commandClass);
    const grant = this.grants.get(k);
    if (grant === undefined) return false;
    if (this.stale(grant, now)) {
      this.grants.delete(k);
      return false;
    }
    return true;
  }

  /**
   * Record an operator approval. No-op when grants are disabled.
   *
   * @param generation The generation the approval was checked under; defaults to the
   *   current one. A caller that awaited anything after its check passes the value it
   *   checked, so a reload landing in that gap leaves a grant that never counts rather
   *   than one tagged with rules nobody evaluated.
   */
  record(
    profile: string,
    command: string,
    commandClass: CommandClass,
    now = Date.now(),
    generation = this.generation(),
  ): void {
    const ttl = this.ttl();
    if (ttl <= 0) return;
    this.grants.set(this.key(profile, command, commandClass), { expiry: now + ttl, generation });
    this.prune(now);
  }

  /**
   * Drop every grant. Used when the approval posture changes underneath us —
   * a grant issued under a looser policy must not outlive it.
   */
  clear(): void {
    this.grants.clear();
  }

  /** Expired, or recorded under a generation other than the current one. */
  private stale(grant: { expiry: number; generation: number }, now: number): boolean {
    return grant.expiry <= now || grant.generation !== this.generation();
  }

  private prune(now: number): void {
    for (const [k, grant] of this.grants) {
      if (this.stale(grant, now)) this.grants.delete(k);
    }
  }
}
