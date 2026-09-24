/**
 * Per-profile command quota — a circuit breaker for runaway agents.
 *
 * The approval gate stops a *destructive* command, and the HTTP rate limiter
 * caps request rate, but neither bounds total work: a prompt-injected agent
 * looping over allowed commands stays under both. The quota bounds the day.
 *
 * Scope is the profile, not the "agent": MCP gives us no stable client
 * identity (a stdio server serves exactly one client anyway), so claiming
 * per-agent accounting would overstate what is actually enforced.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

export interface QuotaDecision {
  allowed: boolean;
  /** Commands still available in the window. */
  remaining: number;
  /** When the oldest counted command falls out of the window. */
  retryAt?: Date;
}

export interface QuotaReservation {
  readonly profile: string;
  readonly token: symbol;
}

export interface QuotaReservationDecision extends QuotaDecision {
  reservation?: QuotaReservation;
}

export class CommandQuota {
  /** Timestamps of counted commands, oldest first, per profile. */
  private hits = new Map<string, number[]>();
  /** Capacity held by commands still in review or awaiting approval. */
  private pending = new Map<string, Set<symbol>>();

  /**
   * A sliding 24h window rather than a calendar day: a fixed daily reset lets
   * an agent burn the whole quota, wait for midnight, and immediately burn it
   * again — twice the intended work in minutes.
   */
  constructor(private windowMs: number = DAY_MS) {}

  /**
   * Hold capacity without consuming it yet.
   *
   * Review and human approval happen before execution and can be costly. A
   * reservation prevents concurrent requests from all entering those stages,
   * while release() preserves the rule that a refused command spends no quota.
   */
  reserve(profile: string, limit: number | undefined, now = Date.now()): QuotaReservationDecision {
    if (!limit || limit <= 0) return { allowed: true, remaining: Infinity };

    const cutoff = now - this.windowMs;
    const recent = (this.hits.get(profile) ?? []).filter((t) => t > cutoff);
    this.hits.set(profile, recent);
    const pending = this.pending.get(profile) ?? new Set<symbol>();

    if (recent.length + pending.size >= limit) {
      return {
        allowed: false,
        remaining: 0,
        retryAt: recent.length > 0 ? new Date(recent[0] + this.windowMs) : undefined,
      };
    }

    const token = Symbol(profile);
    pending.add(token);
    this.pending.set(profile, pending);
    return {
      allowed: true,
      remaining: limit - recent.length - pending.size,
      reservation: { profile, token },
    };
  }

  /** Turn a held slot into a counted command immediately before execution. */
  commit(reservation: QuotaReservation | undefined, now = Date.now()): void {
    if (!reservation || !this.removePending(reservation)) return;
    const recent = this.hits.get(reservation.profile) ?? [];
    recent.push(now);
    this.hits.set(reservation.profile, recent);
  }

  /** Return capacity when a request is refused before execution. */
  release(reservation: QuotaReservation | undefined): void {
    if (reservation) this.removePending(reservation);
  }

  /**
   * Count one command against the profile's quota.
   * `limit <= 0` (or undefined) means unlimited, and nothing is recorded.
   */
  consume(profile: string, limit: number | undefined, now = Date.now()): QuotaDecision {
    const { reservation, ...decision } = this.reserve(profile, limit, now);
    if (decision.allowed) this.commit(reservation, now);
    return decision;
  }

  /** Commands used in the current window, for status reporting. */
  used(profile: string, now = Date.now()): number {
    const cutoff = now - this.windowMs;
    return (this.hits.get(profile) ?? []).filter((t) => t > cutoff).length;
  }

  reset(profile?: string): void {
    if (profile) {
      this.hits.delete(profile);
      this.pending.delete(profile);
    } else {
      this.hits.clear();
      this.pending.clear();
    }
  }

  private removePending(reservation: QuotaReservation): boolean {
    const pending = this.pending.get(reservation.profile);
    if (!pending?.delete(reservation.token)) return false;
    if (pending.size === 0) this.pending.delete(reservation.profile);
    return true;
  }
}
