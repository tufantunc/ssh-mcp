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

export class CommandQuota {
  /** Timestamps of counted commands, oldest first, per profile. */
  private hits = new Map<string, number[]>();

  /**
   * A sliding 24h window rather than a calendar day: a fixed daily reset lets
   * an agent burn the whole quota, wait for midnight, and immediately burn it
   * again — twice the intended work in minutes.
   */
  constructor(private windowMs: number = DAY_MS) {}

  /**
   * Count one command against the profile's quota.
   * `limit <= 0` (or undefined) means unlimited, and nothing is recorded.
   */
  consume(profile: string, limit: number | undefined, now = Date.now()): QuotaDecision {
    if (!limit || limit <= 0) return { allowed: true, remaining: Infinity };

    const cutoff = now - this.windowMs;
    const recent = (this.hits.get(profile) ?? []).filter((t) => t > cutoff);

    if (recent.length >= limit) {
      // Refusal must not consume budget, otherwise a blocked agent could keep
      // pushing the window forward and never recover.
      this.hits.set(profile, recent);
      return {
        allowed: false,
        remaining: 0,
        retryAt: new Date(recent[0] + this.windowMs),
      };
    }

    recent.push(now);
    this.hits.set(profile, recent);
    return { allowed: true, remaining: limit - recent.length };
  }

  /** Commands used in the current window, for status reporting. */
  used(profile: string, now = Date.now()): number {
    const cutoff = now - this.windowMs;
    return (this.hits.get(profile) ?? []).filter((t) => t > cutoff).length;
  }

  reset(profile?: string): void {
    if (profile) this.hits.delete(profile);
    else this.hits.clear();
  }
}
