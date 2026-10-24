import type { PolicyEvaluation } from '../types.js';

/**
 * The evaluation recorded for a session release.
 *
 * Releasing a session is audited but never refused, which is why this is a constant rather
 * than an engine call. The first version of this routed the close through `runAudited`, and
 * that made the stop *refusable*: `session:close <name>` classifies as `safe`, so a
 * `readOnly` profile — which can open a background session, because a `tail -f` classifies
 * `read-only` — was denied permission to close it, and had no other way to stop the
 * command for an hour. `ask-all` prompted on every close, and an exhausted
 * `commandQuotaPerDay` wedged the profile entirely.
 *
 * A control whose refusal mode is "the thing you asked me to stop keeps running" is worse
 * than the unaudited stop it replaced. The record was the part worth having; the veto was
 * not. `ruleId` says so, so the log distinguishes this from an engine `allow`.
 *
 * Here rather than in the tool layer because two writers share it: the `close-session`
 * tool, and a config reload closing a connection's sessions.
 */
export const RELEASE: PolicyEvaluation = {
  decision: 'allow',
  commandClass: 'safe',
  binary: 'session:close',
  ruleId: 'session-release',
  reason: 'A session release is audited but not policy-gated; see SECURITY.md.',
};

/**
 * A session's kind for its release record: its type, or `unknown` when there is no such
 * session or it cannot describe itself. Through `toInfo()` rather than an `instanceof`
 * check: the type is public API, and reaching for a constructor identity is a layer leak.
 */
export function sessionKind(session: { toInfo(): { type: string } } | undefined): string {
  if (!session) return 'unknown';
  try {
    return session.toInfo().type;
  } catch {
    return 'unknown';
  }
}

/**
 * The audited command for a session release, `session:close <kind> <name>`, so a remote
 * SIGKILL is greppable in the log and distinguishable from ending a local shell. A release
 * by a config reload carries a ` (reload)` suffix.
 */
export function sessionReleaseCommand(kind: string, name: string, opts: { reload?: boolean } = {}): string {
  return `${RELEASE.binary} ${kind} ${name}${opts.reload ? ' (reload)' : ''}`;
}
