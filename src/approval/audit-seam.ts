/**
 * OPTIONAL audit-truth seam.
 *
 * The approval engine returns a real `ApprovalDecision` from `gateApproval()`.
 * When the audit module (`src/audit/`) is part of THIS build, the seam threads
 * that decision into a JSONL audit record so the log reflects the TRUTH of why
 * a command ran (mode / decided_by / reason), not a placeholder. When
 * `src/audit/` is ABSENT — as it is on `pr/toml-config`, the base of this lane,
 * where the engine ships before PR-A merges — the seam degrades to a no-op and
 * the engine still builds and unit-passes.
 *
 * Decision D2 (P1 plan §6): audit is an OPTIONAL seam, not a hard build
 * prerequisite. We load the audit module via a *computed* (non-literal)
 * specifier so the TypeScript compiler does not statically resolve it — no
 * TS2307 when `src/audit/` is missing — and a runtime `ERR_MODULE_NOT_FOUND`
 * is caught and turned into the no-op sink.
 */
import type { ApprovalDecision } from './types.js';
import type { ExecResult } from '../transports/types.js';

export type AuditToolName = 'exec' | 'sudo-exec';

/** What an exec/sudo-exec handler hands the seam after (attempting) a command. */
export interface AuditExecInput {
  tool: AuditToolName;
  /** Connection / profile name; `default` for the implicit single host. */
  profile: string;
  /** The command actually sent to the transport (already sanitized). */
  command: string;
  description?: string;
  /** `Date.now()` captured before the transport call, for duration math. */
  startedAt: number;
  /** Present on success. */
  result?: ExecResult;
  /** Present on failure (transport error, timeout, or approval deny). */
  error?: unknown;
  /** The real decision from `gateApproval`, when one was produced. */
  approval?: ApprovalDecision;
}

/** The seam surface the rest of the server depends on. Always safe to call. */
export interface AuditSink {
  record(input: AuditExecInput): void;
  /** Optional read-only tail used by the WebUI when src/audit is present. */
  tail?(opts: { profile?: string; limit: number }): Promise<unknown[]>;
  /** Optional execution event subscription used by WebUI SSE. */
  on?(event: 'execution', listener: (record: unknown) => void): void;
  off?(event: 'execution', listener: (record: unknown) => void): void;
}

export interface AuditSeamConfig {
  /** TOML `[server].audit_dir`. Falls back to env / `~/.ssh-mcp` inside audit. */
  auditDir?: string;
  /** TOML `[server].audit_max_bytes`. */
  auditMaxBytes?: number;
}

/**
 * Minimal structural view of the audit module's public surface this seam uses.
 * Kept local so this file never statically imports `src/audit/` (which may be
 * absent). The real module satisfies this shape structurally.
 */
interface AuditModuleLike {
  AuditStore: new (cfg: { auditDir: string; auditMaxBytes: number }) => {
    append(record: unknown): unknown;
    tail?(opts: { profile?: string; limit: number }): Promise<unknown[]>;
    on?(event: 'execution', listener: (record: unknown) => void): void;
    off?(event: 'execution', listener: (record: unknown) => void): void;
  };
  resolveAuditDir(override?: string | null): string;
  yoloApproval(now?: Date): unknown;
}

/** Shared no-op sink for the audit-absent path. */
const NO_OP_SINK: AuditSink = {
  record(): void {
    /* src/audit/ not present in this build — Decision D2 optional seam */
  },
};

function toApprovalSection(decision: ApprovalDecision) {
  return {
    mode: decision.mode,
    decision: decision.decision,
    reason: decision.reason,
    decided_at: decision.decided_at,
    decided_by: decision.decided_by,
  };
}

/**
 * Try to wire a truth-logging audit sink. Returns a no-op sink (never throws)
 * when `src/audit/` is not part of this build, so callers can wire the seam
 * unconditionally at boot and treat the result as always-present.
 */
export async function loadAuditSink(config: AuditSeamConfig = {}): Promise<AuditSink> {
  // Non-literal specifier: tsc does NOT resolve this, so the build succeeds
  // even though `src/audit/store.js` does not exist on `pr/toml-config`.
  const specifier = '../audit/' + 'store.js';

  let mod: AuditModuleLike;
  try {
    mod = (await import(specifier)) as unknown as AuditModuleLike;
  } catch {
    return NO_OP_SINK; // ERR_MODULE_NOT_FOUND → audit module absent → no-op
  }
  if (!mod || typeof mod.AuditStore !== 'function') {
    return NO_OP_SINK;
  }

  const auditDir = mod.resolveAuditDir(config.auditDir);
  let store: InstanceType<AuditModuleLike['AuditStore']>;
  try {
    store = new mod.AuditStore({
      auditDir,
      auditMaxBytes: config.auditMaxBytes ?? 10_000,
    });
  } catch (storeErr: any) {
    // The audit module IS part of this build (import + AuditStore both
    // resolved), so this is a real, present-but-broken store — e.g. an
    // unwritable `[server].audit_dir`. Degrading silently here would hide a
    // compliance-audit failure AND leave the WebUI execution feed empty with
    // no signal. Surface it. (Only the missing-module path above is allowed
    // to degrade quietly — that is the documented Decision-D2 optional seam.)
    console.error(
      `audit store initialization failed (audit logging disabled): ${storeErr?.message || storeErr}`,
    );
    return NO_OP_SINK;
  }

  return {
    tail(opts: { profile?: string; limit: number }): Promise<unknown[]> {
      return typeof store.tail === 'function' ? store.tail(opts) : Promise.resolve([]);
    },
    on(event: 'execution', listener: (record: unknown) => void): void {
      if (typeof store.on === 'function') store.on(event, listener);
    },
    off(event: 'execution', listener: (record: unknown) => void): void {
      if (typeof store.off === 'function') store.off(event, listener);
    },
    record(input: AuditExecInput): void {
      try {
        const now = new Date();
        const durationMs = Math.max(0, Date.now() - input.startedAt);
        // Truth: prefer the real decision; fall back to the yolo placeholder
        // only when the gate never produced one (error before the gate ran).
        const approval = input.approval
          ? toApprovalSection(input.approval)
          : mod.yoloApproval(now);
        store.append({
          profile: input.profile,
          tool: input.tool,
          command: input.command,
          description: input.description,
          approval,
          exec: input.result
            ? {
                stdout: input.result.stdout ?? '',
                stderr: input.result.stderr ?? '',
                exitCode: input.result.exitCode ?? null,
                durationMs,
              }
            : {
                stdout: '',
                stderr:
                  input.error instanceof Error
                    ? input.error.message
                    : String(input.error ?? 'unknown error'),
                exitCode: null,
                durationMs,
              },
          now,
        });
      } catch (auditErr: any) {
        // Audit failure must be visible but must not hide the real SSH result.
        console.error(`audit log append failed: ${auditErr?.message || auditErr}`);
      }
    },
  };
}
