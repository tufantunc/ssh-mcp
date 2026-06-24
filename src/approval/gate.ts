/**
 * Tool-handler integration glue.
 *
 * The exec / sudo-exec MCP tool handlers call `gateApproval` BEFORE
 * transport.exec. If no engine has been set (legacy boot path that lands
 * before toml-config wires this up), gateApproval is a no-op allow — keeping
 * existing tests green.
 *
 * Once toml-config + audit-log cards land, the boot code will call
 * `setApprovalEngine(engine)` and the audit store will read the decision
 * via the returned ApprovalDecision passed back from `gateApproval`.
 */

import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import {
  ApprovalContext,
  ApprovalDecision,
  ApprovalEngine,
  PendingApproval,
} from './types.js';

let activeEngine: ApprovalEngine | null = null;

export function setApprovalEngine(engine: ApprovalEngine | null): void {
  activeEngine = engine;
}

export function getApprovalEngine(): ApprovalEngine | null {
  return activeEngine;
}

/**
 * Run the engine for `ctx`. On deny, throws McpError(InvalidRequest) so the
 * MCP client surfaces a clear refusal. On allow, returns the decision so the
 * caller can stuff it into the audit record.
 *
 * If no engine is configured, returns a synthetic allow decision tagged
 * `legacy:no-engine`. This keeps the legacy CLI boot path working.
 */
export async function gateApproval(ctx: ApprovalContext): Promise<ApprovalDecision> {
  if (!activeEngine) {
    return {
      decision: 'allow',
      reason: 'no approval engine configured (legacy boot path)',
      decided_by: 'legacy:no-engine',
      decided_at: new Date().toISOString(),
      mode: 'yolo',
    };
  }
  const decision = await activeEngine.decide(ctx);
  if (decision.decision === 'deny') {
    throw new McpError(
      ErrorCode.InvalidRequest,
      `approval denied (${decision.mode}/${decision.decided_by}): ${decision.reason}`,
    );
  }
  return decision;
}

/** Surface for the WebUI card. */
export function listPendingApprovals(): PendingApproval[] {
  return activeEngine?.listPending?.() ?? [];
}

export function resolvePendingApproval(
  id: string,
  decision: 'allow' | 'deny',
  note?: string,
  decided_by?: string,
): boolean {
  return activeEngine?.resolvePending?.(id, decision, note, decided_by) ?? false;
}
