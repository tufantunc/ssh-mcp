import type { ManualApprovalQueue, ApprovalDecisionKind } from '../types.js';

export function handleListApprovals(queue: ManualApprovalQueue | undefined) {
  if (!queue) return { status: 200, body: { approvals: [] } };
  return { status: 200, body: { approvals: queue.list() } };
}

export function handleDecideApproval(
  queue: ManualApprovalQueue | undefined,
  id: string,
  kind: ApprovalDecisionKind,
  note: string | undefined,
  decidedBy: string,
): { status: number; body: unknown } {
  if (!queue) {
    return { status: 503, body: { error: 'manual approval queue not configured' } };
  }
  if (!id) {
    return { status: 400, body: { error: 'missing approval id' } };
  }
  const ok = queue.resolve(id, {
    decision: kind,
    reason: note || (kind === 'allow' ? 'manual allow' : 'manual deny'),
    decided_by: decidedBy,
  });
  if (!ok) {
    return { status: 404, body: { error: `unknown approval id: ${id}` } };
  }
  return { status: 200, body: { ok: true, id, decision: kind } };
}
