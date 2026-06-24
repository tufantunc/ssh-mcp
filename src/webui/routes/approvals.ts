import type { ManualApprovalQueue } from '../types.js';

export function handleListApprovals(queue: ManualApprovalQueue | undefined) {
  if (!queue) return { status: 200, body: { approvals: [] } };
  return { status: 200, body: { approvals: queue.list() } };
}
