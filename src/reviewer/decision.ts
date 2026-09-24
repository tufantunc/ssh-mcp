import type { PolicyEvaluation } from '../types.js';
import type { ReviewResult } from './types.js';

export interface ReviewMerge {
  evaluation: PolicyEvaluation;
  /** An escalation must never be satisfied by an earlier JIT grant. */
  requiresFreshApproval: boolean;
  approver?: 'llm-reviewer';
}

/**
 * Let the contextual reviewer resolve only decisions that passed deterministic
 * authorization. Privileged operations remain human-only even when approved.
 */
export function mergeReview(
  evaluation: PolicyEvaluation,
  review: ReviewResult,
): ReviewMerge {
  if (evaluation.decision === 'deny') {
    return { evaluation, requiresFreshApproval: false };
  }

  if (review.status === 'completed' && review.verdict === 'deny') {
    return {
      evaluation: {
        ...evaluation,
        decision: 'deny',
        ruleId: 'llm-reviewer-deny',
        reason: 'Contextual reviewer denied this operation',
      },
      requiresFreshApproval: false,
    };
  }

  if (evaluation.commandClass === 'privileged') {
    return {
      evaluation: {
        ...evaluation,
        decision: 'require-approval',
        ruleId: 'llm-reviewer-human-only',
        reason: 'Privileged operations require human approval',
      },
      requiresFreshApproval: true,
    };
  }

  if (review.status === 'completed' && review.verdict === 'approve') {
    return {
      evaluation: {
        ...evaluation,
        decision: 'allow',
        ruleId: 'llm-reviewer-approve',
        reason: 'Contextual reviewer approved this operation',
      },
      requiresFreshApproval: false,
      approver: 'llm-reviewer',
    };
  }

  return {
    evaluation: {
      ...evaluation,
      decision: 'require-approval',
      ruleId: 'llm-reviewer-escalate',
      reason: review.status === 'unavailable'
        ? 'Contextual reviewer unavailable; human approval required'
        : `Contextual reviewer reported ${review.risk} risk; human approval required`,
    },
    requiresFreshApproval: true,
  };
}
