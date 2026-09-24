import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { mergeReview } from '../../../src/reviewer/decision.js';
import type { PolicyDecision, PolicyEvaluation, CommandClass } from '../../../src/types.js';
import type { ReviewResult, ReviewRisk, ReviewVerdict } from '../../../src/reviewer/types.js';

function evaluation(decision: PolicyDecision, commandClass: CommandClass = 'safe'): PolicyEvaluation {
  return { decision, commandClass, binary: 'tool', ruleId: 'test-policy' };
}

function review(
  verdict: ReviewVerdict,
  risk: ReviewRisk,
  status: ReviewResult['status'] = 'completed',
): ReviewResult {
  return {
    status,
    verdict,
    risk,
    summary: `${verdict} review`,
    findings: [],
    model: status === 'completed' ? 'fake-model' : undefined,
    policyVersion: '2',
    durationMs: 3,
  };
}

describe('mergeReview bounded autonomy', () => {
  it('never changes a deterministic deny', () => {
    fc.assert(fc.property(
      fc.constantFrom('approve', 'deny', 'escalate') as fc.Arbitrary<ReviewVerdict>,
      fc.constantFrom('low', 'medium', 'high', 'unknown') as fc.Arbitrary<ReviewRisk>,
      (verdict, risk) => {
        const merged = mergeReview(evaluation('deny'), review(verdict, risk));
        expect(merged.evaluation).toEqual(evaluation('deny'));
        expect(merged.requiresFreshApproval).toBe(false);
      },
    ));
  });

  it.each(['allow', 'require-approval'] as const)(
    'approve resolves an agent-reviewable %s decision to allow',
    (decision) => {
      const merged = mergeReview(evaluation(decision), review('approve', 'low'));
      expect(merged.evaluation).toMatchObject({ decision: 'allow', ruleId: 'llm-reviewer-approve' });
      expect(merged.approver).toBe('llm-reviewer');
      expect(merged.requiresFreshApproval).toBe(false);
    },
  );

  it.each(['allow', 'require-approval'] as const)(
    'deny resolves an agent-reviewable %s decision without a human prompt',
    (decision) => {
      const merged = mergeReview(evaluation(decision), review('deny', 'high'));
      expect(merged.evaluation).toMatchObject({ decision: 'deny', ruleId: 'llm-reviewer-deny' });
      expect(merged.requiresFreshApproval).toBe(false);
    },
  );

  it('escalate requires a fresh human approval', () => {
    const merged = mergeReview(evaluation('allow'), review('escalate', 'medium'));
    expect(merged.evaluation).toMatchObject({ decision: 'require-approval', ruleId: 'llm-reviewer-escalate' });
    expect(merged.requiresFreshApproval).toBe(true);
  });

  it('reviewer failure is an escalation', () => {
    const merged = mergeReview(evaluation('allow'), review('escalate', 'unknown', 'unavailable'));
    expect(merged.evaluation.decision).toBe('require-approval');
    expect(merged.requiresFreshApproval).toBe(true);
  });

  it('keeps privileged operations human-only even when the reviewer approves', () => {
    const merged = mergeReview(
      evaluation('require-approval', 'privileged'),
      review('approve', 'low'),
    );
    expect(merged.evaluation.decision).toBe('require-approval');
    expect(merged.evaluation.ruleId).toBe('llm-reviewer-human-only');
    expect(merged.requiresFreshApproval).toBe(true);
    expect(merged.approver).toBeUndefined();
  });
});
