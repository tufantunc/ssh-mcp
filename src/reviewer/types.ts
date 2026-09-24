import type { CommandClass } from '../types.js';

export const REVIEW_SCHEMA_VERSION = 2 as const;
export const REVIEW_POLICY_VERSION = '2';

export type ReviewRisk = 'low' | 'medium' | 'high' | 'unknown';
export type ReviewStatus = 'completed' | 'unavailable';
export type ReviewVerdict = 'approve' | 'deny' | 'escalate';
export type ReviewSeverity = 'low' | 'medium' | 'high';

export interface ReviewFinding {
  category: string;
  severity: ReviewSeverity;
  message: string;
}

export interface ReviewResult {
  status: ReviewStatus;
  verdict: ReviewVerdict;
  risk: ReviewRisk;
  summary: string;
  findings: ReviewFinding[];
  model?: string;
  policyVersion: string;
  durationMs: number;
  unavailableCode?: string;
}

export interface ReviewInput {
  command: string;
  tool: string;
  commandClass: CommandClass;
  tier: string;
  readOnly: boolean;
}

export interface CommandReviewer {
  review(input: ReviewInput): Promise<ReviewResult>;
}
