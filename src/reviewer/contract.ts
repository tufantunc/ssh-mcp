import { z } from 'zod';
import { REVIEW_SCHEMA_VERSION } from './types.js';

export const MAX_REVIEW_COMMAND_CHARS = 12_000;
export const MAX_REVIEW_RESPONSE_BYTES = 64 * 1024;
export const MAX_REVIEW_REQUEST_BYTES = 32 * 1024;

const commandClassSchema = z.enum(['read-only', 'safe', 'destructive', 'privileged']);

export const reviewRequestSchema = z.object({
  schemaVersion: z.literal(REVIEW_SCHEMA_VERSION),
  tool: z.string().min(1).max(64),
  commandClass: commandClassSchema,
  command: z.string().min(1).max(MAX_REVIEW_COMMAND_CHARS),
  context: z.object({
    tier: z.string().min(1).max(64),
    readOnly: z.boolean(),
  }).strict(),
}).strict();

export const reviewResponseSchema = z.object({
  schemaVersion: z.literal(REVIEW_SCHEMA_VERSION),
  verdict: z.enum(['approve', 'deny', 'escalate']),
  risk: z.enum(['low', 'medium', 'high', 'unknown']),
  summary: z.string().min(1).max(500),
  findings: z.array(z.object({
    category: z.string().min(1).max(64),
    severity: z.enum(['low', 'medium', 'high']),
    message: z.string().min(1).max(300),
  }).strict()).max(8),
  model: z.string().min(1).max(128),
  policyVersion: z.string().min(1).max(64),
}).strict().superRefine((review, ctx) => {
  const consistent = (review.verdict === 'approve' && review.risk === 'low') ||
    (review.verdict === 'deny' && review.risk === 'high') ||
    (review.verdict === 'escalate' && ['medium', 'unknown'].includes(review.risk));
  if (!consistent) {
    ctx.addIssue({ code: 'custom', message: 'Reviewer verdict and risk are inconsistent' });
  }
});

export type ReviewRequestBody = z.infer<typeof reviewRequestSchema>;
export type ReviewResponseBody = z.infer<typeof reviewResponseSchema>;
