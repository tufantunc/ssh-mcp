/**
 * yolo mode: always allow. Useful for local dev or trusted hosts.
 */

import { ApprovalContext, ApprovalDecision, ApprovalEngine } from './types.js';

export class YoloApproval implements ApprovalEngine {
  async decide(_ctx: ApprovalContext): Promise<ApprovalDecision> {
    return {
      decision: 'allow',
      reason: 'yolo mode: all commands auto-approved',
      decided_by: 'yolo',
      decided_at: new Date().toISOString(),
      mode: 'yolo',
    };
  }
}
