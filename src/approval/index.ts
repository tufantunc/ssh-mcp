/**
 * Public barrel for the approval module. Tool handlers should import from
 * here so the internal layout (yolo/smart/manual) can evolve without
 * touching call sites.
 */

export type {
  ApprovalMode,
  ApprovalDecision,
  ApprovalContext,
  ApprovalEngine,
  ResolvedSource,
  SmartLlmConfig,
  SmartApprovalOptions,
  ManualApprovalOptions,
  PendingApproval,
} from './types.js';
export { YoloApproval } from './yolo.js';
export { SmartApproval } from './smart.js';
export { ManualApproval, ManualApprovalDisabledError } from './manual.js';
export {
  ApprovalDispatcher,
  buildApprovalEngine,
  buildApprovalEngineFromConfig,
  manualWithoutResolverWarning,
  type BuildApprovalEngineOptions,
  type BuildEngineFromConfigInput,
  type BuildEngineFromConfigOptions,
} from './engine.js';
export {
  setApprovalEngine,
  getApprovalEngine,
  getApprovalDecisionFromError,
  gateApproval,
  listPendingApprovals,
  resolvePendingApproval,
} from './gate.js';
