/**
 * WebUI types — interfaces this module depends on.
 *
 * These mirror the shapes the approval-engine and audit-log cards will produce.
 * Defining them here as a stub lets the WebUI ship in parallel; reviewer reconciles
 * against the real types once those cards land.
 */

export interface PendingApproval {
  id: string;
  profile: string;
  tool: 'exec' | 'sudo-exec';
  command: string;
  description?: string;
  enqueuedAt: string;
}

export type ApprovalDecisionKind = 'allow' | 'deny';

export interface ApprovalDecision {
  decision: ApprovalDecisionKind;
  reason: string;
  decided_by: string;
}

/**
 * Listener API for the manual approval queue.
 *
 * The approval-engine card's `approval/manual.ts` implementation must satisfy
 * this shape. The WebUI reads pending items and submits decisions back; events
 * (enqueue / resolve) are pushed to the SSE stream.
 */
export interface ManualApprovalQueue {
  list(): PendingApproval[];
  resolve(id: string, decision: ApprovalDecision): boolean;
  on(event: 'enqueue', listener: (p: PendingApproval) => void): void;
  on(event: 'resolve', listener: (p: PendingApproval, d: ApprovalDecision) => void): void;
  off?(event: 'enqueue' | 'resolve', listener: (...args: any[]) => void): void;
}

export interface AuditExecRecord {
  exit_code?: number;
  duration_ms?: number;
  stdout_truncated?: boolean;
  stderr_truncated?: boolean;
  stdout?: string;
  stderr?: string;
}

export interface AuditRecord {
  ts: string;
  id: string;
  profile: string;
  tool: 'exec' | 'sudo-exec';
  command: string;
  description?: string;
  approval: {
    mode: 'yolo' | 'smart' | 'manual';
    decision: ApprovalDecisionKind;
    reason: string;
    decided_at: string;
    decided_by: string;
  };
  exec?: AuditExecRecord;
}

/**
 * Audit log tail interface — read-only consumer surface for the WebUI.
 * audit-log card's `audit/store.ts` must provide this shape.
 */
export interface AuditTail {
  tail(opts: { profile?: string; limit: number }): Promise<AuditRecord[]>;
  on(event: 'execution', listener: (r: AuditRecord) => void): void;
  off?(event: 'execution', listener: (r: AuditRecord) => void): void;
}

/**
 * Registry snapshot row, as produced by TransportRegistry.list().
 * Kept loose so the WebUI doesn't have to import the transport types here.
 */
export interface RegistryRow {
  name: string;
  /** Human-readable only; never include secrets here. */
  description?: string;
  host: string;
  port: number;
  username: string;
  transport: string;
  authMode: string;
  connected: boolean;
  isDefault: boolean;
}

export interface RegistrySnapshot {
  list(): RegistryRow[];
}

export interface WebUIOptions {
  host?: string;
  port?: number;
  authToken?: string;
  registry: RegistrySnapshot;
  queue?: ManualApprovalQueue;
  audit?: AuditTail;
  /** Optional resolver for the effective approval mode of each profile. */
  getApprovalMode?: (profileName: string) => string;
}

export interface WebUIHandle {
  address: { host: string; port: number };
  close(): Promise<void>;
}
