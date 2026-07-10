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

/**
 * Event emitted whenever a live approval-mode switch is applied. Mirrors the
 * approval module's ModeChangedPayload but kept loose here so the WebUI doesn't
 * import the approval types directly (reviewer reconciles at merge time).
 */
export interface ModeChangedEvent {
  scope: 'global' | 'profile';
  profileId?: string;
  mode: string;
  effective: string;
  /**
   * Present only for scope === 'profile': the requested per-profile override —
   * a mode string when set, or `null` when the override was cleared. Lets
   * clients mirror a cleared override instead of treating the fallback
   * `effective` mode as a still-active override.
   */
  override?: string | null;
  at: string;
}

/**
 * Live approval-mode control surface (PR-7). The WebUI reads the current
 * effective modes and pushes runtime switches back through this controller;
 * `mode-changed` events flow to the SSE stream. All mutation is in-memory only
 * (Decision D3) — the controller MUST NOT write back to the TOML config.
 */
export interface ModeController {
  /** Modes that can be switched to right now (their sub-engine is armed). */
  availableModes(): string[];
  /** The current live global default mode. */
  getGlobalMode(): string;
  /** Effective mode for a profile (live override > static > global). */
  getEffectiveMode(profileId: string): string;
  /**
   * Set (or clear, when `mode === null`) the per-profile override.
   * Throws if `mode` names an unarmed engine.
   */
  setProfileMode(profileId: string, mode: string | null): ModeChangedEvent;
  /** Replace the global default. Throws if `mode` names an unarmed engine. */
  setGlobalMode(mode: string): ModeChangedEvent;
  on(event: 'mode-changed', listener: (e: ModeChangedEvent) => void): void;
  off?(event: 'mode-changed', listener: (e: ModeChangedEvent) => void): void;
}

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
  cors?: boolean;
  registry: RegistrySnapshot;
  queue?: ManualApprovalQueue;
  audit?: AuditTail;
  /** Optional resolver for the effective approval mode of each profile. */
  getApprovalMode?: (profileName: string) => string;
  /** Optional live approval-mode controller (PR-7). When present, enables the
   * mode-switch routes (`PUT .../approval-mode`, `GET /api/approval-modes`) and
   * SSE `mode-changed` broadcasts. In-memory only (Decision D3). */
  modeController?: ModeController;
}

export interface WebUIHandle {
  address: { host: string; port: number };
  close(): Promise<void>;
}
