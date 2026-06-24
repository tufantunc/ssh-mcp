import { describe, it, expect, afterEach } from 'vitest';
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import {
  gateApproval,
  setApprovalEngine,
  getApprovalEngine,
} from '../gate.js';
import { ApprovalDispatcher } from '../engine.js';
import { ApprovalEngine, ApprovalContext, ApprovalDecision } from '../types.js';

const ctx: ApprovalContext = {
  profile: { id: 'prod' },
  tool: 'exec',
  command: 'ls /',
};

afterEach(() => setApprovalEngine(null));

describe('gateApproval', () => {
  it('returns synthetic allow when no engine is configured (legacy path)', async () => {
    setApprovalEngine(null);
    const d = await gateApproval(ctx);
    expect(d.decision).toBe('allow');
    expect(d.decided_by).toBe('legacy:no-engine');
  });

  it('allows under yolo dispatcher', async () => {
    setApprovalEngine(new ApprovalDispatcher({ defaultMode: 'yolo' }));
    const d = await gateApproval(ctx);
    expect(d.decision).toBe('allow');
    expect(d.mode).toBe('yolo');
  });

  it('throws McpError on deny', async () => {
    const denyingEngine: ApprovalEngine = {
      async decide(): Promise<ApprovalDecision> {
        return {
          decision: 'deny',
          reason: 'destructive command',
          decided_by: 'test-stub',
          decided_at: new Date().toISOString(),
          mode: 'smart',
        };
      },
    };
    setApprovalEngine(denyingEngine);
    await expect(gateApproval(ctx)).rejects.toThrow(McpError);
    await expect(gateApproval(ctx)).rejects.toThrow(/approval denied/);
    await expect(gateApproval(ctx)).rejects.toThrow(/destructive command/);
  });

  it('passes allow decision through on smart-allow stub', async () => {
    const allowingEngine: ApprovalEngine = {
      async decide(): Promise<ApprovalDecision> {
        return {
          decision: 'allow',
          reason: 'safe',
          decided_by: 'smart-llm',
          decided_at: new Date().toISOString(),
          mode: 'smart',
        };
      },
    };
    setApprovalEngine(allowingEngine);
    const d = await gateApproval(ctx);
    expect(d.decision).toBe('allow');
    expect(d.mode).toBe('smart');
  });

  it('set/get round-trip', () => {
    const e = new ApprovalDispatcher({ defaultMode: 'yolo' });
    setApprovalEngine(e);
    expect(getApprovalEngine()).toBe(e);
    setApprovalEngine(null);
    expect(getApprovalEngine()).toBeNull();
  });
});
