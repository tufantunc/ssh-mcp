import { describe, it, expect, vi, beforeEach } from 'vitest';
import { requestApproval } from '../../../src/guard/elicitation.js';
import type { PolicyEvaluation } from '../../../src/types.js';

const mockEvaluation: PolicyEvaluation = {
  decision: 'require-approval',
  commandClass: 'destructive',
  binary: 'rm',
  ruleId: 'approval-policy',
};

function makeMockServer(action: 'accept' | 'decline' | 'cancel' | 'error'): any {
  const server = {
    server: {
      request: vi.fn().mockImplementation(async () => {
        if (action === 'error') throw new Error('Client does not support elicitation');
        if (action === 'accept') return { action: 'accept', content: { confirm: true } };
        if (action === 'decline') return { action: 'decline', content: {} };
        return { action: 'cancel' };
      }),
    },
  };
  return server;
}

describe('requestApproval', () => {
  it('returns approved when client accepts', async () => {
    const server = makeMockServer('accept');
    const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
    expect(result.approved).toBe(true);
    expect(result.approver).toBe('mcp-client');
  });

  it('returns not approved when client declines', async () => {
    const server = makeMockServer('decline');
    const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
    expect(result.approved).toBe(false);
  });

  it('returns not approved when client cancels', async () => {
    const server = makeMockServer('cancel');
    const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
    expect(result.approved).toBe(false);
  });

  it('returns not approved when client throws (no support)', async () => {
    const server = makeMockServer('error');
    const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
    expect(result.approved).toBe(false);
  });

  it('includes command class in message', async () => {
    const server = makeMockServer('accept');
    await requestApproval(server, 'rm /tmp/x', 'prod-web-1', mockEvaluation);
    expect(server.server.request).toHaveBeenCalled();
    const call = server.server.request.mock.calls[0][0];
    expect(call.params.message).toContain('destructive');
    expect(call.params.message).toContain('prod-web-1');
  });
});
