import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { requestApproval } from '../../../src/guard/elicitation.js';
import type { PolicyEvaluation } from '../../../src/types.js';

const mockEvaluation: PolicyEvaluation = {
  decision: 'require-approval',
  commandClass: 'destructive',
  binary: 'rm',
  ruleId: 'approval-policy',
};

// Mocks the SDK's typed Server.elicitInput(). Mocking the old low-level
// server.request() made these tests pass for the wrong reason: any change of
// API left elicitInput undefined, the call threw, and "approved: false" still
// satisfied three of the four assertions.
function makeMockServer(action: 'accept' | 'decline' | 'cancel' | 'error'): any {
  return {
    server: {
      elicitInput: vi.fn().mockImplementation(async () => {
        if (action === 'error') throw new Error('Client does not support elicitation');
        if (action === 'accept') return { action: 'accept', content: { confirm: true } };
        if (action === 'decline') return { action: 'decline', content: {} };
        return { action: 'cancel' };
      }),
    },
  };
}

let errorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  errorSpy.mockRestore();
});

describe('requestApproval', () => {
  it('returns approved when client accepts', async () => {
    const server = makeMockServer('accept');
    const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
    expect(server.server.elicitInput).toHaveBeenCalledOnce();
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

  it('fails closed and logs when the elicitation call throws', async () => {
    const server = makeMockServer('error');
    const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
    expect(result.approved).toBe(false);
    // A gate that always denies for an unnoticed reason is its own outage.
    expect(errorSpy).toHaveBeenCalledOnce();
    expect(String(errorSpy.mock.calls[0][0])).toMatch(/Approval request failed/);
  });

  /**
   * The distinction the caller renders as APPROVAL_DENIED vs APPROVAL_UNAVAILABLE.
   * Both deny; only one of them is the user's doing, and a reader told they
   * declined a prompt they never saw goes looking in the wrong place (#91).
   */
  it('marks a failure to ask as unavailable, carrying the cause', async () => {
    const server = makeMockServer('error');
    const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
    expect(result.unavailable).toMatch(/could not be asked/);
    expect(result.unavailable).toMatch(/elicitation support/);
    // The underlying error travels with it, so stderr is not the only copy.
    expect(result.unavailable).toContain('Client does not support elicitation');
  });

  it.each(['decline', 'cancel'] as const)('leaves unavailable unset when the client answers (%s)', async (action) => {
    const result = await requestApproval(makeMockServer(action), 'rm /tmp/x', 'dev', mockEvaluation);
    expect(result.approved).toBe(false);
    expect(result.unavailable).toBeUndefined();
  });

  it('does not approve when the client accepts but confirm is false', async () => {
    const server = {
      server: { elicitInput: vi.fn().mockResolvedValue({ action: 'accept', content: { confirm: false } }) },
    } as any;
    const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
    expect(result.approved).toBe(false);
  });

  it('sends the command class, profile and command in the prompt', async () => {
    const server = makeMockServer('accept');
    await requestApproval(server, 'rm -rf /tmp/x', 'prod-web-1', mockEvaluation);
    const params = server.server.elicitInput.mock.calls[0][0];
    expect(params.message).toContain('destructive');
    expect(params.message).toContain('prod-web-1');
    expect(params.message).toContain('rm -rf /tmp/x');
    expect(params.requestedSchema.required).toContain('confirm');
  });
});
