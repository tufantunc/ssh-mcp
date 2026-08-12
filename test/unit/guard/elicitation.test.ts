import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { requestApproval, APPROVAL_TIMEOUT_MS } from '../../../src/guard/elicitation.js';
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

  /**
   * Requiring a `confirm` boolean on top of `action` made clients render a
   * checkbox beside the accept/decline row. Choosing Accept without ticking it
   * submits a form missing a required field, so the client sends `cancel` — and
   * the user who picked Approve was told they had declined (#91).
   */
  describe('the decision comes from action, not a second checkbox', () => {
    it('does not mark confirm as required', () => {
      const server = makeMockServer('accept');
      requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
      const params = server.server.elicitInput.mock.calls[0][0];
      expect(params.requestedSchema.required ?? []).not.toContain('confirm');
    });

    it('approves a bare accept that carries no content at all', async () => {
      const server = { server: { elicitInput: vi.fn().mockResolvedValue({ action: 'accept' }) } } as any;
      const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
      expect(result.approved).toBe(true);
    });

    it('still honours an explicit confirm: false', async () => {
      // Reading an explicit "no" as approval would be indefensible, whatever
      // `action` says.
      const server = {
        server: { elicitInput: vi.fn().mockResolvedValue({ action: 'accept', content: { confirm: false } }) },
      } as any;
      expect((await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation)).approved).toBe(false);
    });
  });

  /**
   * The elicitation request inherited the SDK's DEFAULT_REQUEST_TIMEOUT_MSEC of
   * 60s, setting a human's reading time from a default meant for machine round
   * trips. Worse, the expiry then reported "a client without elicitation
   * support" — the wrong cause, in the very message added to stop reporting the
   * wrong cause.
   */
  describe('timeout', () => {
    it('asks for a human-scale budget rather than inheriting the SDK default', () => {
      const server = makeMockServer('accept');
      requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
      const options = server.server.elicitInput.mock.calls[0][1];
      expect(options?.timeout).toBe(APPROVAL_TIMEOUT_MS);
      expect(APPROVAL_TIMEOUT_MS).toBeGreaterThan(60_000);
    });

    it('names the timeout instead of guessing at missing elicitation support', async () => {
      const server = {
        server: {
          elicitInput: vi.fn().mockRejectedValue(
            new McpError(ErrorCode.RequestTimeout, 'Request timed out'),
          ),
        },
      } as any;
      const result = await requestApproval(server, 'rm /tmp/x', 'dev', mockEvaluation);
      expect(result.approved).toBe(false);
      expect(result.unavailable).toMatch(/no answer arrived within/);
      expect(result.unavailable).not.toMatch(/elicitation support/);
    });

    it('keeps the missing-support wording for errors that are not timeouts', async () => {
      const result = await requestApproval(makeMockServer('error'), 'rm /tmp/x', 'dev', mockEvaluation);
      expect(result.unavailable).toMatch(/elicitation support/);
      expect(result.unavailable).not.toMatch(/no answer arrived/);
    });
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
    // `confirm` is still offered so a client that wants a field has one; it is
    // no longer required, which is what turned Accept into a decline (#91).
    expect(params.requestedSchema.properties.confirm).toBeDefined();
  });
});
