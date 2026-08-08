import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { PolicyEvaluation } from '../types.js';

export interface ApprovalResult {
  approved: boolean;
  approver?: string;
}

/**
 * Ask the MCP client to confirm a destructive or privileged command.
 *
 * Uses the SDK's typed `Server.elicitInput()` rather than a hand-built
 * `elicitation/create` envelope, so a protocol change breaks the build instead
 * of silently disabling the gate that guards every destructive command.
 *
 * Fails closed: any error (client without elicitation support, transport
 * failure, malformed reply) denies the command. The failure is logged, because
 * a gate that always denies for an unnoticed reason is its own kind of outage.
 */
export async function requestApproval(
  server: McpServer,
  command: string,
  profileName: string,
  evaluation: PolicyEvaluation,
): Promise<ApprovalResult> {
  const message = `Confirm ${evaluation.commandClass} command on "${profileName}":\n\n${command}`;

  try {
    const result = await server.server.elicitInput({
      message,
      requestedSchema: {
        type: 'object',
        properties: {
          confirm: {
            type: 'boolean',
            title: 'Approve this command?',
          },
        },
        required: ['confirm'],
      },
    });

    if (result.action === 'accept' && result.content?.confirm === true) {
      return { approved: true, approver: 'mcp-client' };
    }
    return { approved: false };
  } catch (err) {
    console.error(
      `Approval request failed for ${evaluation.commandClass} command on "${profileName}" — denying. ` +
      `Does this client support elicitation? Cause: ${err instanceof Error ? err.message : String(err)}`,
    );
    return { approved: false };
  }
}
