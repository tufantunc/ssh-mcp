import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { PolicyEvaluation } from '../types.js';

export interface ApprovalResult {
  approved: boolean;
  approver?: string;
  /**
   * Set when the client could not be asked at all, as opposed to being asked
   * and saying no. Both deny the command; only one of them is the user's doing,
   * and telling the reader they declined something they never saw sends them
   * looking in the wrong place.
   */
  unavailable?: string;
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
    const cause = err instanceof Error ? err.message : String(err);
    // stderr still gets it for the operator's logs, but it cannot be the only
    // copy: for a stdio MCP server that is a client log file nobody reads, so
    // the caller gets the diagnosis too and can put it in front of the user.
    console.error(
      `Approval request failed for ${evaluation.commandClass} command on "${profileName}" — denying. ` +
      `Does this client support elicitation? Cause: ${cause}`,
    );
    return {
      approved: false,
      unavailable:
        `this MCP client could not be asked to approve it. The likely cause is a client without ` +
        `elicitation support; a transport failure or a malformed reply does the same. Approval fails ` +
        `closed, so the command was refused rather than run. Underlying error: ${cause}`,
    };
  }
}
