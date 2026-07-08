import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { PolicyEvaluation } from '../types.js';

export interface ApprovalResult {
  approved: boolean;
  approver?: string;
}

export async function requestApproval(
  server: McpServer,
  command: string,
  profileName: string,
  evaluation: PolicyEvaluation,
): Promise<ApprovalResult> {
  try {
    const message = `Confirm ${evaluation.commandClass} command on "${profileName}":\n\n${command}`;

    const result = await (server as any).server.request(
      {
        method: 'elicitation/create',
        params: {
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
        },
      },
      undefined,
    );

    if (result.action === 'accept' && result.content?.confirm === true) {
      return { approved: true, approver: result.content.user || 'mcp-client' };
    }
    return { approved: false };
  } catch {
    return { approved: false };
  }
}
