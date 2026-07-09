import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { PolicyEvaluation } from '../types.js';

const ElicitResponseSchema = z.object({
  action: z.enum(['accept', 'decline', 'cancel']),
  content: z.record(z.unknown()).optional(),
});

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
      ElicitResponseSchema,
    );

    if (result.action === 'accept' && result.content?.confirm === true) {
      return { approved: true, approver: 'mcp-client' };
    }
    return { approved: false };
  } catch {
    return { approved: false };
  }
}
