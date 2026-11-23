import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
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
 * How long a person has to read a destructive command and decide.
 *
 * Explicit because the SDK's DEFAULT_REQUEST_TIMEOUT_MSEC is 60 seconds, and
 * inheriting it here set a human's reading time from a default chosen for
 * machine round trips. An operator who stepped away, or who was working out an
 * unfamiliar dialog, had the request expire underneath them and the command
 * refused (#91).
 *
 * Ten minutes is long enough to be interrupted and come back, and still bounded
 * so a client that never answers cannot pin a tool call open forever.
 */
export const APPROVAL_TIMEOUT_MS = 600_000;

/**
 * Ask the MCP client to confirm a destructive or privileged command.
 *
 * Uses the SDK's typed `Server.elicitInput()` rather than a hand-built
 * `elicitation/create` envelope, so a protocol change breaks the build instead
 * of silently disabling the gate that guards every destructive command.
 *
 * Fails closed: any error (client without elicitation support, transport
 * failure, timeout, malformed reply) denies the command. The failure is logged,
 * because a gate that always denies for an unnoticed reason is its own kind of
 * outage.
 */
export async function requestApproval(
  server: McpServer,
  command: string,
  profileName: string,
  evaluation: PolicyEvaluation,
): Promise<ApprovalResult> {
  const message = `Confirm ${evaluation.commandClass} command on "${profileName}":\n\n${command}`;

  try {
    const result = await server.server.elicitInput(
      {
        message,
        requestedSchema: {
          type: 'object',
          properties: {
            confirm: {
              type: 'boolean',
              title: 'Approve this command?',
            },
          },
          // `confirm` is deliberately not required. The protocol already carries
          // the decision in `action`, where accept and decline are distinct
          // results, so requiring a boolean on top asked the user to say the
          // same thing twice — and clients render a required boolean as a
          // checkbox beside the accept/decline row. Choosing Accept without
          // ticking it submits a form missing a required field, so the client
          // can produce no valid result and sends `cancel`, which arrived here
          // as "User did not approve this command". The user picked Approve and
          // was told they had declined (#91).
        },
      },
      { timeout: APPROVAL_TIMEOUT_MS },
    );

    // `action` decides. An explicit `confirm: false` from a client that still
    // sends the field is honoured, because refusing to run on an explicit "no"
    // costs nothing and reading it as approval would be indefensible.
    if (result.action === 'accept' && result.content?.confirm !== false) {
      return { approved: true, approver: 'mcp-client' };
    }
    return { approved: false };
  } catch (err) {
    const timedOut = err instanceof McpError && err.code === ErrorCode.RequestTimeout;
    const cause = err instanceof Error ? err.message : String(err);

    // stderr still gets it for the operator's logs, but it cannot be the only
    // copy: for a stdio MCP server that is a client log file nobody reads, so
    // the caller gets the diagnosis too and can put it in front of the user.
    console.error(
      `Approval request failed for ${evaluation.commandClass} command on "${profileName}" — denying. ` +
      `${timedOut ? `No answer within ${APPROVAL_TIMEOUT_MS / 1000}s.` : 'Does this client support elicitation?'} ` +
      `Cause: ${cause}`,
    );

    // Naming the cause rather than guessing at it. This message was introduced
    // to stop APPROVAL_DENIED covering two different failures, and then led with
    // "a client without elicitation support" for every error the catch saw,
    // timeouts included — the same defect, inside its own fix.
    return {
      approved: false,
      unavailable: timedOut
        ? `no answer arrived within ${APPROVAL_TIMEOUT_MS / 1000}s, so it was refused rather than left ` +
          `pending. The prompt may still be open in your client; approve the command again once you are ` +
          `ready to answer it.`
        : `this MCP client could not be asked to approve it. The likely cause is a client without ` +
          `elicitation support; a transport failure or a malformed reply does the same. Approval fails ` +
          `closed, so the command was refused rather than run. Underlying error: ${cause}`,
    };
  }
}
