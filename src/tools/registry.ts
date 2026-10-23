import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import type { PolicyEngine } from '../policy/engine.js';
import type { AuditStore } from '../audit/store.js';
import { createPipeline, type ToolDeps } from './pipeline.js';
import { registerSessionTools } from './session-tools.js';
import { registerCommandTools } from './command-tools.js';
import { registerFileTools } from './file-tools.js';
import { registerTransferTools } from './transfer-tools.js';
import { registerConfigTools } from './config-tools.js';

// Re-exported so existing importers keep a single entry point for the tool layer.
export { TOOL_DESCRIPTIONS, getToolHashes } from './descriptions.js';
export { registerResources } from './resources.js';

/**
 * Wire every MCP tool onto the server.
 *
 * The handlers live in four groups by subject (sessions, commands, text-mode
 * file transfer, streaming file transfer) and share one audited pipeline, built
 * here. A fifth, the config reload, runs no remote command and takes no
 * pipeline. Splitting them up is what keeps the
 * pipeline the only route from caller input to a remote command: a handler that
 * wanted to bypass policy or audit would have to reach past `pipeline` for the
 * registry, which it is not given.
 */
export function registerTools(
  server: McpServer,
  registry: ConnectionRegistry,
  policy: PolicyEngine,
  audit: AuditStore,
  opts: Omit<ToolDeps, 'server' | 'registry' | 'policy' | 'audit'> = {},
) {
  const deps: ToolDeps = { server, registry, policy, audit, ...opts };
  const pipeline = createPipeline(deps);

  registerSessionTools(deps, pipeline);
  registerCommandTools(deps, pipeline);
  registerFileTools(deps, pipeline);
  registerTransferTools(deps, pipeline);
  // Not given the pipeline: a reload runs no remote command, so it is neither
  // policy-gated nor quota-counted. The reloader writes its own audit record.
  registerConfigTools(deps);
}
