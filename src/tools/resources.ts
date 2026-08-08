import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';

export function registerResources(
  server: McpServer,
  registry: ConnectionRegistry,
) {
  function jsonResource(uri: string, data: unknown) {
    return {
      contents: [{
        uri,
        mimeType: 'application/json',
        text: JSON.stringify(data, null, 2),
      }],
    };
  }

  server.resource(
    'connections',
    'ssh://connections',
    { description: 'List all SSH profiles and their connection status', mimeType: 'application/json' },
    async () => {
      const connections = registry.listConnections();
      const profiles = registry.listAllProfiles().map((p) => {
        const conn = connections.find((c) => c.profile === p.name);
        return {
          name: p.name,
          host: p.host,
          port: p.port,
          user: p.user,
          role: p.role,
          readOnly: p.readOnly,
          approvalPolicy: p.approvalPolicy,
          status: conn?.status || 'disconnected',
          sessions: conn?.sessionCount || 0,
        };
      });
      return jsonResource('ssh://connections', { profiles });
    },
  );

  server.resource(
    'profile',
    new ResourceTemplate('ssh://connections/{profile}', { list: undefined }),
    { description: 'Get details for a specific SSH profile', mimeType: 'application/json' },
    async (uri, variables) => {
      const profileName = variables.profile as string;
      const profile = registry.listAllProfiles().find((p) => p.name === profileName);
      if (!profile) {
        return jsonResource(uri.href, { error: `Profile "${profileName}" not found` });
      }
      const conn = registry.get(profileName);
      const sessions = conn?.listSessions().map((s) => s.toInfo()) || [];
      return jsonResource(uri.href, {
        profile: {
          name: profile.name,
          host: profile.host,
          port: profile.port,
          user: profile.user,
          role: profile.role,
          readOnly: profile.readOnly,
          auth: profile.auth,
          approvalPolicy: profile.approvalPolicy,
          via: profile.via,
          workdir: profile.workdir,
          tty: profile.tty,
          timeout: profile.timeout,
          maxChars: profile.maxChars,
          sessionMaxPerConnection: profile.sessionMaxPerConnection,
          sessionIdleTimeoutMs: profile.sessionIdleTimeoutMs,
        },
        connection: conn?.toInfo() || null,
        sessions,
      });
    },
  );

  server.resource(
    'session',
    new ResourceTemplate('ssh://sessions/{profile}/{session}', { list: undefined }),
    { description: 'Get metadata for a specific session', mimeType: 'application/json' },
    async (uri, variables) => {
      const profileName = variables.profile as string;
      const sessionName = variables.session as string;
      const conn = registry.get(profileName);
      if (!conn) {
        return jsonResource(uri.href, { error: `Profile "${profileName}" not connected` });
      }
      const session = conn.getSession(sessionName);
      if (!session) {
        return jsonResource(uri.href, { error: `Session "${sessionName}" not found on ${profileName}` });
      }
      return jsonResource(uri.href, session.toInfo());
    },
  );
}
