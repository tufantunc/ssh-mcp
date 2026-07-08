import { readFile } from 'fs/promises';
import { resolve } from 'path';
import type { Profile, ResolvedCredentials } from '../types.js';

export async function resolveCredentials(profile: Profile): Promise<ResolvedCredentials> {
  const creds: ResolvedCredentials = {};

  const envPrefix = `SSH_MCP_${profile.name.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;

  if (process.env.SSH_AUTH_SOCK && profile.auth === 'agent') {
    creds.agentSocket = process.env.SSH_AUTH_SOCK;
  }

  if (process.env[`${envPrefix}_PASSWORD`]) {
    creds.password = process.env[`${envPrefix}_PASSWORD`];
  } else if (process.env.SSH_MCP_PASSWORD) {
    creds.password = process.env.SSH_MCP_PASSWORD;
  }

  if (process.env[`${envPrefix}_SUDO_PASSWORD`]) {
    creds.sudoPassword = process.env[`${envPrefix}_SUDO_PASSWORD`];
  } else if (process.env.SSH_MCP_SUDO_PASSWORD) {
    creds.sudoPassword = process.env.SSH_MCP_SUDO_PASSWORD;
  }

  if (process.env[`${envPrefix}_PASSPHRASE`]) {
    creds.passphrase = process.env[`${envPrefix}_PASSPHRASE`];
  } else if (process.env.SSH_MCP_PASSPHRASE) {
    creds.passphrase = process.env.SSH_MCP_PASSPHRASE;
  }

  const keyPath = profile.keyRef || process.env[`${envPrefix}_KEY`] || process.env.SSH_MCP_KEY;
  if (keyPath) {
    try {
      creds.privateKey = await readFile(resolve(keyPath.replace(/^~/, process.env.HOME || '~')), 'utf8');
    } catch (err: any) {
      if (err.code !== 'ENOENT') throw err;
    }
  }

  if (process.env.SSH_MCP_CLI_PASSWORD) {
    creds.password = creds.password || process.env.SSH_MCP_CLI_PASSWORD;
  }
  if (process.env.SSH_MCP_CLI_SUDO_PASSWORD) {
    creds.sudoPassword = creds.sudoPassword || process.env.SSH_MCP_CLI_SUDO_PASSWORD;
  }

  if (!creds.password && !creds.privateKey && !creds.agentSocket) {
    throw new Error(
      `No credentials resolved for profile "${profile.name}". ` +
      `Set SSH_MCP_PASSWORD or SSH_MCP_KEY env var, or configure auth=agent with SSH_AUTH_SOCK.`,
    );
  }

  return creds;
}
