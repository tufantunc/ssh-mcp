import { createConnection } from 'net';

export async function isSshServerUp(host: string, port: number, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, timeoutMs);
    socket.on('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

export const SSH_HOST = process.env.SSH_HOST || '127.0.0.1';
export const SSH_PORT = Number(process.env.SSH_PORT || 2222);

/**
 * Set in CI. Integration tests skip themselves when the Docker SSH servers
 * aren't running, which is convenient locally but means CI can report a green
 * run in which zero integration tests executed. With this set, an unreachable
 * server is a hard failure instead.
 */
export const REQUIRE_SSH_SERVERS = process.env.SSH_MCP_REQUIRE_SERVERS === '1';

let cached: boolean | null = null;

export async function sshAvailable(): Promise<boolean> {
  if (cached !== null) return cached;
  cached = await isSshServerUp(SSH_HOST, SSH_PORT);
  return assertAvailable(cached, `${SSH_HOST}:${SSH_PORT}`);
}

/**
 * Turns "servers are down" into a loud failure when SSH_MCP_REQUIRE_SERVERS=1,
 * and into a skip otherwise.
 */
export function assertAvailable(up: boolean, what: string): boolean {
  if (!up && REQUIRE_SSH_SERVERS) {
    throw new Error(
      `Integration servers unavailable (${what}) and SSH_MCP_REQUIRE_SERVERS=1. ` +
      'Start them with: docker compose --profile test up -d',
    );
  }
  return up;
}
