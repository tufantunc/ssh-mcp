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

let cached: boolean | null = null;

export async function sshAvailable(): Promise<boolean> {
  if (cached !== null) return cached;
  cached = await isSshServerUp(SSH_HOST, SSH_PORT);
  return cached;
}
