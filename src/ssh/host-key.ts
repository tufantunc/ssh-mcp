import { createHash } from 'crypto';

export type HostKeyMode = 'tofu' | 'strict' | 'insecure';

export function fingerprintPublicKey(key: Buffer): string {
  const hash = createHash('sha256').update(key).digest('base64');
  return `SHA256:${hash.replace(/=+$/, '')}`;
}

export function verifyHostKey(
  host: string,
  port: number,
  fingerprint: string,
  knownHosts: Map<string, string>,
  mode: HostKeyMode,
): boolean {
  if (mode === 'insecure') return true;

  const key = `${host}:${port}`;
  const stored = knownHosts.get(key);

  if (stored) {
    if (stored !== fingerprint) {
      throw new Error(
        `HOST_KEY_MISMATCH: ${host}:${port} key changed (expected ${stored.slice(0, 20)}..., got ${fingerprint.slice(0, 20)}...)`,
      );
    }
    return true;
  }

  if (mode === 'strict') {
    throw new Error(
      `HOST_KEY_MISMATCH: No known key for ${host}:${port}. Use TOFU mode or --acceptNewHostKey to trust on first use.`,
    );
  }

  knownHosts.set(key, fingerprint);
  return true;
}
