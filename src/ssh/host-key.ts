import { createHash } from 'crypto';

export type HostKeyMode = 'tofu' | 'strict' | 'insecure';

export function fingerprintPublicKey(key: Buffer): string {
  const hash = createHash('sha256').update(key).digest('base64');
  // `={0,2}` rather than `=+`: base64 padding is never longer than two
  // characters, and the bounded form cannot backtrack. Not reachable here — the
  // input is always a 44-character digest — but an unbounded trailing
  // quantifier is the shape worth not copying elsewhere.
  return `SHA256:${hash.replace(/={0,2}$/, '')}`;
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
      `HOST_KEY_UNKNOWN: No known key for ${host}:${port} and --hostKeyMode=strict is set. ` +
      'Pin the key with trustedHostKey in the profile, or use --hostKeyMode=tofu to trust on first use.',
    );
  }

  knownHosts.set(key, fingerprint);
  return true;
}
