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
      // Two very different things produce this, and the message has to let the
      // reader tell them apart — otherwise the reflex is --insecureHostKey,
      // which turns the check off for every host rather than for this one.
      throw new Error(
        `HOST_KEY_MISMATCH: the key presented by ${host}:${port} is not the one seen before.\n` +
        `  expected ${stored}\n` +
        `  received ${fingerprint}\n` +
        'Either the server was rebuilt, reinstalled or had its address reused — in which case the new key is ' +
        'genuine — or something is intercepting this connection, which is what this check exists to catch. ' +
        'Nothing here can tell those apart; confirm the fingerprint out of band, from the host itself ' +
        '(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server) or from whoever rebuilt it.\n' +
        'If it matches, pin it with trustedHostKey on the profile. Do not reach for --insecureHostKey to get ' +
        'past this: it disables verification for every host and every future connection, including the case ' +
        'this message is warning you about.',
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
