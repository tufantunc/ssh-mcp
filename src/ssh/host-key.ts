import { createHash } from 'crypto';
import { OperatorError } from '../errors.js';

export type HostKeyMode = 'tofu' | 'strict' | 'insecure';

export function fingerprintPublicKey(key: Buffer): string {
  const hash = createHash('sha256').update(key).digest('base64');
  // `={0,2}` rather than `=+`: base64 padding is never longer than two
  // characters, and the bounded form cannot backtrack. Not reachable here — the
  // input is always a 44-character digest — but an unbounded trailing
  // quantifier is the shape worth not copying elsewhere.
  return `SHA256:${hash.replace(/={0,2}$/, '')}`;
}

/**
 * Decide whether to accept the key a host just presented.
 *
 * The order of the branches below is load-bearing, and two of them exist because
 * getting it wrong is how `--hostKeyMode=strict` came to refuse every host on
 * every connection until 2.8.0. The store is in-memory and lives for the process;
 * the only write to it is the trust-on-first-use accept at the bottom, which
 * `strict` never reaches. So under strict the store started empty and stayed
 * empty, and a pin did not rescue it either — `trustedHostKey` was a reject-only
 * gate in connection.ts that fell through to here and threw anyway. Strict plus a
 * correct pin, which reads like the secure configuration, connected to nothing.
 *
 * A pin now answers the question by itself, and deliberately without consulting
 * or writing the store. `knownHostsStore` is a single Map shared by every profile
 * (connection-registry.ts), so seeding it from the pin — the obvious fix, and the
 * one this replaced — meant two profiles pinning different keys for the same
 * `host:port` produced a false HOST_KEY_MISMATCH against each other's entry. A
 * pinned host has no use for trust-on-first-use memory: the pin already is that
 * memory, and it outranks anything the store could have learned.
 */
export function verifyHostKey(
  host: string,
  port: number,
  fingerprint: string,
  knownHosts: Map<string, string>,
  mode: HostKeyMode,
  trustedHostKey?: string,
): boolean {
  // Before `insecure`, not after. This function replaced a gate that sat ahead of
  // it in connection.ts, so a key contradicting the pin was refused in every mode
  // — `insecure` included. Moving the check below the early return would keep the
  // tests green and silently drop that, which is the one way this change could
  // have been a security regression rather than a fix.
  if (trustedHostKey !== undefined) {
    if (trustedHostKey !== fingerprint) {
      // No "or turn the check off" exit here, unlike the two refusals below.
      // Nothing overrides a pin — not tofu, not insecure — so offering a mode
      // would describe a way out that does not exist.
      throw new OperatorError(
        `HOST_KEY_PIN_MISMATCH: the key presented by ${host}:${port} is not the pinned key.\n` +
        `  pinned   ${trustedHostKey}\n` +
        `  received ${fingerprint}\n` +
        'trustedHostKey on this profile is what decided, and no host key mode overrides it. ' +
        'Either the pin is stale — the server was rebuilt or its address reused, in which case ' +
        'confirm the new fingerprint out of band (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` ' +
        'on the server) and update trustedHostKey — or something is intercepting this connection, ' +
        'which is what pinning exists to catch.',
      );
    }
    // Matched. Answered without reading or writing `knownHosts`, for the reason
    // in the block comment above.
    return true;
  }

  if (mode === 'insecure') return true;

  const key = `${host}:${port}`;
  const stored = knownHosts.get(key);

  if (stored) {
    if (stored !== fingerprint) {
      // Two very different things produce this, and the message has to let the
      // reader tell them apart — otherwise the reflex is --insecureHostKey,
      // which turns the check off for every host rather than for this one.
      throw new OperatorError(
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
    throw new OperatorError(
      `HOST_KEY_UNKNOWN: No known key for ${host}:${port} and --hostKeyMode=strict is set. ` +
      'Pin the key with trustedHostKey in the profile, or use --hostKeyMode=tofu to trust on first use.',
    );
  }

  knownHosts.set(key, fingerprint);
  return true;
}
