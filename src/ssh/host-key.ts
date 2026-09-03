import { createHash } from 'crypto';
import { OperatorError } from '../errors.js';

export type HostKeyMode = 'tofu' | 'strict' | 'insecure';

/**
 * Shared as a literal, not through a message builder: the three refusals below
 * diverge in their advice, and message-quality.test.ts asserts each one's wording
 * separately. Only the command is common, and only it should be.
 */
const CONFIRM_OUT_OF_BAND =
  '`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server';

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
 * `knownHosts` is one Map shared by every profile (connection-registry.ts), which
 * is why a pin never *reads* it: consulting it for a pinned host would make two
 * profiles pinning different keys for one host:port collide with a false
 * HOST_KEY_MISMATCH, once the host presents each its own key.
 *
 * Why `--hostKeyMode=strict` refused every host before 2.8.0 is in
 * .changeset/lucky-keys-pinned.md and SECURITY.md; the branch order here is what
 * that history left behind.
 *
 * @param pinnedFingerprint `trustedHostKey` from the profile. Falsy means no pin.
 *   A value decides the outcome in every mode, `insecure` included. It is never
 *   compared against `knownHosts`, but a match does record into it under `tofu` —
 *   see the pin branch for why those two differ.
 */
export function verifyHostKey(
  host: string,
  port: number,
  fingerprint: string,
  knownHosts: Map<string, string>,
  mode: HostKeyMode,
  pinnedFingerprint: string | undefined,
): boolean {
  const key = `${host}:${port}`;

  // Before `insecure`, not after: the gate this replaced sat ahead of
  // verifyHostKey in connection.ts, so a key contradicting the pin was refused in
  // every mode, `insecure` included. Pinned by host-key.test.ts, "refuses a key
  // that contradicts the pin, in every mode including insecure".
  //
  // Truthiness, not `!== undefined`: `trustedHostKey = ""` was inert on 2.7.0
  // because that gate tested truthiness, and `!== undefined` would turn the same
  // config into "refuse every host". The schema rejects a blank pin, so this is
  // defence in depth rather than the primary guard.
  if (pinnedFingerprint) {
    if (pinnedFingerprint !== fingerprint) {
      // No "or turn the check off" exit here, unlike the two refusals below.
      // Nothing overrides a pin — not tofu, not insecure — so offering a mode
      // would describe a way out that does not exist.
      throw new OperatorError(
        `HOST_KEY_PIN_MISMATCH: the key presented by ${host}:${port} is not the pinned key.\n` +
        `  pinned   ${pinnedFingerprint}\n` +
        `  received ${fingerprint}\n` +
        'trustedHostKey on this profile is what decided, and no host key mode overrides it. ' +
        'Either the pin is stale — the server was rebuilt or its address reused, in which case ' +
        `confirm the new fingerprint out of band (${CONFIRM_OUT_OF_BAND}) ` +
        'and update trustedHostKey — or something is intercepting this connection, ' +
        'which is what pinning exists to catch.',
      );
    }
    // Matched. Two constraints on the write, neither derivable from the code:
    //
    // `tofu` only — under `strict` the store is the only thing that admits an
    // *unpinned* profile, so seeding it there would let one profile's pin authorise
    // another. Fill-only — an unconditional set makes the entry order-dependent for
    // an unpinned sibling, and 2.7.0's write was reachable only on a store miss, so
    // this writes exactly when that one would have.
    //
    // And it is inside the match, below the throw: recording on the refusal path
    // would put an interceptor's fingerprint into the shared store, which is the
    // failure the write exists to prevent.
    if (mode === 'tofu' && !knownHosts.has(key)) knownHosts.set(key, fingerprint);
    return true;
  }

  if (mode === 'insecure') return true;

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
        `(${CONFIRM_OUT_OF_BAND}) or from whoever rebuilt it.\n` +
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
