import { createHash } from 'crypto';
import { OperatorError } from '../errors.js';

export type HostKeyMode = 'tofu' | 'strict' | 'insecure';

/**
 * The one operational instruction two of the three refusals below have to give.
 *
 * Shared as a literal rather than through a message builder: the three refusals
 * deliberately diverge in their advice — MISMATCH warns against
 * `--insecureHostKey`, UNKNOWN offers two modes, PIN_MISMATCH offers none —
 * and message-quality.test.ts asserts that divergence per message. Only the
 * command is common, and only it should be.
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
 * is why a pin answers this without ever *reading* it: seeding the store from the
 * pin makes two profiles pinning different keys for one host:port collide with a
 * false HOST_KEY_MISMATCH, once the host presents each its own key. It still
 * writes, under `tofu` only — see the pin branch.
 *
 * Why `--hostKeyMode=strict` refused every host before 2.8.0 is in
 * .changeset/lucky-keys-pinned.md and SECURITY.md; the branch order here is what
 * that history left behind.
 *
 * @param pinnedFingerprint `trustedHostKey` from the profile. Falsy means no pin.
 *   A value decides the outcome in every mode, `insecure` included, and is never
 *   compared against `knownHosts`.
 */
export function verifyHostKey(
  host: string,
  port: number,
  fingerprint: string,
  knownHosts: Map<string, string>,
  mode: HostKeyMode,
  pinnedFingerprint: string | undefined,
): boolean {
  // Before `insecure`, not after: the gate this replaced sat ahead of
  // verifyHostKey in connection.ts, so a key contradicting the pin was refused in
  // every mode, `insecure` included. Pinned by host-key.test.ts, "refuses a key
  // that contradicts the pin, in every mode including insecure" — which fails on
  // the reordering, measured, so this is not a comment you have to take on faith.
  const key = `${host}:${port}`;

  // Truthiness, not `!== undefined`. `trustedHostKey = ""` was inert on 2.7.0
  // because the gate this replaced tested truthiness; `!== undefined` would turn
  // the same config into "refuse every host". The schema rejects a blank pin now,
  // so this is defence in depth rather than the primary guard.
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
    // Matched. The store is not *read* — that is what keeps two profiles pinning
    // different keys for one host:port from colliding — but it is still written,
    // and under `tofu` only.
    //
    // Dropping the write was a draft of this fix, and it cost a real refusal.
    // On 2.7.0 a matching pin fell through into the trust-on-first-use
    // accept below, so a pinned profile seeded the shared store and an unpinned
    // profile on the same host:port was compared against it. Measured: pinned
    // profile connects (served K, store becomes {H:22 -> K}), then an unpinned
    // profile is served K' and refuses with HOST_KEY_MISMATCH. Without the write
    // the unpinned profile trust-on-first-uses K' instead, and the store then
    // holds the attacker's key — so the next unpinned connection served the
    // genuine K is refused, with the diagnostic naming the real server as the
    // impostor. The collision argument does not justify dropping the write: it is
    // about the read, and the read is already skipped. (Found in review, after
    // the draft had been written down as finished.)
    //
    // `tofu` only, deliberately. Under `strict` the store is what an *unpinned*
    // profile consults, so seeding it there would let one profile's pin authorise
    // a different profile that pinned nothing — strict's whole point. Under
    // `insecure` 2.7.0 returned before reaching the write, so writing now would
    // invent a record where there was none.
    if (mode === 'tofu') knownHosts.set(key, fingerprint);
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
