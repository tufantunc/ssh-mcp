import { describe, it, expect } from 'vitest';
import { verifyHostKey, fingerprintPublicKey } from '../../../src/ssh/host-key.js';

/**
 * #41: mechanisms that work correctly while telling the reader something
 * misleading. Both messages here refuse correctly; what they said pushed the
 * reader towards the least safe way out.
 *
 * These assert on wording, which is unusual and deliberate. The wording *is*
 * the fix — a test on the throw alone would have passed before it.
 */
describe('host key mismatch explains itself', () => {
  const seen = () => new Map([['10.0.0.5:22', 'SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']]);
  const mismatch = () =>
    verifyHostKey('10.0.0.5', 22, 'SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', seen(), 'tofu', undefined);

  it('names both causes rather than only the fact', () => {
    // The reader cannot act on "the key changed" alone: a rebuilt server and an
    // interception produce the identical symptom.
    expect(mismatch).toThrow(/rebuilt|reinstalled/);
    expect(mismatch).toThrow(/intercepting/);
  });

  it('says how to tell them apart, out of band', () => {
    expect(mismatch).toThrow(/out of band/);
    expect(mismatch).toThrow(/ssh-keygen -lf/);
  });

  it('shows both fingerprints in full', () => {
    // Truncating to 20 characters made the two look alike at a glance, which is
    // the one comparison the reader has to make.
    expect(mismatch).toThrow(/SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
    expect(mismatch).toThrow(/SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/);
  });

  it('warns against the escape hatch it would otherwise invite', () => {
    // --insecureHostKey disables verification for every host, not this one.
    expect(mismatch).toThrow(/every host/);
  });

  // The message next door was already right, and is the standard the one above
  // was measured against: it names the setting that decided and gives two ways out.
  it('the unknown-key refusal still names what decided and how to proceed', () => {
    const unknown = () => verifyHostKey('10.0.0.9', 22, 'SHA256:ccc', new Map(), 'strict', undefined);
    expect(unknown).toThrow(/--hostKeyMode=strict/);
    expect(unknown).toThrow(/trustedHostKey/);
  });

  // All three host-key refusals belong in the file where "a refusal explains
  // itself" is the concern; this is the only one that deliberately offers no exit.
  it('the pin refusal names the pin, shows both keys against their labels, and offers no escape', () => {
    const PIN = fingerprintPublicKey(Buffer.from('pinned-host-key'));
    const OTHER = fingerprintPublicKey(Buffer.from('some-other-host-key'));
    const esc = (fp: string) => fp.replace(/[+/]/g, (c) => `\\${c}`);
    const refused = () => verifyHostKey('10.0.0.7', 22, OTHER, new Map(), 'tofu', PIN);

    expect(refused).toThrow(/HOST_KEY_PIN_MISMATCH/);
    expect(refused).toThrow(/trustedHostKey/);

    // Bound to their labels, not merely present. Two `toThrow(substring)` checks
    // pass just as happily on a message that tells the operator their config holds
    // the key the server presented and the server presented their pin — and
    // comparing the two is the reader's whole job here.
    expect(refused).toThrow(new RegExp(`pinned\\s+${esc(PIN)}`));
    expect(refused).toThrow(new RegExp(`received\\s+${esc(OTHER)}`));

    // The actionable half. Without these the entire diagnostic — both causes, the
    // verification command, "update trustedHostKey" — is deletable with the suite
    // green, which is the #41 class this file exists to catch. It is also the only
    // assertion holding the shared CONFIRM_OUT_OF_BAND to its second consumer.
    expect(refused).toThrow(/out of band/);
    expect(refused).toThrow(/ssh-keygen -lf/);
    expect(refused).toThrow(/rebuilt/);
    expect(refused).toThrow(/intercepting/);

    // Nothing overrides a pin — not tofu, not insecure. A refusal naming a mode
    // would describe a way out that does not exist.
    expect(refused).not.toThrow(/--insecureHostKey|--hostKeyMode/);
  });
});
