import { describe, it, expect } from 'vitest';
import { verifyHostKey } from '../../../src/ssh/host-key.js';

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
  /**
   * The third refusal, and the only one that deliberately offers no way out.
   *
   * It lives here rather than beside the pin's behaviour cases because this file
   * is where "a refusal explains itself" is the concern — and because a sweep of
   * this file should cover all three host-key refusals, not two of them.
   */
  it('the pin refusal names the pin, shows both keys, and offers no mode as an escape', () => {
    const PIN = 'SHA256:pinnedkeypinnedkeypinnedkeypinnedkeypinne';
    const OTHER = 'SHA256:otherkeyotherkeyotherkeyotherkeyotherkeyo';
    const refused = () => verifyHostKey('10.0.0.7', 22, OTHER, new Map(), 'tofu', PIN);

    expect(refused).toThrow(/HOST_KEY_PIN_MISMATCH/);
    expect(refused).toThrow(/trustedHostKey/);
    // Both in full, for the same reason the mismatch case asserts it: the reader's
    // whole job is comparing them.
    expect(refused).toThrow(new RegExp(PIN));
    expect(refused).toThrow(new RegExp(OTHER));
    // Nothing overrides a pin — not tofu, not insecure. A refusal that named a
    // mode would be describing a way out that does not exist, which is the exact
    // failure #41 was about.
    expect(refused).not.toThrow(/--insecureHostKey|--hostKeyMode/);
  });

  it('the unknown-key refusal still names what decided and how to proceed', () => {
    const unknown = () => verifyHostKey('10.0.0.9', 22, 'SHA256:ccc', new Map(), 'strict', undefined);
    expect(unknown).toThrow(/--hostKeyMode=strict/);
    expect(unknown).toThrow(/trustedHostKey/);
  });
});
