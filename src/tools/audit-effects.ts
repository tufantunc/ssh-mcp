import { createHash } from 'crypto';

/**
 * How the transfer tools spell what they are about to do, in the one string the
 * approver reads, the policy classifies and the audit record keeps.
 *
 * Shared because the two tools spelled one concept differently: `sftp-upload-file`
 * already carried `--overwrite` when it would clobber, while `sftp-upload` — which
 * always clobbers — carried nothing, so the presence of the flag read as a
 * difference between the tools rather than between operations (#223). A second
 * copy of `--overwrite` is one rename away from putting them back out of step, so
 * there is one.
 *
 * `--mode` is *not* at parity and was left that way deliberately. `sftp-upload`
 * applies 0o644 on a create and never says so, while an absent `--mode=` on
 * `sftp-upload-file` means 0o600-or-inherited — one absence, two meanings, which
 * is the same shape of defect #223 describes. Fixing it means deciding what the
 * effective mode even is on an overwrite (createWriteStream's mode is ignored for
 * an existing file), which is a separate question from what this module landed for.
 */

/**
 * Spelled once so a rename cannot reach one tool and miss the other.
 *
 * Exported rather than reached through `effectSuffix(true)`: `sftp-upload` has no
 * `overwrite` parameter, so passing a literal `true` to a two-argument helper and
 * letting the reader constant-fold it needed three lines of comment to say what
 * one token says.
 */
export const OVERWRITE_FLAG = ' --overwrite';

/** The arguments that change what a transfer does, spelled for policy and the approver. */
export function effectSuffix(overwrite: boolean | undefined, mode?: number): string {
  return (overwrite ? OVERWRITE_FLAG : '') + (mode !== undefined ? ` --mode=${mode.toString(8)}` : '');
}

/**
 * 128 bits, because the property claimed here is adversarial, not accidental.
 *
 * This was 12 characters on first writing, and 48 truncated bits is ~24 bits of
 * birthday security — measured, a collision took 12.3 seconds and 10.9M hashes on
 * one core, producing two 96-byte payloads with the same `--bytes` and the same
 * digest, hence the byte-identical approved string. `--bytes` costs an attacker
 * nothing to match, since both candidates can be padded to one length. At 32
 * characters the same search is 2^64 and not worth describing.
 *
 * Length is free on the redaction axis, which is the reason a short digest looked
 * attractive. The emitted run is `--sha256=<hex>` — `-` and `=` are both in the
 * redactor's character class, so the run is the flag *plus* the digest, and at any
 * digest length it is past that scan's 20-character window and is inspected. It
 * can nonetheless never be redacted: the run draws on 20 distinct symbols, so its
 * Shannon entropy cannot exceed log2(20) = 4.32 against a 4.5 threshold. Measured
 * 4.24 at this length. An earlier version of this comment claimed the digest sat
 * *under* the window; it did not, and reasoning about a length change from that
 * claim would have started from the wrong mechanism.
 */
const DIGEST_CHARS = 32;

/**
 * What the approved string says about the bytes, for a tool whose payload is an
 * argument rather than a named file.
 *
 * `sftp-upload` takes its content inline, so unlike the streaming tools there is
 * no local path in the string to stand for it. Without this, two uploads to the
 * same destination are the same string — to the approver deciding, to
 * `ApprovalGrants` keying on it, and to an auditor later asking which one ran.
 *
 * Byte length rather than `content.length`: a JS string counts UTF-16 code units,
 * and the upload writes `Buffer.from(content)` as utf8, so the two disagree on
 * every multi-byte character. The digest is over the same encoding, which is why
 * `update(content, 'utf8')` states the encoding rather than relying on a default.
 *
 * `string` only, though `SftpClient.upload` also accepts a Buffer: the one tool
 * that calls this takes its content through `z.string()`, so a Buffer branch here
 * would be a branch no test could reach honestly. Widen it when a caller needs it,
 * with the case that needs it.
 */
export function payloadSuffix(content: string): string {
  const digest = createHash('sha256').update(content, 'utf8').digest('hex').slice(0, DIGEST_CHARS);
  return ` --bytes=${Buffer.byteLength(content, 'utf8')} --sha256=${digest}`;
}
