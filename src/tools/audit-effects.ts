import { createHash } from 'crypto';

/**
 * How the transfer tools spell what they are about to do, in the one string the
 * approver reads, the policy classifies and the audit record keeps.
 *
 * Shared because the defect this module exists to prevent was two tools whose
 * strings looked the same and meant different things: `sftp:upload /etc/crontab`
 * and `sftp:upload-file /etc/crontab` both named a destination and neither named
 * an effect, while one replaced the file unconditionally and the other refused
 * to (#223). A second copy of `--overwrite` is one rename away from putting them
 * back out of step, so there is one.
 */

/** The arguments that change what a transfer does, spelled for policy and the approver. */
export function effectSuffix(overwrite: boolean | undefined, mode?: number): string {
  return (overwrite ? ' --overwrite' : '') + (mode !== undefined ? ` --mode=${mode.toString(8)}` : '');
}

/**
 * Enough of the digest to tell two uploads apart, and no more.
 *
 * Twelve hex characters is 48 bits — far past what an approver comparing two
 * prompts needs, and short enough to stay readable next to a path. It also sits
 * under the audit log's entropy scan, which only inspects runs of 20 or more
 * characters (`redactor.ts`); a full digest would be inspected, though it would
 * survive anyway, since hex tops out at 4.0 bits of entropy per character
 * against a 4.5 threshold. Both facts are here because the obvious "improvement"
 * is to carry the whole digest, and the next person should know it was
 * considered rather than overlooked.
 */
const DIGEST_CHARS = 12;

/**
 * What the approved string says about the bytes, for a tool whose payload is an
 * argument rather than a named file.
 *
 * `sftp-upload` takes its content inline, so unlike the streaming tools there is
 * no local path in the string to stand for it. Without this, two uploads to the
 * same destination are indistinguishable — to the approver deciding, to
 * `ApprovalGrants` keying on the string, and to an auditor later asking which
 * one ran.
 *
 * Byte length rather than `content.length`: a JS string counts UTF-16 code
 * units, and the upload writes `Buffer.from(content)` as utf8, so the two
 * disagree on every multi-byte character. The digest is over the same bytes.
 */
export function payloadSuffix(content: string | Buffer): string {
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
  const digest = createHash('sha256').update(bytes).digest('hex').slice(0, DIGEST_CHARS);
  return ` --bytes=${bytes.byteLength} --sha256=${digest}`;
}
