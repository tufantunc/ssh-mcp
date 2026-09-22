import { describe, it, expect, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { createHarness, type Harness } from './harness.js';

/**
 * #223: what `sftp-upload`'s approved string says about what it is going to do.
 *
 * The tool replaces an existing remote file unconditionally — `createWriteStream`
 * with default flags — while its sibling `sftp-upload-file` refuses unless
 * `overwrite: true` and spells `--overwrite` into its own string. Both used to
 * render as `sftp:upload[-file] <path>`, so an approver was shown a string that
 * means "will not clobber" on one tool while approving an unconditional
 * replacement on the other, with bytes that appeared nowhere.
 *
 * `ApprovalGrants` keys on this same string, which is what turns a cosmetic
 * complaint into a security one: one approval covered the create case and the
 * destroy case because they were spelled identically.
 *
 * These assert the string, not the transfer, because the string *is* the thing
 * under test — it is what the approver reads, what policy classifies, and what
 * the audit record keeps.
 */

let h: Harness;
afterEach(async () => { await h?.close(); });

/** The audited command for one `sftp-upload` call, with exactly one record required. */
async function auditedUpload(args: Record<string, unknown>): Promise<string> {
  const before = h.auditRecords.length;
  await h.client.callTool({ name: 'sftp-upload', arguments: args }).catch(() => {});
  expect(h.auditRecords.length, 'sftp-upload wrote no audit record').toBe(before + 1);
  return h.auditRecords[before].command as string;
}

describe('the approved string for sftp-upload describes the operation', () => {
  it('spells the replacement it always performs', async () => {
    h = await createHarness({});
    const command = await auditedUpload({ remotePath: '/etc/crontab', content: 'x' });
    expect(command).toContain('sftp:upload /etc/crontab');
    expect(command, 'the tool truncates unconditionally, so the string must say so')
      .toContain(' --overwrite');
  });

  it('distinguishes two uploads to the same path', async () => {
    // The defect itself. Without a payload descriptor these two are the same
    // string, so one approval — and one ApprovalGrants entry — covers both, and
    // an auditor reading the log cannot tell which set of bytes landed.
    h = await createHarness({});
    const first = await auditedUpload({ remotePath: '/etc/crontab', content: '* * * * * true\n' });
    const second = await auditedUpload({ remotePath: '/etc/crontab', content: '* * * * * curl evil\n' });
    expect(first).not.toBe(second);
  });

  it('gives identical bytes an identical string, so a repeat is still one operation', async () => {
    // The other half of the previous case: the descriptor must be a function of
    // the payload, not of the call. A nonce here would make every upload a new
    // approval and train the approver to click through.
    h = await createHarness({});
    const first = await auditedUpload({ remotePath: '/srv/app.conf', content: 'port = 8080\n' });
    const second = await auditedUpload({ remotePath: '/srv/app.conf', content: 'port = 8080\n' });
    expect(first).toBe(second);
  });

  it('counts the bytes that land on the host, not the characters in the argument', async () => {
    // 'é' and the emoji are one JS string unit each and several utf8 bytes;
    // `SftpClient.upload` writes Buffer.from(content), so a length-based count
    // under-reports exactly what an approver is trying to judge.
    h = await createHarness({});
    const content = 'é🔑';
    const command = await auditedUpload({ remotePath: '/srv/x', content });
    // 3 UTF-16 units: 'é' is one, the emoji is a surrogate pair. 6 utf8 bytes.
    expect(content.length, 'precondition: the string is shorter than its utf8 encoding').toBe(3);
    expect(command).toContain(` --bytes=${Buffer.byteLength(content, 'utf8')}`);
    expect(command).toContain(' --bytes=6');
  });

  it('digests the same bytes it uploads', async () => {
    // Computed here from the input rather than read back from the module, so
    // this fails if the digest is ever taken over something else — the string,
    // a normalised copy, or the path.
    h = await createHarness({});
    const content = 'hello world\n';
    const expected = createHash('sha256').update(Buffer.from(content, 'utf8')).digest('hex').slice(0, 12);
    const command = await auditedUpload({ remotePath: '/srv/x', content });
    expect(command).toContain(` --sha256=${expected}`);
  });
});
