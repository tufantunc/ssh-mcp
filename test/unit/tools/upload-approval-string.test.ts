import { describe, it, expect, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { createHarness, type Harness } from './harness.js';

/**
 * #223: what `sftp-upload`'s approved string says about what it is going to do.
 *
 * The tool replaces an existing remote file unconditionally — `createWriteStream`
 * with default flags — and its string used to name a destination and no effect,
 * while saying nothing at all about the bytes. So two uploads to one path were one
 * string: one thing for the approver to decide, one entry for `ApprovalGrants` to
 * key on, and one indistinguishable audit record for whoever later asks which set
 * of bytes landed.
 *
 * The assertions are anchored on the whole string rather than `toContain`. Measured
 * in review: with substring assertions, renaming the flag to `--overwrite-always`,
 * multiplying the byte count by ten, lengthening the digest and swapping the suffix
 * order all left this file green. A substring assertion on a string whose whole
 * point is its exact shape tests almost nothing.
 */

/** 32 hex characters — see DIGEST_CHARS in audit-effects.ts for why not fewer. */
const DIGEST = '[0-9a-f]{32}';

let h: Harness;
afterEach(async () => { await h?.close(); });

/** The audit record for one `sftp-upload` call, with exactly one record required. */
async function upload(args: Record<string, unknown>) {
  const before = h.auditRecords.length;
  await h.client.callTool({ name: 'sftp-upload', arguments: args }).catch(() => {});
  expect(h.auditRecords.length, 'sftp-upload wrote no audit record').toBe(before + 1);
  return h.auditRecords[before];
}

describe('the approved string for sftp-upload describes the operation', () => {
  it('spells the destination, the replacement and the payload, in that order', async () => {
    h = await createHarness({});
    const record = await upload({ remotePath: '/etc/crontab', content: 'x' });
    // The decision, not only the string. Measured in review: without this, the
    // whole file passed with the approver declining, with a readOnly profile, and
    // with approvalPolicy 'never' — because a refusal records the same command.
    expect(record.decision, 'a destructive upload must reach the approval gate')
      .toBe('require-approval');
    // And got past it. `decision` is the policy's answer, not the approver's, so
    // it reads `require-approval` whether the human said yes or no — measured, a
    // declining approver left this whole file green when `decision` was the only
    // thing asserted. The refusals name themselves in `error`.
    expect(String(record.error ?? ''), 'the call must not have been refused')
      .not.toMatch(/APPROVAL_DENIED|POLICY_DENIED/);
    expect(record.command).toMatch(
      new RegExp(`^sftp:upload /etc/crontab --overwrite --bytes=1 --sha256=${DIGEST}$`),
    );
  });

  it('distinguishes two same-length uploads to the same path', async () => {
    // Same length on purpose. An earlier version used payloads of 16 and 20 bytes,
    // so `--bytes` alone separated them and the digest was never load-bearing —
    // measured, digesting a constant left that version passing. These two differ
    // only in content, which is the case an attacker constructs and the one the
    // digest exists for.
    h = await createHarness({});
    const a = await upload({ remotePath: '/etc/crontab', content: '* * * * * /bin/true\n' });
    const b = await upload({ remotePath: '/etc/crontab', content: '* * * * * /bin/evil\n' });
    expect(a.command).toContain(' --bytes=20 ');
    expect(b.command).toContain(' --bytes=20 ');
    expect(a.command).not.toBe(b.command);
  });

  it('gives identical bytes an identical string, so a repeat is still one operation', async () => {
    // The other half: the descriptor must be a function of the payload, not of the
    // call. Measured, both a counter and `Date.now()` in the suffix fail this.
    h = await createHarness({});
    const first = await upload({ remotePath: '/srv/app.conf', content: 'port = 8080\n' });
    const second = await upload({ remotePath: '/srv/app.conf', content: 'port = 8080\n' });
    expect(first.command).toBe(second.command);
  });

  it('counts the bytes that land on the host, not the characters in the argument', async () => {
    h = await createHarness({});
    const content = 'é🔑';
    // The invariant, not a number: an ASCII fixture satisfies `content.length === 3`
    // too, and then the case silently stops exercising the encoding at all.
    expect(Buffer.byteLength(content, 'utf8'),
      'precondition: the fixture must encode to more bytes than it has UTF-16 units')
      .toBeGreaterThan(content.length);
    const record = await upload({ remotePath: '/srv/x', content });
    expect(record.command).toMatch(
      new RegExp(`^sftp:upload /srv/x --overwrite --bytes=6 --sha256=${DIGEST}$`),
    );
  });

  it('digests the same bytes it uploads, in the same encoding', async () => {
    // Multi-byte fixture deliberately: for pure ASCII, latin1 and utf8 are
    // byte-identical, so an ASCII fixture cannot tell a wrong encoding from a right
    // one — measured, digesting latin1 while counting utf8 left the whole repo green.
    h = await createHarness({});
    const content = 'é🔑 hello world\n';
    const expected = createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 32);
    const record = await upload({ remotePath: '/srv/x', content });
    expect(record.command).toContain(` --sha256=${expected}`);
  });
});

describe('the string is what an approval grant is keyed on', () => {
  // The security argument for the whole change, exercised through the mechanism
  // rather than through string equality. Grants are off by default
  // (`approvalGrantTtlMs` 0), so this block has to turn them on.
  it('does not let one approval cover a different payload to the same path', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    await upload({ remotePath: '/etc/crontab', content: '* * * * * /bin/true\n' });
    await upload({ remotePath: '/etc/crontab', content: '* * * * * /bin/evil\n' });
    expect(h.approvalPrompts(), 'the second payload must be approved on its own').toBe(2);
  });

  it('still lets one approval cover a byte-identical repeat', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    await upload({ remotePath: '/etc/crontab', content: '* * * * * /bin/true\n' });
    await upload({ remotePath: '/etc/crontab', content: '* * * * * /bin/true\n' });
    expect(h.approvalPrompts(), 'an identical repeat is the same operation').toBe(1);
  });
});
