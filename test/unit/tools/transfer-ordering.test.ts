import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { chmod, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { platform } from 'node:os';
import { createHarness, textOf, type Harness } from './harness.js';
import { checkMode } from '../../../src/tools/transfer-tools.js';

/**
 * What #207 asked for: nothing observable happens before the policy decision.
 *
 * The streaming file tools have to build an audited string from resolved paths,
 * and resolving a *local* path means touching the filesystem — an `lstat` that
 * answers "does this exist?" through the error it returns, a staged `.part`
 * file, and refusals that quote the operator's own configuration back. Doing
 * any of that before authorization hands all three to a caller who is about to
 * be denied.
 *
 * The shape these tests pin: the remote path (which policy classifies) is
 * validated purely, with no I/O; every local effect lives inside the run step,
 * which the pipeline reaches only after allow and approve.
 *
 * Skipped on Windows, where the transfer-root gate refuses outright — there is
 * no ordering to observe when the second phase never runs.
 */

const IS_WINDOWS = platform() === 'win32';

let h: Harness;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'ssh-mcp-order-'));
  await chmod(root, 0o700);
});

afterEach(async () => {
  await h?.close();
  await rm(root, { recursive: true, force: true });
});

/** A profile whose role cannot run destructive commands, so both transfers are denied. */
const DENIED = { role: 'viewer', readOnly: true, approvalPolicy: 'deny' as const };

const partFiles = async () => (await readdir(root)).filter((f) => f.includes('.part'));

describe.skipIf(IS_WINDOWS)('the streaming SFTP tools refuse before they resolve', () => {
  it('denies a download without creating the staged file it would have needed', async () => {
    h = await createHarness(DENIED, { localPath: { transferRoot: root } });
    const result = await h.client.callTool({
      name: 'sftp-download-file',
      arguments: { remotePath: '/etc/hostname', localPath: 'out.bin' },
    }) as any;

    expect(result.isError).toBeTruthy();
    // The staged `.part` is the observable effect that matters most: it is a
    // real file, in a directory the operator owns, created for a caller the
    // policy had already decided to refuse.
    expect(await partFiles()).toEqual([]);
    expect(await readdir(root)).toEqual([]);
  });

  it('answers the same way whether or not the local path exists', async () => {
    h = await createHarness(DENIED, { localPath: { transferRoot: root } });
    const ask = (localPath: string) => h.client.callTool({
      name: 'sftp-download-file',
      arguments: { remotePath: '/etc/hostname', localPath },
    }) as Promise<any>;

    await writeFile(join(root, 'present.bin'), 'x');
    const forPresent = textOf(await ask('present.bin'));
    const forAbsent = textOf(await ask('absent.bin'));

    // Identical text, because neither call reached a filesystem check. A
    // difference here is an existence oracle over the transfer root, readable
    // by a role that may not transfer anything.
    expect(forPresent).toBe(forAbsent);
    expect(forPresent).toContain('POLICY_DENIED');
  });

  it('does not leak operator configuration to a caller it refuses', async () => {
    // A root that would fail the gate's own checks, so the detailed refusals
    // are the ones a caller past policy would get. This caller is not past it.
    h = await createHarness(DENIED, { localPath: { transferRoot: '/nonexistent-root-9f3a' } });
    const result = await h.client.callTool({
      name: 'sftp-upload-file',
      arguments: { localPath: 'x.bin', remotePath: '/tmp/x.bin' },
    }) as any;

    const message = textOf(result);
    expect(result.isError).toBeTruthy();
    for (const leak of ['transferRoot', 'not an accessible directory', 'owned by', 'installation']) {
      expect(message, `refusal named "${leak}" to a caller policy had already denied`).not.toContain(leak);
    }
  });

  // The positive half. Without it the three above would also pass if the tools
  // simply never touched local disk, which is not the property being claimed.
  it('does reach the local gate once the call is allowed', async () => {
    h = await createHarness({}, { localPath: { transferRoot: root } });
    const result = await h.client.callTool({
      name: 'sftp-download-file',
      arguments: { remotePath: '/etc/hostname', localPath: '../escape.bin' },
    }) as any;

    expect(result.isError).toBeTruthy();
    // The same argument that produced a bare POLICY_DENIED above now produces
    // the transfer-root refusal, which only the second phase can raise.
    expect(textOf(result)).toContain('transferRoot');
  });

  it('records the refusal in the audit log with the class it was denied at', async () => {
    h = await createHarness(DENIED, { localPath: { transferRoot: root } });
    await h.client.callTool({
      name: 'sftp-upload-file',
      arguments: { localPath: 'x.bin', remotePath: '/tmp/audited.bin' },
    }).catch(() => {});

    const record = h.auditRecords.find((r) => r.command.startsWith('sftp:upload-file'));
    expect(record).toBeDefined();
    expect(record.decision).toBe('deny');
    expect(record.commandClass).toBe('destructive');
    // Both halves are in the record even though nothing was resolved: each is
    // the caller's own spelling, validated without I/O, which is exactly why
    // policy could see them.
    expect(record.command).toBe('sftp:upload-file /tmp/audited.bin <- x.bin');
  });
});

describe('remote path validation happens before anything else', () => {
  it('refuses a control character in the remote path', async () => {
    h = await createHarness({}, { localPath: { transferRoot: root } });
    const result = await h.client.callTool({
      name: 'sftp-list',
      // A right-to-left override: renders as one path, names another.
      arguments: { remotePath: `/tmp/${String.fromCharCode(0x202e)}gnp.exe` },
    }).catch((err: any) => ({ isError: true, content: [{ text: err.message }] })) as any;

    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toContain('bidirectional or zero-width');
  });

  it('refuses a mode carrying setuid, and says that is why', async () => {
    h = await createHarness({}, { localPath: { transferRoot: root } });
    // The file has to exist, or `localFileForRead` throws first and the refusal
    // under test never runs — which is how the previous version of this test
    // passed with both mode guards deleted.
    await writeFile(join(root, 'x.bin'), 'payload');
    const result = await h.client.callTool({
      name: 'sftp-upload-file',
      arguments: { localPath: 'x.bin', remotePath: '/tmp/x.bin', mode: 0o4755 },
    }).catch((err: any) => ({ isError: true, content: [{ text: err.message }] })) as any;

    expect(result.isError).toBeTruthy();
    // Named, so the assertion cannot be satisfied by an unrelated failure.
    expect(textOf(result)).toMatch(/mode/i);
  });

  it('refuses mode 0 rather than silently reading it as unset', async () => {
    h = await createHarness({}, { localPath: { transferRoot: root } });
    await writeFile(join(root, 'x.bin'), 'payload');
    const result = await h.client.callTool({
      name: 'sftp-upload-file',
      arguments: { localPath: 'x.bin', remotePath: '/tmp/x.bin', mode: 0 },
    }).catch((err: any) => ({ isError: true, content: [{ text: err.message }] })) as any;

    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toMatch(/mode/i);
  });
});

/**
 * `checkMode` on its own, because the zod bound on the field refuses the same
 * values first for a well-formed client — so driving it through the MCP surface
 * exercises the schema, not this function, and the message it was given cannot
 * reach a caller that way.
 */
describe('checkMode', () => {
  it('accepts an ordinary permission mode and passes it through', () => {
    for (const mode of [0o600, 0o644, 0o755, 0o777, 1]) {
      expect(checkMode(mode)).toBe(mode);
    }
    expect(checkMode(undefined)).toBeUndefined();
  });

  it('refuses setuid, setgid and the sticky bit', () => {
    for (const mode of [0o4755, 0o2755, 0o1777, 0o7777, 0o4000]) {
      expect(() => checkMode(mode), mode.toString(8)).toThrow(/setuid, setgid and the sticky bit/);
    }
  });

  it('refuses 0, which the transfer layer reads as "unset"', () => {
    // Not pedantry: `uploadFile` does `opts.mode || 0o600`, so 0 became 0600 —
    // and on the overwrite path it also suppressed the inherit-the-destination's
    // -mode step, producing neither the mode asked for nor the one replaced.
    expect(() => checkMode(0)).toThrow(/read as "unset"/);
  });

  it('refuses a negative or non-integer mode', () => {
    for (const mode of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => checkMode(mode)).toThrow();
    }
  });
});

/**
 * What a human is actually asked to approve, and what a grant is remembered
 * under. `overwrite` destroys an existing remote file and `mode` sets its
 * permissions, so a call that omits them from the authorized string lets one
 * approval of a path cover every other spelling of the call — the grant key is
 * the command string (guard/approval-grants.ts).
 */
describe('the arguments that change what a transfer does are in the authorized string', () => {
  const auditedCommandFor = async (args: Record<string, unknown>) => {
    h = await createHarness(DENIED, { localPath: { transferRoot: root } });
    await h.client.callTool({ name: 'sftp-upload-file', arguments: args }).catch(() => {});
    return h.auditRecords.find((r) => r.command.startsWith('sftp:upload-file'))?.command;
  };

  it('names overwrite and mode when they are given', async () => {
    expect(await auditedCommandFor({
      localPath: 'a.bin', remotePath: '/tmp/a.bin', overwrite: true, mode: 0o644,
    })).toBe('sftp:upload-file /tmp/a.bin --overwrite --mode=644 <- a.bin');
  });

  it('says nothing about them when they are not', async () => {
    expect(await auditedCommandFor({ localPath: 'a.bin', remotePath: '/tmp/a.bin' }))
      .toBe('sftp:upload-file /tmp/a.bin <- a.bin');
  });

  it('distinguishes a download that may clobber from one that may not', async () => {
    h = await createHarness(DENIED, { localPath: { transferRoot: root } });
    const ask = (overwrite?: boolean) => h.client.callTool({
      name: 'sftp-download-file',
      arguments: { remotePath: '/etc/hostname', localPath: 'out.bin', ...(overwrite === undefined ? {} : { overwrite }) },
    }).catch(() => {});

    await ask(true);
    await ask(false);
    const commands = h.auditRecords
      .filter((r) => r.command.startsWith('sftp:download-file'))
      .map((r) => r.command);
    expect(commands).toEqual([
      'sftp:download-file /etc/hostname --overwrite -> out.bin',
      'sftp:download-file /etc/hostname -> out.bin',
    ]);
  });
});

/**
 * A rejected call still has to reach the audit log.
 *
 * `pipeline.ts` moved sanitization inside its own try for exactly this reason —
 * "a client probing with malformed payloads used to leave none" — and these
 * handlers validate a *path*, which the pipeline's own sanitizer knows nothing
 * about. Running that validation ahead of `runAudited` would have reopened the
 * hole on the one surface whose whole job is refusing crafted paths.
 */
describe('a refused call is audited', () => {
  it('records a probe with a bidi-override path, under a placeholder', async () => {
    h = await createHarness({}, { localPath: { transferRoot: root } });
    await h.client.callTool({
      name: 'sftp-list',
      arguments: { remotePath: `/tmp/${String.fromCharCode(0x202e)}exe.doc` },
    }).catch(() => {});

    const record = h.auditRecords.find((r) => r.command.startsWith('sftp:list'));
    expect(record, 'a probe of the path validator left no audit record').toBeDefined();
    expect(record.decision).toBe('deny');
    // The placeholder, not the crafted path: the record goes into a hash-chained
    // log, and writing the override into it would be the forgery the validator
    // exists to refuse.
    expect(record.command).toBe('sftp:list (rejected: invalid remote path)');
    expect(record.command).not.toContain(String.fromCharCode(0x202e));
  });

  it('records a probe with a setuid mode', async () => {
    h = await createHarness({}, { localPath: { transferRoot: root } });
    await h.client.callTool({
      name: 'sftp-upload-file',
      arguments: { localPath: 'a.bin', remotePath: '/tmp/a.bin', mode: 0o4755 },
    }).catch(() => {});

    const record = h.auditRecords.find((r) => r.command.startsWith('sftp:upload-file'));
    expect(record).toBeDefined();
    expect(record.decision).toBe('deny');
  });
});

/**
 * #217 at the layer it was reported at.
 *
 * The engine-level assertions live in readonly-guarantee.test.ts. This one
 * drives the actual tools, because the engine tests hard-code the synthesised
 * strings (`sftp:list …`) independently of the handlers that build them — so
 * renaming a verb, or changing what the handler composes, leaves them green
 * while the tools go back to being refused for the profile the fix targeted.
 */
describe('a readOnly profile reaches the SFTP tools that only read', () => {
  const READ_ONLY = { role: 'viewer', readOnly: true, approvalPolicy: 'deny' as const };

  /**
   * The audit record *this* call produced.
   *
   * `auditRecords.at(-1)` is the last record written by anyone, and the harness
   * is shared across a loop — so a tool that wrote none re-read the previous
   * iteration's record and the assertion passed for it. Measured: breaking one
   * tool's schema so the SDK rejects before the pipeline, emitting no record at
   * all, left the loop green. Binding to the call is what makes per-tool
   * coverage real.
   */
  const decisionFor = async (name: string, args: Record<string, unknown>) => {
    const before = h.auditRecords.length;
    await h.client.callTool({ name, arguments: args }).catch(() => {});
    expect(h.auditRecords.length, `${name} wrote no audit record`).toBe(before + 1);
    return h.auditRecords[before];
  };

  const callResult = (name: string, args: Record<string, unknown>) =>
    h.client.callTool({ name, arguments: args })
      .catch((err: any) => ({ isError: true, content: [{ text: err.message }] })) as Promise<any>;

  it('is allowed to list', async () => {
    h = await createHarness(READ_ONLY, { localPath: { transferRoot: root } });
    const record = await decisionFor('sftp-list', { remotePath: '/var/log' });
    expect(record.command).toBe('sftp:list /var/log');
    expect(record.commandClass).toBe('read-only');
    expect(record.decision).toBe('allow');
  });

  it('is allowed to download', async () => {
    h = await createHarness(READ_ONLY, { localPath: { transferRoot: root } });
    const record = await decisionFor('sftp-download', { remotePath: '/etc/nginx.conf' });
    expect(record.command).toBe('sftp:download /etc/nginx.conf');
    expect(record.commandClass).toBe('read-only');
    expect(record.decision).toBe('allow');
  });

  it('is still refused every tool that writes', async () => {
    h = await createHarness(READ_ONLY, { localPath: { transferRoot: root } });
    for (const [name, args] of [
      ['sftp-upload', { remotePath: '/tmp/x', content: 'x' }],
      ['sftp-upload-file', { localPath: 'x.bin', remotePath: '/tmp/x' }],
      ['sftp-download-file', { remotePath: '/etc/hostname', localPath: 'x.bin' }],
    ] as const) {
      const record = await decisionFor(name, args);
      // The verb too, so the record is provably this tool's and not a neighbour's.
      expect(record.command, name).toMatch(new RegExp('^' + name.replace('sftp-', 'sftp:') + ' '));
      expect(record.decision, name).toBe('deny');
      expect(record.commandClass, name).toBe('destructive');
    }
  });

  it('refuses a spoofed remote path on the text tools too, not only the streaming ones', async () => {
    // `sftp-download` interpolated the caller's raw path into the audited string
    // and the approval prompt, with no validation at all — `synthetic: true`
    // skips `sanitizeCommand`. Harmless while only roles holding `safe` could
    // reach it; lowering its class is what would have opened it to every
    // readOnly profile.
    h = await createHarness({}, { localPath: { transferRoot: root } });
    const spoofed = `/tmp/${String.fromCharCode(0x202e)}txt.exe`;

    // The call has to be REFUSED, not merely audited under a placeholder. An
    // earlier version of this test asserted only the audit string, which comes
    // from `remotePathForAudit` — so deleting the `preCheck` that does the
    // refusing left it green while a spoofed path went through to the SFTP
    // layer.
    const result = await callResult('sftp-download', { remotePath: spoofed });
    expect(result.isError).toBeTruthy();
    expect(textOf(result)).toContain('bidirectional or zero-width');

    const record = h.auditRecords.at(-1);
    expect(record.decision).toBe('deny');
    expect(record.command).toBe('sftp:download (rejected: invalid remote path)');
    expect(record.command).not.toContain(String.fromCharCode(0x202e));
  });

  it('refuses a spoofed remote path on sftp-upload as well', async () => {
    h = await createHarness({}, { localPath: { transferRoot: root } });
    const result = await callResult('sftp-upload', {
      remotePath: `/tmp/${String.fromCharCode(0x200b)}x`,
      content: 'x',
    });
    expect(result.isError).toBeTruthy();
    // The message, not just `isError`: this harness's SFTP client is a stub, so
    // the call fails either way and only the *reason* distinguishes a refusal
    // from a transfer that was attempted with a spoofed path.
    expect(textOf(result)).toContain('bidirectional or zero-width');
    // Shape rather than a hard-coded digest: what this line is for is that the
    // path is the placeholder, and the suffixes must not paper over that.
    expect(h.auditRecords.at(-1).command).toMatch(
      /^sftp:upload \(rejected: invalid remote path\) --overwrite --bytes=1 --sha256=[0-9a-f]{32}$/,
    );
  });
});

describe('refineCommand can elaborate the audited string but not replace it', () => {
  /** A pipeline over stubs, so the guard can be driven directly. */
  async function runWith(refined: string) {
    const { createPipeline } = await import('../../../src/tools/pipeline.js');
    const { PolicyEngine, DEFAULT_RULES } = await import('../../../src/policy/engine.js');
    const { testProfile } = await import('./harness.js');
    const records: any[] = [];
    const conn: any = { profile: testProfile };
    const pipeline = createPipeline({
      server: {} as any,
      registry: {
        getOrCreate: async () => conn,
        getProfile: () => testProfile,
        listAllProfiles: () => [testProfile],
      } as any,
      policy: new PolicyEngine(DEFAULT_RULES),
      audit: { record: async (r: any) => { records.push(r); } } as any,
    });
    const result = await pipeline.runAudited(
      'ls /tmp',
      { toolName: 'probe', failureClass: 'read-only', extra: {}, synthetic: true },
      async (rt) => {
        rt.refineCommand(refined);
        return {
          audited: { exitCode: 0, stdout: '', stderr: '', durationMs: 0, profile: testProfile.name },
          output: { content: [{ type: 'text' as const, text: 'ok' }] },
        };
      },
    ).catch((err: Error) => err);
    return { result, records };
  }

  it('audits the elaborated string when it extends the approved one', async () => {
    const { result, records } = await runWith('ls /tmp <- /root/x');
    expect(result).not.toBeInstanceOf(Error);
    expect(records.at(-1).command).toBe('ls /tmp <- /root/x');
  });

  it('refuses a refinement that replaces the subject policy actually evaluated', async () => {
    const { result, records } = await runWith('rm -rf /');
    expect(result).toBeInstanceOf(Error);
    expect((result as Error).message).toContain('elaborated, not replaced');
    // And the record still names what was approved, not the attempted swap.
    expect(records.at(-1).command).toBe('ls /tmp');
  });
});
