import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { chmod, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { platform } from 'node:os';
import { createHarness, textOf, type Harness } from './harness.js';

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
    // The remote path is in the record even though nothing was resolved: it is
    // the half that needed no I/O, which is exactly why policy could see it.
    expect(record.command).toBe('sftp:upload-file /tmp/audited.bin');
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
    expect(textOf(result)).toContain('bidirectional formatting');
  });

  it('refuses a mode carrying setuid', async () => {
    h = await createHarness({}, { localPath: { transferRoot: root } });
    const result = await h.client.callTool({
      name: 'sftp-upload-file',
      arguments: { localPath: 'x.bin', remotePath: '/tmp/x.bin', mode: 0o4755 },
    }).catch((err: any) => ({ isError: true, content: [{ text: err.message }] })) as any;

    expect(result.isError).toBeTruthy();
    // Rejected by the schema's own max before the handler is entered, which is
    // the earliest place it can be caught; checkMode is the second line for a
    // caller that reaches the handler another way.
    expect(await readdir(root)).toEqual([]);
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
