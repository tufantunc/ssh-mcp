import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFile, exec } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, writeFile, rm } from 'fs/promises';
import { tmpdir, platform } from 'os';
import { join } from 'path';
import { checkPermissions } from '../../../src/config/loader.js';
import { inspectAcl } from '../../../src/config/windows-acl.js';
import { MINIMAL_CONFIG } from './helpers.js';

const run = promisify(execFile);
const shell = promisify(exec);
const onWindows = platform() === 'win32';

/**
 * The ACL check against real ACLs, which is the only place `icacls` and this
 * parser can be shown to agree. Runs on the Windows CI job.
 *
 * The prescription tests are the ones that earn their keep. #138 was not only a
 * check that could not pass — it was a check whose stated remedy did nothing, so
 * an operator who followed it exactly got the same refusal back. This suite has
 * now caught two versions of that same mistake in the replacement: a one-command
 * form that reported success and removed nothing, and a `%USERNAME%` that expands
 * only in cmd.exe. Both were invisible until the commands were executed.
 */
describe.runIf(onWindows)('Windows ACL check, against real ACLs', () => {
  let dir: string;
  let file: string;

  beforeEach(async () => {
    // Under the user profile, so the inherited ACL starts out restricted.
    dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-acl-'));
    file = join(dir, 'config.toml');
    await writeFile(file, MINIMAL_CONFIG);

    // The assumption the whole suite rests on, asserted rather than commented:
    // on a runner whose TEMP is machine-wide (C:\Windows\TEMP grants
    // BUILTIN\Users) every "accepts" test below would fail as if the product
    // were broken.
    expect((await inspectAcl(dir)).status).toBe('restricted');
    expect((await inspectAcl(file)).status).toBe('restricted');
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  /**
   * Awaits a refusal and names the behaviour when there isn't one. `.catch(e => e)`
   * leaves `undefined` on the success path, so the assertion after it fails with
   * "cannot read properties of undefined" — which points at the test rather than
   * at "checkPermissions accepted a file granted to Everyone", on a job a
   * reviewer cannot reproduce locally.
   */
  async function refusal(promise: Promise<void>): Promise<Error> {
    const err = await promise.then(() => null, (e: Error) => e);
    expect(err, 'expected checkPermissions to refuse, but it resolved').toBeInstanceOf(Error);
    return err as Error;
  }

  it('accepts a file that only its owner can reach', async () => {
    await expect(checkPermissions(file)).resolves.toBeUndefined();
  });

  it('refuses a file granted to Everyone', async () => {
    await run('icacls', [file, '/grant', '*S-1-1-0:(R)']);
    await expect(checkPermissions(file)).rejects.toThrow(/Everyone/);
  });

  it('refuses a file granted to BUILTIN\\Users', async () => {
    await run('icacls', [file, '/grant', '*S-1-5-32-545:(R)']);
    await expect(checkPermissions(file)).rejects.toThrow(/Users/);
  });

  it('refuses a file granted to a group no denylist would have named', async () => {
    // Power Users is the point of the allowlist rewrite: it is neither Everyone
    // nor Users, and the first version passed it as owner-only.
    await run('icacls', [file, '/grant', '*S-1-5-32-547:(R)']);
    await expect(checkPermissions(file)).rejects.toThrow(/Power Users/);
  });

  it('refuses when the directory is open even though the file is not', async () => {
    await run('icacls', [dir, '/grant', '*S-1-1-0:(R)']);
    await expect(checkPermissions(file)).rejects.toThrow(/directory/);
  });

  it('names the principal and the path, not just the fact of a refusal', async () => {
    await run('icacls', [file, '/grant', '*S-1-1-0:(R)']);
    const err = await refusal(checkPermissions(file));
    expect(err.message).toContain('Everyone');
    expect(err.message).toContain(file);
    expect(err.message).toContain('icacls');
  });

  /**
   * Runs the `icacls` lines out of our own error message, verbatim, through a
   * shell — no substitution, because the message no longer contains a shell
   * variable to substitute. What the operator would paste is what runs.
   */
  async function runPrescription(message: string): Promise<void> {
    const lines = message
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.startsWith('icacls '));
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) await shell(line);
  }

  /**
   * Follow the prescription until the check passes.
   *
   * The rounds are needed because the file and the directory are separate
   * subjects and the check reports the first offender — but each round must be
   * about a *different* subject. Without that assertion a prescription that only
   * converges when applied twice to the same path would pass here, and "the
   * printed fix has to be applied twice" is a defect in the message, which is the
   * class this whole suite exists to catch.
   */
  async function fixUntilClean(path: string): Promise<void> {
    const subjects: string[] = [];
    for (let round = 0; round < 3; round++) {
      const err = await checkPermissions(path).then(() => null, (e: Error) => e);
      if (err === null) break;
      subjects.push(err.message.match(/^Config (?:file|directory) (\S+)/)?.[1] ?? '?');
      await runPrescription(err.message);
    }
    await expect(checkPermissions(path)).resolves.toBeUndefined();
    expect(new Set(subjects).size, `a subject needed fixing twice: ${subjects.join(', ')}`)
      .toBe(subjects.length);
  }

  it('prescribes commands that actually fix an explicit grant', async () => {
    await run('icacls', [file, '/grant', '*S-1-1-0:(R)']);
    await expect(checkPermissions(file)).rejects.toThrow();

    await fixUntilClean(file);
    expect((await inspectAcl(file)).status).toBe('restricted');
  });

  it('prescribes commands that actually fix inherited access', async () => {
    // Entries arriving by inheritance is the realistic shape, and an inherited
    // ACE cannot be removed until inheritance is broken — which is what made the
    // single-command form silently ineffective.
    await run('icacls', [dir, '/grant', '*S-1-5-32-545:(OI)(CI)(R)']);
    const inherited = join(dir, 'inherited.toml');
    await writeFile(inherited, MINIMAL_CONFIG);
    expect((await inspectAcl(inherited)).status).toBe('broad');

    await fixUntilClean(inherited);
    expect((await inspectAcl(inherited)).status).toBe('restricted');
  });

  it('prescribes a directory command that actually fixes the directory', async () => {
    // The directory arm prints different rights — (OI)(CI)F rather than F — and
    // was never executed by any test, so those flags could have been wrong in
    // either direction without CI noticing.
    //
    // Granted without (OI)(CI) on purpose: an inheritable grant reaches the file
    // too, and the file is examined first, so the message would be about the
    // file and this test would silently exercise the arm it already covers.
    await run('icacls', [dir, '/grant', '*S-1-1-0:(R)']);
    const err = await refusal(checkPermissions(file));
    expect(err.message).toContain('directory');
    expect(err.message).toContain('(OI)(CI)F');

    await fixUntilClean(file);
    expect((await inspectAcl(dir)).status).toBe('restricted');
    // And the directory is still usable as one: a new file inherits access.
    const fresh = join(dir, 'fresh.toml');
    await writeFile(fresh, MINIMAL_CONFIG);
    expect((await inspectAcl(fresh)).status).toBe('restricted');
  });

  it('leaves SYSTEM and Administrators in place after the fix', async () => {
    // Stripping those would be its own surprise: backup, AV and repair tools
    // expect them, and %APPDATA% keeps them.
    await run('icacls', [file, '/grant', '*S-1-1-0:(R)']);
    await fixUntilClean(file);

    const { stdout } = await run('icacls', [file]);
    expect(stdout).toContain('SYSTEM');
    expect(stdout).toMatch(/Administrators|Administrat/);
  });

  it('reports a path icacls will not describe as unknown rather than clean', async () => {
    const verdict = await inspectAcl(join(dir, 'no-such-file.toml'));
    expect(verdict.status).toBe('unknown');
    if (verdict.status === 'unknown') expect(verdict.reason).toBe('read-refused');
  });

  it('refuses rather than loading when the ACL cannot be read', async () => {
    // The fail-closed direction, end to end: a path whose ACL icacls will not
    // report must not become "unchecked, loaded anyway".
    await expect(checkPermissions(join(dir, 'no-such-dir', 'config.toml'))).rejects.toThrow(
      /could not be checked/,
    );
  });

  it('loads unverified when the operator asks for it', async () => {
    await expect(
      checkPermissions(join(dir, 'no-such-dir', 'config.toml'), { allowUnchecked: true }),
    ).resolves.toBeUndefined();
  });
});
