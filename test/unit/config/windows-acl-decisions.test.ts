import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join, parse } from 'path';
import {
  inspectAcl,
  type AclOptions,
  type UnverifiedAcl,
  assertPrivateOnWindows,
  type AclVerdict,
  type Grant,
  type UnknownReason,
} from '../../../src/config/windows-acl.js';
import { OperatorError } from '../../../src/errors.js';

/**
 * What the Windows branch *decides*, as opposed to what the parser reads.
 *
 * This is the gap the first review found: every branch was reachable only by
 * making a real subprocess fail on a real Windows host, so the decision that
 * matters most — whether an ACL we could not read blocks startup — was asserted on
 * no platform at all. The verdict is injected here, which makes the branches
 * testable everywhere.
 *
 * The rule being pinned: refuse when the answer is unknown, *except* when the
 * reason is about the machine rather than the file — icacls absent, or the check
 * running out of time. That exception is #138's lesson, and it is deliberately
 * narrow, because "any subprocess hiccup disables the check" is not that lesson.
 */

const ROOT = parse(process.cwd()).root;
// A config inside the user profile, which is where a tightenable directory lives.
// USERPROFILE is stubbed below so the profile-scoped branch is deterministic on
// every OS rather than depending on whether the variable happens to be set.
const PROFILE = join(ROOT, 'Users', 'me');
const FILE = join(PROFILE, 'AppData', 'Roaming', 'ssh-mcp', 'config.toml');
const DIR = join(PROFILE, 'AppData', 'Roaming', 'ssh-mcp');

const grant = (name: string, trustee: string, sid: string | null): Grant => ({ name, trustee, sid });
const EVERYONE = grant('Everyone', 'WD', 'S-1-1-0');

/** Answers `path` with `verdict`, everything else `restricted`. */
function only(path: string, verdict: AclVerdict) {
  return async (p: string): Promise<AclVerdict> => (p === path ? verdict : { status: 'restricted' });
}

const unknown = (reason: UnknownReason, detail = 'x'): AclVerdict =>
  ({ status: 'unknown', reason, detail });

const broad = (...grants: Grant[]): AclVerdict => ({ status: 'broad', grants });

/** Awaits the refusal and names the behaviour if there isn't one. */
/** The default posture: report, do not refuse. */
function warned(): { events: UnverifiedAcl[]; warnings: string[]; opts: AclOptions } {
  const events: UnverifiedAcl[] = [];
  const warnings: string[] = [];
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { warnings.push(String(a[0])); });
  return { events, warnings, opts: { onUnverified: (e) => events.push(e) } };
}

/** Refusal is opt-in now, so every refusal test says so. */
const strict = (extra: AclOptions = {}): AclOptions => ({ ...extra, strict: true });

async function refusal(p: Promise<void>): Promise<Error> {
  const err = await p.then(() => null, (e: Error) => e);
  expect(err, 'expected a refusal, but the check accepted the path').toBeInstanceOf(OperatorError);
  return err as Error;
}

beforeEach(() => vi.stubEnv('USERPROFILE', PROFILE));

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe('inspectAcl — the shared deadline', () => {
  it('yields unknown, never restricted, when the budget is already spent', async () => {
    // The bound belongs to the check, not to each subprocess it happens to start:
    // an earlier shape gave every child its own budget, so three children meant a
    // 3x ceiling. Runs on every platform — the point is the direction of the answer
    // under an expired deadline, not which reason it lands on.
    const verdict = await inspectAcl('anything', AbortSignal.abort());
    expect(verdict.status).toBe('unknown');
  });

  it('does not remember a failed identity lookup', async () => {
    // Memoising the failure made one aborted whoami pin identity-unknown for the
    // life of the process, so every later check refused.
    await inspectAcl('anything', AbortSignal.abort());
    expect((await inspectAcl('anything', AbortSignal.abort())).status).toBe('unknown');
  });
});

describe('assertPrivateOnWindows — a clean ACL', () => {
  it('accepts when both the file and its directory are restricted', async () => {
    const seen: string[] = [];
    const inspect = async (p: string): Promise<AclVerdict> => {
      seen.push(p);
      return { status: 'restricted' };
    };
    await expect(assertPrivateOnWindows(FILE, {}, inspect)).resolves.toBeUndefined();
    // Both subjects are examined; checking only the file would miss a directory
    // that lets another account replace the config wholesale.
    expect(seen).toEqual([FILE, DIR]);
  });
});

describe('assertPrivateOnWindows — a broad ACL', () => {
  it('refuses and names the principals', async () => {
    const err = await refusal(
      assertPrivateOnWindows(FILE, strict(), only(FILE, broad(
        grant('BUILTIN\\Users', 'BU', 'S-1-5-32-545'),
        grant('Authenticated Users', 'AU', 'S-1-5-11'),
      ))),
    );
    expect(err.message).toContain('BUILTIN\\Users, Authenticated Users');
    expect(err.message).toContain(FILE);
  });

  it('prescribes removal by SID, which is the only spelling icacls accepts', async () => {
    // `*` introduces a SID. Measured: `*WD` happens to be accepted but `*DU` exits
    // 1337 having done nothing — and DU is what a descriptor on a domain-joined
    // host, the case this check exists for, actually spells. So the fixture uses
    // the realistic alias trustee and the assertion demands a SID in the command.
    const err = await refusal(assertPrivateOnWindows(FILE, strict(), only(FILE, broad(EVERYONE))));
    expect(err.message).toMatch(/\/remove:g \*S-1-[0-9-]+\b/);
    expect(err.message).not.toMatch(/\/remove:g \*[A-Z]{2,3}\b/);
  });

  it('removes exactly the trustees it found, for a mix of spellings', async () => {
    const err = await refusal(
      assertPrivateOnWindows(FILE, strict(), only(FILE, broad(
        EVERYONE,
        grant('S-1-5-21-1-2-3-513', 'S-1-5-21-1-2-3-513', 'S-1-5-21-1-2-3-513'),
      ))),
    );
    expect(err.message).toContain('/remove:g *S-1-1-0');
    expect(err.message).toContain('/remove:g *S-1-5-21-1-2-3-513');
    // Removing entries that were never granted would be noise; missing one would
    // leave the file open after the operator did as they were told.
    expect(err.message).not.toContain('S-1-5-32-545');
  });

  it('names an unresolvable alias instead of printing a /remove:g that does nothing', async () => {
    // `*` declares a numeric SID to icacls, so `/remove:g *OW` is accepted and removes
    // nothing — the operator restarts into the identical refusal, and the escape hatch
    // does not cover a broad verdict. Aliases outside the table (AC on C:\Program Files,
    // OW on redirected profiles) and every domain-relative one on a host with no account
    // domain land here.
    const err = await refusal(
      assertPrivateOnWindows(FILE, strict(), only(FILE, broad(grant('OW', 'OW', null)))),
    );
    expect(err.message).not.toMatch(/\/remove:g \*[A-Z]{2,3}\b/);
    expect(err.message).toMatch(/cannot be named as a SID/);
    expect(err.message).toContain('OW');
  });

  it('still removes the entries it can name when only one is unresolvable', async () => {
    const err = await refusal(
      assertPrivateOnWindows(FILE, strict(), only(FILE, broad(EVERYONE, grant('OW', 'OW', null)))),
    );
    expect(err.message).toContain('/remove:g *S-1-1-0');
    expect(err.message).toMatch(/cannot be named as a SID/);
  });

  it('does not put a shell variable in the command', async () => {
    // %USERNAME% is cmd.exe syntax. Pasted into PowerShell — the default shell on
    // Windows 11 — icacls receives it literally, reports "Failed processing 1
    // files", and changes nothing. Measured. That is `chmod 600` one shell over.
    const err = await refusal(assertPrivateOnWindows(FILE, strict(), only(FILE, broad(EVERYONE))));
    expect(err.message).not.toContain('%USERNAME%');
    expect(err.message).toMatch(/\/grant:r "[^"%]+:/);
  });

  it('uses inheritable rights for a directory and plain rights for a file', async () => {
    const onFile = await refusal(assertPrivateOnWindows(FILE, strict(), only(FILE, broad(EVERYONE))));
    const onDir = await refusal(assertPrivateOnWindows(FILE, strict(), only(DIR, broad(EVERYONE))));
    expect(onFile.message).toContain(':F"');
    expect(onFile.message).not.toContain('(OI)(CI)');
    expect(onDir.message).toContain('(OI)(CI)F');
  });

  it('refuses to prescribe ACL surgery on a filesystem root', async () => {
    // A config at the drive root makes the directory subject the root itself. The
    // first version printed `icacls "C:\" /inheritance:d` plus a `/remove:g` of
    // BUILTIN\Users — which, run as printed, takes the volume away from every
    // non-administrator account.
    const err = await refusal(
      assertPrivateOnWindows(join(ROOT, 'config.toml'), strict(), only(ROOT, broad(
        grant('BUILTIN\\Users', 'BU', 'S-1-5-32-545'),
      ))),
    );
    // Leads with relocation, and still prints the commands rather than pointing at
    // text that is not there — with the removals, because a pair without them reports
    // success and changes nothing.
    expect(err.message.indexOf('Move the config')).toBeLessThan(err.message.indexOf('icacls'));
    expect(err.message).toMatch(/only you can judge/);
    expect(err.message).toContain('/remove:g *S-1-5-32-545');
  });

  it('refuses to prescribe ACL surgery on the working directory', async () => {
    // `--config config.toml` is documented usage, and it makes the directory
    // subject `.` — the working directory, which belongs to whichever MCP client
    // spawned us, not to the operator. Same destructive shape as the root case.
    const err = await refusal(
      assertPrivateOnWindows('config.toml', strict(), only('.', broad(EVERYONE))),
    );
    expect(err.message.indexOf('Move the config')).toBeLessThan(err.message.indexOf('icacls'));
    expect(err.message).toMatch(/only you can judge/);
  });

  it('still prescribes the fix for the file itself, wherever it lives', async () => {
    // A file is always tightenable: removing a broad entry from one config file
    // takes nothing from anyone. Scoping the profile rule to files as well made the
    // advice for the commonest real case — a config under C:\sshcfg — worse than
    // what it replaced.
    const outsideFile = join(ROOT, 'sshcfg', 'config.toml');
    const err = await refusal(
      assertPrivateOnWindows(outsideFile, strict(), only(outsideFile, broad(EVERYONE))),
    );
    expect(err.message).toContain('/inheritance:d');
    expect(err.message).toContain('/remove:g *S-1-1-0');
  });

  it('refuses to prescribe ACL surgery on a directory outside the user profile', async () => {
    // Not just roots. Everything under C:\ inherits BUILTIN\Users read-and-execute,
    // so `--config C:\Users\config.toml` produces a broad verdict — and the advice
    // would be to strip BUILTIN\Users from C:\Users, which removes every other
    // account's traverse to its own profile.
    const outside = join(ROOT, 'Users', 'config.toml');
    const err = await refusal(
      assertPrivateOnWindows(outside, strict(), only(join(ROOT, 'Users'), broad(
        grant('BUILTIN\\Users', 'BU', 'S-1-5-32-545'),
      ))),
    );
    expect(err.message).toMatch(/Move the config/);
    // The door is left open: a directory that really is the operator's alone is
    // tightenable, and telling them otherwise would be poor advice — so the commands
    // are printed, behind the judgement the operator has to make.
    expect(err.message).toMatch(/only you can judge/);
    expect(err.message).toContain('/remove:g *S-1-5-32-545');
  });

  it('describes rather than prescribes when there is no profile to compare against', async () => {
    // With no USERPROFILE the containment question cannot be answered, and the honest
    // answer is "cannot tell". Returning "tightenable" reinstated exactly the advice this
    // guard exists to prevent: strip BUILTIN\Users from a shared directory.
    vi.stubEnv('USERPROFILE', '');
    const err = await refusal(
      assertPrivateOnWindows(FILE, strict(), only(DIR, broad(grant('BUILTIN\\Users', 'BU', 'S-1-5-32-545')))),
    );
    expect(err.message).toMatch(/Move the config/);
  });

  it('refuses to prescribe ACL surgery on the parent directory', async () => {
    const err = await refusal(
      assertPrivateOnWindows(join('..', 'config.toml'), strict(), only('..', broad(EVERYONE))),
    );
    expect(err.message).toMatch(/Move the config/);
  });
});

describe('assertPrivateOnWindows — a NULL DACL', () => {
  it('refuses, because no ACL means full control for everyone', async () => {
    const err = await refusal(assertPrivateOnWindows(FILE, strict(), only(FILE, { status: 'no-dacl' })));
    expect(err.message).toContain('no access control list');
  });

  it('prescribes granting a DACL rather than removing entries', async () => {
    // There is nothing to /remove:g — the fix is to give the file an ACL at all.
    const err = await refusal(assertPrivateOnWindows(FILE, strict(), only(FILE, { status: 'no-dacl' })));
    expect(err.message).toContain('/grant:r');
    expect(err.message).not.toContain('/remove:g');
  });
});

describe('assertPrivateOnWindows — an unknown ACL', () => {
  it('loads anyway, reporting it, when icacls is not on the machine', async () => {
    // One of two fail-open cases. Server Core and stripped images exist, and a
    // check that cannot run there must not be a reason to refuse the config.
    const reported: unknown[] = [];
    await expect(
      assertPrivateOnWindows(
        FILE,
        strict({ onUnverified: (e) => reported.push(e) }),
        only(FILE, unknown('tool-missing', 'no icacls.exe')),
      ),
    ).resolves.toBeUndefined();
    expect(reported).toEqual([{ path: FILE, reason: 'tool-missing', detail: 'no icacls.exe' }]);
  });

  it('loads anyway when the check ran out of time', async () => {
    // Also a statement about the machine: process creation under on-access
    // scanning can outlast any budget, and refusing then is #138's shape.
    const reported: unknown[] = [];
    await expect(
      assertPrivateOnWindows(
        FILE,
        strict({ onUnverified: (e) => reported.push(e) }),
        only(FILE, unknown('timed-out', 'exceeded 5000ms')),
      ),
    ).resolves.toBeUndefined();
    expect(reported).toHaveLength(1);
  });

  it('falls back to stderr when the caller supplies no sink', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    await expect(
      assertPrivateOnWindows(FILE, strict(), only(FILE, unknown('tool-missing'))),
    ).resolves.toBeUndefined();
    expect(String(warn.mock.calls[0][0])).toMatch(/was not checked/);
  });

  it('refuses when icacls ran and would not describe the path', async () => {
    // Access denied on a DACL read is evidence about the file. The first version
    // collapsed every failure to "unchecked, load anyway", so breaking icacls was
    // enough to disable the check.
    const err = await refusal(
      assertPrivateOnWindows(FILE, strict(), only(FILE, unknown('read-refused', 'Access is denied'))),
    );
    expect(err.message).toContain('read-refused');
    expect(err.message).toContain('--allowUncheckedConfigAcl');
  });

  it('refuses a descriptor it cannot parse', async () => {
    const err = await refusal(
      assertPrivateOnWindows(FILE, strict(), only(FILE, unknown('unparsable', 'no DACL component'))),
    );
    expect(err.message).toContain('unparsable');
  });

  it("refuses when this account's own SID could not be read", async () => {
    // Without an identity there is no allowlist to compare against, so a verdict
    // would be meaningless rather than merely uncertain.
    await refusal(assertPrivateOnWindows(FILE, strict(), only(FILE, unknown('identity-unknown'))));
  });

  it('honours --allowUncheckedConfigAcl for the refusing reasons', async () => {
    const reported: unknown[] = [];
    await expect(
      assertPrivateOnWindows(
        FILE,
        strict({ allowUnchecked: true, onUnverified: (e) => reported.push(e) }),
        only(FILE, unknown('read-refused', 'Access is denied')),
      ),
    ).resolves.toBeUndefined();
    expect(reported).toHaveLength(1);
  });

  it('does not let the escape hatch turn a broad ACL into a warning', async () => {
    // The flag is about an unanswered question, not about a known-bad answer.
    await expect(
      assertPrivateOnWindows(FILE, strict({ allowUnchecked: true }), only(FILE, broad(EVERYONE))),
    ).rejects.toThrow(/Everyone/);
  });
});

describe('assertPrivateOnWindows — advisory by default', () => {
  /**
   * The posture this settled on, and why.
   *
   * 2.3.0 refused a broad ACL, and on the first day it blocked a reporter's config at the
   * documented `%APPDATA%` location: their ACL carried a principal the allowlist did not
   * know about, because the allowlist was measured on one machine. `--allowUncheckedConfigAcl`
   * deliberately did not cover a known-bad verdict, so there was no way past it — a check
   * whose worst outcome is stranding an operator in their own config.
   */
  it('reports a broad ACL and loads the config', async () => {
    const { warnings } = warned();
    await expect(
      assertPrivateOnWindows(FILE, {}, only(FILE, broad(EVERYONE))),
    ).resolves.toBeUndefined();
    expect(warnings.join('\n')).toMatch(/readable beyond its owner/);
    // The commands are still printed: the finding is worth stating, and stating it is not
    // the same act as refusing.
    expect(warnings.join('\n')).toContain('/remove:g *S-1-1-0');
  });

  it('reports a NULL DACL and loads the config', async () => {
    const { warnings } = warned();
    await expect(
      assertPrivateOnWindows(FILE, {}, only(FILE, { status: 'no-dacl' })),
    ).resolves.toBeUndefined();
    expect(warnings.join('\n')).toMatch(/no access control list/);
  });

  it('reports an undeterminable ACL and loads the config', async () => {
    const { warnings } = warned();
    await expect(
      assertPrivateOnWindows(FILE, {}, only(FILE, unknown('read-refused', 'Access is denied'))),
    ).resolves.toBeUndefined();
    expect(warnings.join('\n')).toMatch(/was not checked/);
  });

  it('still examines the directory after warning about the file', async () => {
    // Warning must not short-circuit what refusing used to.
    const seen: string[] = [];
    warned();
    await assertPrivateOnWindows(FILE, {}, async (p) => {
      seen.push(p);
      return broad(EVERYONE);
    });
    expect(seen).toEqual([FILE, DIR]);
  });

  it('refuses only when --strictConfigAcl asks it to', async () => {
    await expect(
      refusal(assertPrivateOnWindows(FILE, strict(), only(FILE, broad(EVERYONE)))),
    ).resolves.toBeInstanceOf(OperatorError);
  });
});
