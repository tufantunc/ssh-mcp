import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join, parse } from 'path';
import {
  inspectAcl,
  type AclOptions,
  type AclFinding,
  assertPrivateOnWindows,
  type AclVerdict,
  type Grant,
  type UnknownReason,
} from '../../../src/config/windows-acl.js';
import { OperatorError } from '../../../src/errors.js';
import { enforceAcl } from './helpers.js';

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

const grant = (name: string, trustee: string, sid: string | null, writes = false): Grant =>
  ({ name, trustee, sid, writes });
/** A grant that lets another account change the config — refused by default. */
const writer = (name: string, trustee: string, sid: string) => grant(name, trustee, sid, true);
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
function warned(): { events: AclFinding[]; warnings: string[]; opts: AclOptions } {
  const events: AclFinding[] = [];
  const warnings: string[] = [];
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { warnings.push(String(a[0])); });
  // Both halves are used: `opts` wires the sink so a test can assert the structured
  // finding, `warnings` catches the module's default when no sink is supplied. The
  // helper returned both before and every caller ignored `opts` — which was the sink
  // bug showing up in the tests as scaffolding nothing could use.
  return { events, warnings, opts: { onFinding: (e) => events.push(e) } };
}

/** Refusal is opt-in now, so every refusal test says so. */
const strict = enforceAcl;

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

describe('assertPrivateOnWindows — the three postures', () => {
  /**
   * Three postures, two flags, and no combination that strands anybody — which is the
   * whole lesson of #138 and why this is a table rather than a boolean.
   *
   * Default: a read-only over-grant is reported, because that is where Windows is muddier
   * than POSIX and refusing over it blocked a real operator. A grant that lets another
   * account *change* the config is refused, because that is an authorization bypass and
   * Windows is not muddy about it. An undeterminable ACL is refused too — #138 was a
   * known-bad verdict, never an undeterminable one, and flipping those open would let an
   * attacker swap a loud finding for a vague one at no cost.
   */
  const READ_ONLY = broad(grant('BUILTIN\\Users', 'BU', 'S-1-5-32-545'));
  const WRITABLE = broad(writer('Authenticated Users', 'AU', 'S-1-5-11'));
  const UNDETERMINABLE = unknown('read-refused', 'Access is denied');
  const MACHINE_SAYS_NOTHING = unknown('tool-missing', 'no icacls.exe');

  it('reports a read-only over-grant and loads the config', async () => {
    const { warnings, events, opts } = warned();
    await expect(assertPrivateOnWindows(FILE, opts, only(FILE, READ_ONLY))).resolves.toBeUndefined();
    // Through the caller's sink, not only to stderr: the advisory branch wrote straight to
    // console.error, so the strongest finding the check can make was the one thing no
    // caller could reach while "I could not read the ACL" was delivered structurally.
    expect(events).toEqual([expect.objectContaining({ path: FILE, kind: 'file', status: 'broad' })]);
    expect(warnings).toEqual([]);
  });

  it('names a read-only grant as readable', async () => {
    const { warnings } = warned();
    await assertPrivateOnWindows(FILE, {}, only(FILE, READ_ONLY));
    // The severity marker is part of the deliverable — it is the only thing separating an
    // advisory finding from the fatal this used to be, in an operator's startup log.
    expect(warnings[0]).toMatch(/^Warning: Config file /);
    expect(warnings[0]).toMatch(/is readable beyond its owner/);
    expect(warnings[0]).toContain('/remove:g *S-1-5-32-545');
  });

  it('refuses a write-granting ACL, and says modified rather than readable', async () => {
    // `parseDacl` used to discard the rights mask, so a modify grant and a read grant were
    // the same verdict with the same wording — an integrity failure described as a
    // disclosure. The config decides which hosts, roles and approval policy this server
    // honours, so another account being able to rewrite it is an authorization bypass.
    const err = await refusal(assertPrivateOnWindows(FILE, {}, only(FILE, WRITABLE)));
    expect(err.message).toMatch(/can be modified by accounts other than its owner/);
    expect(err.message).toContain('Authenticated Users');
  });

  it('names both when one trustee writes and another only reads', async () => {
    const mixed = broad(
      writer('Authenticated Users', 'AU', 'S-1-5-11'),
      grant('BUILTIN\\Users', 'BU', 'S-1-5-32-545'),
    );
    const err = await refusal(assertPrivateOnWindows(FILE, {}, only(FILE, mixed)));
    expect(err.message).toMatch(/modified by accounts other than its owner: Authenticated Users/);
    expect(err.message).toMatch(/and read by BUILTIN\\Users/);
  });

  it('refuses a NULL DACL, which is full control rather than read access', async () => {
    const err = await refusal(assertPrivateOnWindows(FILE, {}, only(FILE, { status: 'no-dacl' })));
    expect(err.message).toContain('no access control list');
    // Nothing to remove; the fix is to give the object an ACL at all.
    expect(err.message).toContain('/grant:r');
    expect(err.message).not.toContain('/remove:g');
  });

  it('refuses an undeterminable ACL by default', async () => {
    // Not what #138 was about, and flipping it open hands an attacker a free downgrade:
    // make the descriptor unparseable and the loud finding becomes a vague one.
    const err = await refusal(assertPrivateOnWindows(FILE, {}, only(FILE, UNDETERMINABLE)));
    expect(err.message).toContain('could not be checked');
    expect(err.message).toContain('--allowUncheckedConfigAcl');
  });

  it.each(['tool-missing', 'timed-out'] as const)(
    'reports %s and loads, because it says nothing about the file',
    async (reason) => {
      const { warnings } = warned();
      await expect(
        assertPrivateOnWindows(FILE, {}, only(FILE, unknown(reason, 'detail'))),
      ).resolves.toBeUndefined();
      expect(warnings.join('\n')).toMatch(/could not be checked/);
    },
  );

  it('reports everything and refuses nothing under --allowUncheckedConfigAcl', async () => {
    // The single exit, and it has to cover every verdict — the 2.3.0 version covered only
    // an undeterminable ACL, which is how the reporter of #138 ended up with none.
    for (const verdict of [READ_ONLY, WRITABLE, UNDETERMINABLE, { status: 'no-dacl' } as const]) {
      const { warnings } = warned();
      await expect(
        assertPrivateOnWindows(FILE, { allowUnchecked: true }, only(FILE, verdict)),
      ).resolves.toBeUndefined();
      expect(warnings, JSON.stringify(verdict)).toHaveLength(1);
    }
  });

  it('refuses everything the check objects to under --strictConfigAcl', async () => {
    for (const verdict of [READ_ONLY, WRITABLE, UNDETERMINABLE, MACHINE_SAYS_NOTHING]) {
      await refusal(assertPrivateOnWindows(FILE, strict(), only(FILE, verdict)));
    }
  });

  it('refuses instead of reporting, rather than as well', async () => {
    const { warnings, events, opts } = warned();
    await refusal(assertPrivateOnWindows(FILE, strict(opts), only(FILE, READ_ONLY)));
    expect(warnings).toEqual([]);
    expect(events).toEqual([]);
  });

  it('still examines the directory after reporting on the file', async () => {
    const seen: string[] = [];
    const { warnings } = warned();
    await assertPrivateOnWindows(FILE, {}, async (p) => {
      seen.push(p);
      return READ_ONLY;
    });
    expect(seen).toEqual([FILE, DIR]);
    // Two subjects, two findings — not one report covering both.
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain(FILE);
    expect(warnings[1]).toContain(DIR);
  });

  it('falls back to stderr when the caller supplies no sink', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    await assertPrivateOnWindows(FILE, {}, only(FILE, READ_ONLY));
    expect(String(warn.mock.calls[0][0])).toMatch(/Warning: /);
  });
});
