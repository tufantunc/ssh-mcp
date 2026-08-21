import { describe, it, expect } from 'vitest';
import { join } from 'path';
import { parseDacl, aclIdentity, type AclVerdict } from '../../../src/config/sddl.js';
// Stays behind the cut: classifying an icacls failure is the platform half's vocabulary.
import { classifyReadFailure } from '../../../src/config/windows-acl.js';

/**
 * The SDDL parser, which runs everywhere, so it is tested everywhere. The
 * descriptors below are real: each was produced by `icacls <path> /save` on a
 * Windows 11 host and pasted verbatim, because a hand-written one would only
 * prove the parser agrees with my idea of the format.
 *
 * The invariant the first version got wrong: there must be no input for which
 * "I could not account for this" and "restricted to the owner" produce the same
 * answer. It returned an empty list — read as safe — for a NULL DACL, for a
 * descriptor with no DACL, for a conditional ACE, and for the string `D:\`.
 */

const OWNER = 'S-1-5-21-185570930-3122470475-1457210486-1001';
const DOMAIN = 'S-1-5-21-185570930-3122470475-1457210486';
// The production rule, not a replica of it. A hand-built set let 40 parser tests keep
// passing against a policy the product no longer had.
const ALLOWED = aclIdentity(OWNER);

/** %APPDATA%\ssh-mcp\config.toml — owner, SYSTEM, Administrators, inherited. */
const NARROW = `D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;${OWNER})`;

/** C:\sshcfg\config.toml — inherited from the drive root. */
const DRIVE_ROOT = 'D:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)';

/** After `icacls <file> /grant *S-1-1-0:(R)`. */
const EVERYONE = `D:AI(A;;FR;;;WD)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;${OWNER})`;

/** C:\sshcfg — note the inherit-only AU entry, which grants nothing here. */
const DIR_WITH_INHERIT_ONLY =
  'D:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)';

const parse = (d: string): AclVerdict => parseDacl(d, ALLOWED);
const status = (d: string) => parse(d).status;
const namesIn = (d: string) => {
  const v = parse(d);
  return v.status === 'broad' ? v.grants.map((g) => g.name).sort() : v.status;
};

describe('parseDacl — accepts only what it can account for', () => {
  it('accepts an ACL restricted to owner, SYSTEM and Administrators', () => {
    expect(status(NARROW)).toBe('restricted');
  });

  it('flags the drive-root inheritance that --config walks into', () => {
    expect(namesIn(DRIVE_ROOT)).toEqual(['Authenticated Users', 'BUILTIN\\Users']);
  });

  it('flags an explicit Everyone grant', () => {
    expect(namesIn(EVERYONE)).toEqual(['Everyone']);
  });

  it('ignores a principal granted only by an inherit-only ACE', () => {
    // The sibling case below grants AU twice, so dedupe would hide a missing skip.
    // Here the skip is the only reason the principal is absent.
    expect(status('D:AI(A;OICIIOID;FA;;;AU)(A;ID;FA;;;SY)')).toBe('restricted');
  });

  it('ignores an inherit-only ACE, which grants nothing on this object', () => {
    // The AU entry appears twice in this real descriptor: once applying here,
    // once inherit-only. Counting the second would be wrong, and counting it
    // twice would name the same principal twice.
    expect(namesIn(DIR_WITH_INHERIT_ONLY)).toEqual(['Authenticated Users', 'BUILTIN\\Users']);
  });

  it('ignores a deny ACE, which restricts rather than grants', () => {
    expect(status('D:(D;;FA;;;WD)(A;ID;FA;;;SY)')).toBe('restricted');
  });

  it('treats an empty DACL as private, because it denies everyone', () => {
    expect(status('D:')).toBe('restricted');
    expect(status('D:P')).toBe('restricted');
  });
});

describe('parseDacl — the openings the first version reported as safe', () => {
  it('refuses a NULL DACL, which grants full control to every account', () => {
    // D:NO_ACCESS_CONTROL is the most open ACL a file can carry and contains no
    // ACEs, so an ACE scan alone calls it restricted.
    expect(status('D:NO_ACCESS_CONTROL')).toBe('no-dacl');
  });

  it('reports a descriptor with no DACL as unknown, not as safe', () => {
    expect(parse('O:BAG:BA')).toMatchObject({ status: 'unknown', reason: 'unparsable' });
  });

  it('reports a drive path that merely looks like a descriptor as unknown', () => {
    // The item-name line of `icacls /save` output. Selecting it instead of the
    // descriptor used to yield "clean".
    expect(parse('D:\\')).toMatchObject({ status: 'unknown' });
    expect(parse('D:\\cfg\\config.toml')).toMatchObject({ status: 'unknown' });
  });

  it('counts a conditional allow ACE, which grants when its condition holds', () => {
    // XA/ZA are what Dynamic Access Control writes. A type filter of A|OA
    // skipped them silently.
    expect(namesIn('D:AI(XA;;FA;;;WD;(@USER.Title=="x"))')).toEqual(['Everyone']);
    expect(namesIn('D:AI(ZA;;FR;;;BU;(@USER.Title=="x"))')).toEqual(['BUILTIN\\Users']);
  });

  it('does not truncate a conditional ACE whose expression nests parentheses', () => {
    expect(namesIn('D:AI(XA;;FR;;;WD;(Member_of {SID(BA)}))')).toEqual(['Everyone']);
  });

  it('does not merge ACEs across a paren inside a quoted condition', () => {
    // The quote-blind scan counted the literal's paren and swallowed the two real grants
    // into one group whose trustee was the owner — verified `restricted` before the fix.
    // Refusing is the outcome now, not reporting the grants: a descriptor whose quoting
    // and parenthesisation disagree is one we cannot account for, and `unknown` is what
    // that has to mean. What matters is only that it is never `restricted`.
    const attack =
      `D:AI(XA;;FR;;;${OWNER};(@USER.a=="("))(A;;0x1200a9;;;BU)(A;;0x1301bf;;;AU)` +
      `(XA;;FR;;;${OWNER};(@USER.a==")"))(A;;FA;;;${OWNER})`;
    expect(parse(attack).status).not.toBe('restricted');
  });

  it('still reads a conditional ACE whose quoted literal is balanced', () => {
    // The refusal above must not cost the ordinary case: quotes around a balanced
    // expression are fine, and the grant inside is still counted.
    expect(namesIn('D:AI(XA;;FR;;;WD;(@USER.a=="(x)"))')).toEqual(['Everyone']);
  });

  it('does not merge ACEs across an unmatched quote either', () => {
    // Closing the paren variant opened this one: two literals each carrying a single
    // unmatched quote put the scanner inQuotes across the ACE boundary, so the group's
    // type, flags and trustee all became the attacker's. Five such shapes came back
    // `restricted`; the quote-blind balance check refuses them.
    const hidden = `(A;ID;FA;;;WD)(A;ID;0x1200a9;;;BU)(A;ID;FA;;;AU)`;
    for (const attack of [
      `D:AI(XA;;FA;;;SY;(@U.a=="))${hidden}(XA;;FA;;;SY;(@U.b=="))`,
      `D:AI(ZD;;FA;;;WD;(@U.a=="))${hidden}(ZD;;FA;;;WD;(@U.b=="))`,
      `D:AI(XA;IO;FA;;;WD;(@U.a=="))${hidden}(XA;IO;FA;;;WD;(@U.b=="))`,
    ]) {
      expect(parse(attack).status, attack).not.toBe('restricted');
    }
  });

  it('refuses a descriptor with an unterminated quote', () => {
    expect(parse('D:(A;;FA;;;SY)"(A;;FR;;;WD)')).toMatchObject({ status: 'unknown' });
  });

  it('does not read IO across a CI/OI boundary', () => {
    // `flags.includes('IO')` matched the substring spanning CI and OI, so a grant that
    // applies to the object was discarded as inherit-only. Codes are read two at a time.
    expect(namesIn('D:AI(A;CIOI;FA;;;WD)(A;ID;FA;;;SY)')).toEqual(['Everyone']);
  });

  it('reports an unrecognised ACE flag code as unknown', () => {
    expect(parse('D:(A;ZZ;FR;;;WD)')).toMatchObject({ status: 'unknown', reason: 'unparsable' });
  });

  it.each(['CONTOSO\\alice', 'FOO"BAR', 'ssh mcp', 'S-1-5-21-x-1', 'WDX'])(
    'refuses %s, which is neither a SID nor an SDDL alias',
    (trustee) => {
      // Not merely non-empty: a merged group's field 5 was trusted on non-emptiness, and
      // the value is interpolated into a command the operator is told to paste.
      expect(parse(`D:(A;;FR;;;${trustee})`)).toMatchObject({ status: 'unknown' });
    },
  );

  it('leaves an alias it cannot resolve without a SID, rather than passing the alias off as one', () => {
    // AC is on C:\\Program Files, OW on redirected profiles; neither is in the table, and
    // a domain-relative alias is unresolvable on a host with no account domain. The
    // verdict must still refuse — only the printed SID is withheld.
    for (const alias of ['AC', 'OW', 'RD']) {
      const v = parseDacl(`D:(A;;0x1200a9;;;${alias})`, ALLOWED);
      expect(v.status).toBe('broad');
      expect(v.status === 'broad' && v.grants[0].sid).toBeNull();
    }
    // With no account domain, DU cannot be expanded either.
    const noDomain = parseDacl('D:(A;;FR;;;DU)', aclIdentity('S-1-5-18'));
    expect(noDomain.status === 'broad' && noDomain.grants[0].sid).toBeNull();
  });

  it('reads a lowercase alias as the principal it names', () => {
    expect(namesIn('D:(A;;FR;;;wd)')).toEqual(['Everyone']);
  });

  it('keeps a SACL marker inside a quoted condition out of the boundary cut', () => {
    expect(namesIn('D:AI(XA;;FR;;;WD;(@U.a=="S:"))S:(AU;SAFA;FA;;;WD)')).toEqual(['Everyone']);
  });

  it('reports unbalanced parentheses as unknown', () => {
    expect(parse('D:AI(A;;FR;;;WD')).toMatchObject({ status: 'unknown' });
    expect(parse('D:AI(A;;FR;;;WD))')).toMatchObject({ status: 'unknown' });
  });

  it('reports a malformed ACE as unknown rather than skipping it', () => {
    // Previously `D:(A;;FR)` returned [] and therefore passed.
    expect(parse('D:(A;;FR)')).toMatchObject({ status: 'unknown', reason: 'unparsable' });
  });

  it('reports an ACE with an empty trustee as unknown', () => {
    expect(parse('D:(A;;FR;;;)')).toMatchObject({ status: 'unknown' });
  });

  it('treats an unrecognised ACE type as granting', () => {
    // A type nobody has heard of must not be a way through. 'QQ' is not SDDL;
    // the point is the direction of the error.
    expect(namesIn('D:(QQ;;FR;;;WD)')).toEqual(['Everyone']);
  });
});

describe('parseDacl — the allowlist', () => {
  it('refuses a second local account, which no static denylist could name', () => {
    const other = 'S-1-5-21-185570930-3122470475-1457210486-1002';
    expect(namesIn(`D:(A;;FA;;;${other})`)).toEqual([other]);
  });

  it('refuses Domain Users, whose SID is domain-relative', () => {
    // The reason this is an allowlist: '…-513' cannot be enumerated ahead of
    // time, and on a domain-joined host it is every employee.
    expect(namesIn('D:(A;;FR;;;DU)')).toEqual(['Domain Users']);
    expect(namesIn(`D:(A;;FR;;;${DOMAIN}-513)`)).toEqual([`${DOMAIN}-513`]);
    // Alias and SID are the same principal, so a descriptor spelling it both
    // ways must name it once rather than twice.
    const both = parseDacl(`D:(A;;FR;;;DU)(A;;FA;;;${DOMAIN}-513)`, ALLOWED);
    expect(both.status === 'broad' && both.grants).toHaveLength(1);
  });

  it('refuses Power Users and Pre-Windows 2000 Compatible Access', () => {
    expect(namesIn('D:(A;;FR;;;PU)')).toEqual(['BUILTIN\\Power Users']);
    expect(namesIn('D:(A;;FR;;;RU)')).toEqual(['Pre-Windows 2000 Compatible Access']);
  });

  it('accepts the built-in Administrator account, which Administrators already covers', () => {
    // The GitHub windows-latest runner is this account, and SDDL writes its ACE
    // as `LA`. Comparing raw SIDs made the operator a stranger to their own file.
    expect(status('D:(A;;FA;;;LA)(A;ID;FA;;;SY)')).toBe('restricted');
    expect(status(`D:(A;;FA;;;${DOMAIN}-500)`)).toBe('restricted');
  });

  it('accepts SYSTEM and Administrators by alias and by SID alike', () => {
    expect(status('D:(A;;FA;;;SY)(A;;FA;;;BA)')).toBe('restricted');
    expect(status('D:(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-32-544)')).toBe('restricted');
  });

  it('accepts a user SID only when it is this account', () => {
    expect(status(`D:(A;;FA;;;${OWNER})`)).toBe('restricted');
    // The same descriptor judged for a different account: now a stranger's grant.
    expect(parseDacl(`D:(A;;FA;;;${OWNER})`, { allowed: new Set(['S-1-5-18']) }).status).toBe('broad');
  });

  it('names each refused principal once however many ACEs grant to it', () => {
    expect(namesIn('D:(A;;FR;;;WD)(A;OICI;FA;;;WD)')).toEqual(['Everyone']);
  });
});

describe('parseDacl — descriptor components', () => {
  it('reads the DACL when an owner and group precede it', () => {
    expect(status(`O:BAG:BAD:(A;ID;FA;;;SY)`)).toBe('restricted');
    expect(namesIn(`O:BAG:BAD:(A;;FR;;;WD)`)).toEqual(['Everyone']);
  });

  it('is unmoved by an owner or group that names a broad principal', () => {
    // Owner and group are not grants. Only ACEs are.
    expect(status('O:WDG:BUD:(A;ID;FA;;;SY)')).toBe('restricted');
  });

  it('ignores audit entries in the SACL', () => {
    // An audit ACE for Everyone asks for logging; it grants nothing. Reading
    // past the DACL would refuse a correctly-restricted file that is audited.
    expect(status('D:(A;ID;FA;;;SY)S:(AU;SAFA;FA;;;WD)')).toBe('restricted');
  });

  it('stops at the SACL even when it carries an allow-shaped entry', () => {
    // The case that actually exercises the DACL/SACL split: a type filter alone
    // would not save us here, because this entry looks like a grant.
    expect(status('D:(A;ID;FA;;;SY)S:(A;;FR;;;WD)')).toBe('restricted');
  });

  it('handles a DACL that is empty with a SACL following it', () => {
    expect(status('D:S:(AU;SAFA;FA;;;WD)')).toBe('restricted');
  });

  it('handles an empty DACL that carries control flags before the SACL', () => {
    // Without the bare-SACL arm the flags read as "AIS:", fail validation, and the
    // verdict becomes a refusal to start over a correctly-private audited file —
    // the false-positive direction.
    expect(status('D:AIS:(AU;SAFA;FA;;;WD)')).toBe('restricted');
    expect(status('D:PS:(AU;SAFA;FA;;;WD)')).toBe('restricted');
  });
});

describe('aclIdentity — the allowlist rule itself', () => {
  // Asserted rather than mirrored. While this was inline in inspectAcl — which
  // only runs on win32 — both suites built a replica of the set by hand, so adding
  // BUILTIN\\Users to the production allowlist, or dropping the RID-500 entry, left
  // every off-Windows test green and failed only on the advisory Windows job.
  it('allows exactly this account, SYSTEM, Administrators and the built-in Administrator', () => {
    const { allowed, accountDomain } = aclIdentity(OWNER);
    expect([...allowed].sort()).toEqual([
      'S-1-5-18',
      `${DOMAIN}-1001`,
      `${DOMAIN}-500`,
      'S-1-5-32-544',
    ].sort());
    expect(accountDomain).toBe(DOMAIN);
  });

  it('allows nobody broad', () => {
    const { allowed } = aclIdentity(OWNER);
    for (const stranger of ['S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', `${DOMAIN}-513`, `${DOMAIN}-1002`]) {
      expect(allowed.has(stranger)).toBe(false);
    }
  });

  it('derives no account domain for a SID that has none', () => {
    // An Entra-joined account is S-1-12-1-…, and a service SID is S-1-5-80-…;
    // neither has a classic account domain, so no RID-500 entry is added and the
    // domain-relative aliases stay unresolved — which fails closed.
    for (const sid of ['S-1-5-19', 'S-1-12-1-11-22-33-44', 'S-1-5-80-1-2-3-4-5']) {
      const { allowed, accountDomain } = aclIdentity(sid);
      expect(accountDomain).toBeUndefined();
      expect([...allowed].sort()).toEqual(['S-1-5-18', 'S-1-5-32-544', sid].sort());
    }
  });
});

describe('classifyReadFailure — what a failed descriptor read means', () => {
  // Extracted and tested directly because the branch that matters most is unreachable
  // from either platform's suite otherwise: off Windows the identity lookup fails first,
  // and on the Windows job only the read-refused arm is exercised. Coverage confirmed the
  // canonical-location check — the whole security argument for pinning System32 — was
  // executed by nothing, and deleting it survived every mutation.
  const enoent = (path: string) => Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT', path });
  const ICACLS = join('C:\\Windows\\System32', 'icacls.exe');

  it('calls icacls absent from the machine tool-missing, which loads anyway', () => {
    expect(classifyReadFailure(enoent(ICACLS), () => false)).toMatchObject({ failure: 'tool-missing' });
  });

  it('refuses when icacls is missing here but present canonically', () => {
    // A redirected %SystemRoot% must not reach the fail-open branch — that is what
    // pinning the path exists to prevent.
    const verdict = classifyReadFailure(enoent(ICACLS), () => true);
    expect(verdict.failure).toBe('read-refused');
    expect(verdict.detail).toMatch(/%SystemRoot% looks wrong/);
  });

  it('calls an expired budget timed-out, whichever subprocess it fired in', () => {
    const verdict = classifyReadFailure(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    expect(verdict.failure).toBe('timed-out');
    expect(verdict.detail).toMatch(/5000ms/);
  });

  it('refuses anything else, because it is about this path', () => {
    expect(classifyReadFailure(new Error('Access is denied'))).toMatchObject({
      failure: 'read-refused',
      detail: 'Access is denied',
    });
    // An ENOENT on the temp file rather than on the executable is not the tool missing.
    expect(classifyReadFailure(enoent('C:\\Temp\\acl.sddl'), () => false))
      .toMatchObject({ failure: 'read-refused' });
  });
});

describe('the rights field decides read from write', () => {
  // The classifier, not the decision above it. The decisions suite builds Grant objects
  // by hand, so `grantsWrite` could return a constant and nothing would fail — which is
  // the gap that let a modify grant be reported as merely readable in the first place.
  const grantsOf = (rights: string) => {
    const v = parseDacl(`D:(A;;${rights};;;WD)`, ALLOWED);
    return v.status === 'broad' ? v.grants[0] : null;
  };

  it('reads a real read-and-execute mask as read-only', () => {
    // 0x1200a9 is what a file under C:\ inherits for BUILTIN\Users. Measured.
    expect(grantsOf('0x1200a9')?.writes).toBe(false);
  });

  it('reads a real modify mask as write', () => {
    // 0x1301bf is what the same inheritance gives Authenticated Users. Measured.
    expect(grantsOf('0x1301bf')?.writes).toBe(true);
  });

  // The decimal spelling of the same two masks. `icacls /save` emits hex, so these were
  // uncovered — and deleting the decimal branch was measured to change the answer rather
  // than merely lose coverage: without it 1179817 falls through to the two-character code
  // loop, where an unrecognised chunk counts as write, so a read-only grant is reported as a
  // writer and the default posture refuses a config that is fine. That is the #138
  // false-positive direction, which the parser's own invariants call as costly as a bypass.
  it('reads a decimal read-and-execute mask as read-only', () => {
    expect(grantsOf('1179817')?.writes).toBe(false);   // 0x1200a9
  });

  it('reads a decimal modify mask as write', () => {
    expect(grantsOf('1245631')?.writes).toBe(true);    // 0x1301bf
  });

  it.each(['FA', 'FW', 'WD', 'WO', 'SD', 'GA', 'GW'])('treats %s as write', (rights) => {
    // WD here is WRITE_DAC, not Everyone: whoever can rewrite the DAC can grant
    // themselves anything, so it is a write however narrow the other bits look.
    expect(grantsOf(rights)?.writes).toBe(true);
  });

  it.each(['FR', 'FX', 'GR', 'FRFX'])('treats %s as read-only', (rights) => {
    expect(grantsOf(rights)?.writes).toBe(false);
  });

  it('treats a rights field it cannot classify as write', () => {
    // The safe direction: an unrecognised code refuses rather than reporting.
    for (const rights of ['ZZ', 'FRZZ', 'F', '']) {
      expect(grantsOf(rights)?.writes ?? true, rights).toBe(true);
    }
  });

  it('distinguishes the two principals of a real drive-root descriptor', () => {
    const v = parseDacl(DRIVE_ROOT, ALLOWED);
    expect(v.status).toBe('broad');
    if (v.status !== 'broad') return;
    const byName = Object.fromEntries(v.grants.map((g) => [g.name, g.writes]));
    // The whole basis of the default posture: one of these is a disclosure, the other is
    // an authorization bypass, and they arrive in the same descriptor.
    expect(byName['BUILTIN\\Users']).toBe(false);
    expect(byName['Authenticated Users']).toBe(true);
  });
});
