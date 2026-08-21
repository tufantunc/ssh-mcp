import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { parseDacl, aclIdentity } from '../../src/config/sddl.js';

/**
 * `parseDacl` is the security decision for the whole Windows config path, and
 * before this it was covered by a handful of hand-picked descriptors. Hand-picked
 * inputs are exactly what let its first version through: every string I thought
 * to write happened to have ACEs in it, so the cases that returned "safe" for a
 * NULL DACL, a conditional ACE or a drive path were never written down.
 *
 * The invariant is the one the check exists for, and it is stated in both
 * directions — a generated descriptor granting to a stranger must never come
 * back `restricted`, and one granting only to allowed principals must never come
 * back `broad`. Assembling descriptors from parts rather than generating free
 * text is deliberate: random strings would nearly all land in `unknown`, which
 * proves nothing about either direction.
 */

const OWNER = 'S-1-5-21-11-22-33-1001';
const DOMAIN = 'S-1-5-21-11-22-33';
// The production rule, not a replica of it — `aclIdentity(OWNER)` yields exactly the set
// this used to spell out by hand. sddl.ts records why that matters: while both suites held
// a replica, adding `BUILTIN\Users` to the allowlist or dropping the RID-500 entry left
// every off-Windows test green, and two mutations survived the required check that way. The
// sibling suite was fixed then; this one still had the copy, and measured, it was blind to
// both mutations. Free to fix now that `aclIdentity` lives in the module this file imports.
const ALLOWED = aclIdentity(OWNER);

const allowedTrustee = fc.constantFrom('SY', 'BA', 'S-1-5-18', 'S-1-5-32-544', OWNER);
const strangerTrustee = fc.constantFrom(
  'WD', 'BU', 'AU', 'IU', 'BG', 'AN', 'PU', 'DU', 'RU', 'NU', 'SU',
  'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-21-11-22-33-513',
  'S-1-5-21-11-22-33-1002', 'S-1-5-21-99-88-77-1001',
);

/** Aliases and SIDs that resolve to the same principal must dedupe to one. */
const equivalentSpellings: [string, string][] = [
  ['WD', 'S-1-1-0'],
  ['BU', 'S-1-5-32-545'],
  ['AU', 'S-1-5-11'],
  ['DU', `${DOMAIN}-513`],
];

const grantingType = fc.constantFrom('A', 'OA', 'XA', 'ZA');
const nonGrantingType = fc.constantFrom('D', 'OD', 'XD', 'AU', 'AL', 'ML', 'RA', 'SP');
/** Flag strings that leave the ACE applying to this object. */
// CIOI is the one that matters: `includes('IO')` matched across the CI|OI boundary.
const applyingFlags = fc.constantFrom('', 'ID', 'OICI', 'CIOI', 'OICIID', 'CI', 'NP', 'CIID');
const rights = fc.constantFrom('FA', 'FR', 'FX', '0x1200a9', '0x1301bf', 'GRGX');
const daclFlags = fc.constantFrom('', 'AI', 'P', 'PAI', 'AR');

interface Ace {
  type: string;
  flags: string;
  rights: string;
  trustee: string;
}

const ace = (type: fc.Arbitrary<string>, trustee: fc.Arbitrary<string>): fc.Arbitrary<Ace> =>
  fc.record({ type, flags: applyingFlags, rights, trustee });

const render = (flags: string, aces: Ace[]): string =>
  `D:${flags}` + aces.map((a) => `(${a.type};${a.flags};${a.rights};;;${a.trustee})`).join('');

describe('parseDacl invariants', () => {
  it('never calls a descriptor restricted when a stranger is granted access', () => {
    fc.assert(
      fc.property(
        daclFlags,
        fc.array(ace(grantingType, allowedTrustee), { maxLength: 4 }),
        ace(grantingType, strangerTrustee),
        fc.array(ace(nonGrantingType, strangerTrustee), { maxLength: 3 }),
        (flags, allowedAces, strangerAce, denials) => {
          // The stranger's ACE is placed among allowed grants and denials so its
          // position, and the noise around it, cannot be what makes it visible.
          const verdict = parseDacl(render(flags, [...allowedAces, strangerAce, ...denials]), ALLOWED);
          expect(verdict.status).toBe('broad');
          if (verdict.status === 'broad') {
            expect(verdict.grants.map((g) => g.trustee)).toContain(strangerAce.trustee.toUpperCase());
          }
        },
      ),
      { numRuns: 2000 },
    );
  });

  it('never calls a descriptor broad when only allowed principals are granted', () => {
    fc.assert(
      fc.property(
        daclFlags,
        fc.array(ace(grantingType, allowedTrustee), { minLength: 1, maxLength: 6 }),
        fc.array(ace(nonGrantingType, strangerTrustee), { maxLength: 4 }),
        (flags, allowedAces, denials) => {
          // A false positive here refuses to start a server whose config is
          // fine — the failure mode #138 was, so it is worth as much as the
          // bypass direction.
          expect(parseDacl(render(flags, [...allowedAces, ...denials]), ALLOWED).status).toBe('restricted');
        },
      ),
      { numRuns: 2000 },
    );
  });

  it('treats an alias and its SID as the same principal', () => {
    // SDDL prefers an alias when one exists, so both spellings turn up in real
    // descriptors — including for the account we run as, which is how `LA` made
    // the operator a stranger to their own config.
    for (const [alias, sid] of equivalentSpellings) {
      const both = parseDacl(`D:AI(A;;FR;;;${alias})(A;;FA;;;${sid})`, ALLOWED);
      expect(both.status).toBe('broad');
      if (both.status === 'broad') expect(both.grants).toHaveLength(1);
    }
  });

  it('accepts the built-in Administrator, however spelled', () => {
    // RID 500 is in the Administrators group by construction, and that group is
    // allowed, so naming the account directly grants nobody new access.
    expect(parseDacl('D:AI(A;;FA;;;LA)(A;ID;FA;;;SY)', ALLOWED).status).toBe('restricted');
    expect(parseDacl(`D:AI(A;;FA;;;${DOMAIN}-500)`, ALLOWED).status).toBe('restricted');
  });

  it('ignores inherit-only grants however they are spelled', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('OICIIO', 'IO', 'CIIO', 'OICIIOID'),
        strangerTrustee,
        rights,
        (flags, trustee, r) => {
          // Inherit-only entries grant nothing on the object carrying them; the
          // child's own descriptor is read separately.
          expect(parseDacl(`D:AI(A;${flags};${r};;;${trustee})(A;ID;FA;;;SY)`, ALLOWED).status)
            .toBe('restricted');
        },
      ),
      { numRuns: 500 },
    );
  });

  it('never returns restricted for a descriptor it cannot fully read', () => {
    // Truncating a well-formed descriptor at an arbitrary point must produce
    // `unknown` or a refusal — never "safe". This is the class the first version
    // failed: any input it did not understand became an empty grant list.
    //
    // The assertion is unconditional. It used to escape into `expect(truncated)
    // .toMatch(/^D:(?:P|AI|AR)*$/)` whenever the verdict was restricted, which
    // instrumenting showed fired on 101 of 2000 runs against five distinct strings
    // — so 1899 runs asserted nothing at all. The five honest cases are now an
    // explicit table below, which is stronger and instant.
    fc.assert(
      fc.property(
        fc.array(ace(grantingType, strangerTrustee), { minLength: 1, maxLength: 4 }),
        daclFlags,
        fc.nat(),
        (aces, flags, cut) => {
          const full = render(flags, aces);
          const prefixLength = 1 + (cut % (full.length - 1));
          const truncated = full.slice(0, prefixLength);
          const verdict = parseDacl(truncated, ALLOWED);

          // A prefix that stops before the first ACE is a syntactically complete
          // empty DACL, which denies everyone; the table below covers those.
          if (/^D:(?:P|AI|AR)*$/.test(truncated)) return;

          expect(verdict.status).not.toBe('restricted');

          // The other half of "cannot fully read": if it does report grants, every
          // one of them has to come from text that actually survived the cut. A
          // parser carrying state across the boundary would name a principal the
          // prefix never mentions.
          if (verdict.status === 'broad') {
            for (const g of verdict.grants) {
              expect(truncated).toContain(g.trustee);
            }
          }
        },
      ),
      { numRuns: 2000 },
    );
  });

  it.each(['D:', 'D:P', 'D:AI', 'D:AR', 'D:PAI'])(
    'treats %s — a complete but empty DACL — as private',
    (descriptor) => {
      // Denies everyone, so it is private. These are the only prefixes for which
      // `restricted` is the honest answer, which is why the property above returns
      // early on them rather than accepting them wherever they happen to appear.
      expect(parseDacl(descriptor, ALLOWED).status).toBe('restricted');
    },
  );
});
