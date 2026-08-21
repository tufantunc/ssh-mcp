/**
 * The SDDL half of the Windows ACL check: descriptor text in, verdict out.
 *
 * Split from windows-acl.ts so the parser's platform independence is legible in the module
 * graph — this file imports nothing at all, and `sddl-import-boundary.test.ts` holds it to
 * that. What it owns is the grammar *and* the allowlist the grammar is judged against
 * (`ALWAYS_ALLOWED_SIDS`, the RID-500 rule in `aclIdentity`): the second is authorization
 * policy rather than syntax, but it is policy that needs no machine to evaluate, which is
 * the line this cut actually draws.
 *
 * An earlier version of this header claimed the split prevents a *silent* failure — that an
 * edit reaching for `icacls` inside `parseDacl` would leave CI green. That was wrong, and a
 * review round disproved it by doing it: such an edit fails about 69 parser tests loudly on
 * Linux, because none of those tests carries a platform guard. The real hazard is the step
 * after. Faced with 69 red tests on a change that "obviously only affects Windows", the
 * cheapest repair is `describe.runIf(win32)` — and *then* the 2000-run property suite stops
 * exercising the decision off Windows and the green is real. Asserting the boundary here
 * means the first step fails somewhere whose only sane repair is to undo the import.
 *
 * The type split follows the same line: the verdict vocabulary is what a descriptor says, so
 * `Grant`, `UnknownReason`, `AclVerdict` and `AclIdentity` live here. `AclFinding` and
 * `AclOptions` are what we tell the operator and what the operator asked for, so they stay
 * with the platform half.
 *
 * `PRINCIPAL_NAMES`/`nameFor` are here against the plan that queued this split, which put
 * them on the message side. They cannot go there while `parseDacl` populates `Grant.name`:
 * honouring it would mean passing the parser a name resolver, a signature change the same
 * plan ruled out by asking for no behaviour change. The table is keyed by SDDL alias and
 * SID, which is this file's vocabulary anyway.
 */

/**
 * The principals a private config may name, by SID.
 *
 * An allowlist, because the POSIX branch is one — it refuses any bit outside
 * 0700 — and the refusal message promises "the owning user only". The first
 * version of this file was a denylist of six well-known groups, which let
 * through `Domain Users` (whose SID is domain-relative, so no static list can
 * name it), `Power Users`, and any second local account or custom group. On a
 * domain-joined host that is every employee, reported as owner-only.
 *
 * SYSTEM and Administrators stay allowed: they are what a file under %APPDATA%
 * actually carries (measured), and an administrator can take ownership
 * regardless of what any DACL says, so refusing them would buy nothing.
 */
const ALWAYS_ALLOWED_SIDS: ReadonlySet<string> = new Set([
  'S-1-5-18',       // NT AUTHORITY\SYSTEM
  'S-1-5-32-544',   // BUILTIN\Administrators
]);

/**
 * SDDL alias to SID.
 *
 * Three entries carry the correctness load — `SY`, `BA`, and `LA` via
 * DOMAIN_RELATIVE_RIDS — because those are the only principals that can appear in the
 * allowlist, so those are the only comparisons where two spellings of one principal
 * have to come out equal. That mattered: on a GitHub `windows-latest` runner the user is
 * the built-in Administrator, whose own ACE is written `LA`, and comparing raw SIDs made
 * the operator a stranger to their own config — 60 tests failed with "access is granted
 * to LA".
 *
 * The other fourteen are verdict-neutral: an unresolved alias falls through unchanged and
 * is refused either way. They exist so a refusal reports one entry per principal and
 * prints a SID a remediation can name — which means the length of this list is not a
 * security property.
 */
const ALIAS_SIDS: ReadonlyMap<string, string> = new Map([
  ['SY', 'S-1-5-18'],
  ['BA', 'S-1-5-32-544'],
  ['WD', 'S-1-1-0'],
  ['BU', 'S-1-5-32-545'],
  ['AU', 'S-1-5-11'],
  ['IU', 'S-1-5-4'],
  ['BG', 'S-1-5-32-546'],
  ['AN', 'S-1-5-7'],
  ['PU', 'S-1-5-32-547'],
  ['NU', 'S-1-5-2'],
  ['SU', 'S-1-5-6'],
  ['RU', 'S-1-5-32-554'],
  ['WR', 'S-1-5-33'],
  ['CO', 'S-1-3-0'],
  ['LS', 'S-1-5-19'],
  ['NS', 'S-1-5-20'],
  ['RC', 'S-1-5-12'],
]);

/**
 * Aliases whose SID is relative to an account domain, expanded against the
 * domain of the account we run as. `LA` is the reason this exists; the group ones
 * are here so a descriptor that spells one principal both ways is reported once
 * rather than twice — the display name still comes from the raw trustee, so `DU`
 * reads as "Domain Users" while the SID spelling reads as the SID.
 */
const DOMAIN_RELATIVE_RIDS: ReadonlyMap<string, number> = new Map([
  ['LA', 500],  // built-in Administrator
  ['LG', 501],  // built-in Guest
  ['DA', 512],  // Domain Admins
  ['DU', 513],  // Domain Users
  ['DG', 514],  // Domain Guests
  ['DC', 515],  // Domain Computers
  ['DD', 516],  // Domain Controllers
  ['CA', 517],  // Cert Publishers
  // These two live only in the forest root domain, so expanding them against *our*
  // account domain names a SID that does not exist in a child domain. Harmless for
  // the verdict — a SID resolving to nothing is not in the allowlist, so the ACE is
  // refused either way — but the remediation would print a /remove:g icacls cannot
  // map, which is the defect Grant.sid exists to prevent. Kept so a refusal names
  // the principal; treat the SID as best effort.
  ['SA', 518],  // Schema Admins (forest root)
  ['EA', 519],  // Enterprise Admins (forest root)
  ['PA', 520],  // Group Policy Creator Owners
]);

/**
 * Display names for principals we expect to have to name in a refusal. Only
 * cosmetic — an unrecognised trustee is reported by its SID or alias, and is
 * refused either way, so nothing security-relevant depends on this table being
 * complete.
 */
const PRINCIPAL_NAMES: ReadonlyMap<string, string> = new Map([
  ['WD', 'Everyone'], ['S-1-1-0', 'Everyone'],
  ['BU', 'BUILTIN\\Users'], ['S-1-5-32-545', 'BUILTIN\\Users'],
  ['AU', 'Authenticated Users'], ['S-1-5-11', 'Authenticated Users'],
  ['IU', 'Interactive'], ['S-1-5-4', 'Interactive'],
  ['BG', 'BUILTIN\\Guests'], ['S-1-5-32-546', 'BUILTIN\\Guests'],
  ['AN', 'Anonymous'], ['S-1-5-7', 'Anonymous'],
  ['PU', 'BUILTIN\\Power Users'], ['S-1-5-32-547', 'BUILTIN\\Power Users'],
  ['DU', 'Domain Users'],
  ['NU', 'NETWORK'], ['S-1-5-2', 'NETWORK'],
  ['SU', 'SERVICE'], ['S-1-5-6', 'SERVICE'],
  ['RU', 'Pre-Windows 2000 Compatible Access'], ['S-1-5-32-554', 'Pre-Windows 2000 Compatible Access'],
  ['WR', 'WRITE RESTRICTED'], ['S-1-5-33', 'WRITE RESTRICTED'],
  ['CO', 'CREATOR OWNER'], ['S-1-3-0', 'CREATOR OWNER'],
]);

/**
 * ACE types that grant nothing to their trustee: denials, and the audit, alarm
 * and non-ACL entry types.
 *
 * A denylist here, and an allowlist for principals — each in the direction that
 * fails safe. The first version tested `type === 'A' || type === 'OA'`, which
 * silently skipped `XA` and `ZA`: conditional allow ACEs, exactly what Dynamic
 * Access Control puts on managed files. An ACE type this does not recognise is
 * now treated as granting, so a future addition to SDDL cannot open a hole by
 * being unfamiliar.
 */
const NON_GRANTING_ACE_TYPES: ReadonlySet<string> = new Set([
  'D', 'OD', 'XD',                    // access denied
  'AU', 'AL', 'OU', 'OL', 'XU',       // audit and alarm
  'ML', 'RA', 'SP', 'TL', 'FL',       // label, attribute, policy, trust, filter
]);

/**
 * Two different flag vocabularies, which is easy to conflate — the first draft
 * did, and rejected every real descriptor as unparseable because `D:AI(...)`
 * carries a *control* flag where an ACE flag was expected.
 *
 * DACL control flags qualify the ACL as a whole: `P` protected (inheritance
 * blocked), `AI` auto-inherited, `AR` auto-inherit-required. `P` is one
 * character, so these cannot be read in fixed-width chunks.
 */
const DACL_CONTROL_FLAGS = /^(?:P|AI|AR)*$/;

/** ACE flags, which are all two characters. */
const ACE_FLAG_CODES: ReadonlySet<string> = new Set([
  'CI', 'OI', 'IO', 'NP', 'ID', 'SA', 'FA', 'TP', 'CR',
]);

/**
 * Rights that let a trustee change the object, as SDDL letter codes. `WD` here is
 * WRITE_DAC, not Everyone — the rights field and the trustee field have separate
 * vocabularies that happen to share spellings.
 */
const WRITE_RIGHT_CODES: ReadonlySet<string> = new Set([
  'FA', 'FW', 'KA', 'KW', 'GA', 'GW', 'SD', 'WD', 'WO', 'CC', 'DC', 'SW', 'WP', 'DT',
]);

/** Rights that only let a trustee look. Anything unrecognised counts as write. */
const READ_RIGHT_CODES: ReadonlySet<string> = new Set([
  'FR', 'FX', 'GR', 'GX', 'KR', 'RC', 'RP', 'LC', 'LO',
]);

/**
 * FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, DELETE,
 * WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL.
 */
const WRITE_MASK = 0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000;

/**
 * Whether a rights field lets its trustee *change* the object rather than only read it.
 *
 * This distinction is the basis of the default posture, and the field used to be parsed
 * and discarded. Read exposure on Windows is genuinely muddier than under POSIX — a
 * shared volume grants `BUILTIN\Users` read, and refusing over that stranded the reporter
 * of #138 — but write exposure is not muddy at all: "an ACE grants a non-owner
 * FILE_WRITE_DATA or WRITE_DAC" is exactly as unambiguous as `0o022`, and a config another
 * account can rewrite decides which hosts, roles and approval policy this server honours.
 * That is an authorization bypass, not a disclosure, and it was being reported as one.
 *
 * Measured from real inheritance: `0x1200a9` is read-and-execute, `0x1301bf` is modify.
 * Anything this cannot classify counts as write, because refusing is the safe direction.
 */
function grantsWrite(rights: string): boolean {
  const field = rights.trim().toUpperCase();
  if (field === '') return true;
  if (/^0X[0-9A-F]+$/.test(field)) return (Number.parseInt(field.slice(2), 16) & WRITE_MASK) !== 0;
  if (/^[0-9]+$/.test(field)) return (Number.parseInt(field, 10) & WRITE_MASK) !== 0;
  if (field.length % 2 !== 0) return true;
  for (let i = 0; i < field.length; i += 2) {
    const code = field.slice(i, i + 2);
    if (WRITE_RIGHT_CODES.has(code)) return true;
    if (!READ_RIGHT_CODES.has(code)) return true;
  }
  return false;
}

export interface Grant {
  /** How the operator will see it in `icacls` output; falls back to the trustee. */
  name: string;
  /** The trustee exactly as the descriptor spelled it — SID or SDDL alias. */
  trustee: string;
  /**
   * The resolved SID, which is what a remediation must name.
   *
   * `*` introduces a SID for `icacls /remove:g`. That SDDL *aliases* work there at all
   * is undocumented — the SID Strings page says the conversion APIs do not support SDDL
   * constants — and it is not uniform. Measured on a workgroup host (a `windows-latest`
   * runner): `*WD` is accepted, `*DU` exits 1337, ERROR_NONE_MAPPED, having processed 0
   * files. The split is not about obscurity: `WD` is a fixed SID while `DU` is
   * domain-relative and needs an account domain to expand against, which that host does
   * not have. So printing the alias makes the command's success depend on the operator's
   * domain membership.
   *
   * The SID is already computed to make the decision, so using it means the message and
   * the verdict cannot disagree, on any host.
   */
  sid: string | null;
  /** Whether this grant lets the trustee change the file, not merely read it. */
  writes: boolean;
}

/** Why the ACL could not be determined. Decides whether we refuse or continue. */
export type UnknownReason =
  /** icacls is not on this machine. Nothing about the file is suspicious. */
  | 'tool-missing'
  /**
   * The check ran out of time. Also a statement about the machine rather than the
   * file — a cold host or an on-access scanner can outlast any budget — so it is
   * treated like a missing tool rather than as grounds to refuse.
   */
  | 'timed-out'
  /** The identity to compare against could not be established. */
  | 'identity-unknown'
  /** icacls ran and would not or could not describe this path. */
  | 'read-refused'
  /** A descriptor came back that this parser cannot account for. */
  | 'unparsable';

export type AclVerdict =
  /** Nobody but the owner, SYSTEM and Administrators. */
  | { status: 'restricted' }
  /** Named trustees beyond the owner hold access. */
  | { status: 'broad'; grants: Grant[] }
  /** A NULL DACL: full control for every principal, expressed by having no ACL. */
  | { status: 'no-dacl' }
  /** No answer. The caller decides what an absent answer means. */
  | { status: 'unknown'; reason: UnknownReason; detail: string };

/**
 * Whether a group's parentheses balance when quoting is ignored.
 *
 * The quote handling closed one merge and opened another: two ACEs whose conditional
 * literals each carry a single unmatched `"` put the scanner into `inQuotes` across the
 * intervening `)(`, collapsing every ACE between them into one group whose type, flags
 * and trustee the attacker chooses. Five shapes were executed against the previous
 * version and all five came back `restricted` while hiding real Everyone, Users and
 * Authenticated Users grants.
 *
 * Where the quote-aware and quote-blind scans disagree, the quotes were load-bearing
 * across an ACE boundary and the descriptor is not something to draw a conclusion from.
 */
function quoteBlindBalanced(group: string): boolean {
  let depth = 0;
  for (const ch of group) {
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth < 0) return false;
    }
  }
  return depth === 0;
}

/**
 * ACE groups from a DACL body, respecting nesting *and quoting*.
 *
 * The quote handling is not decoration. A conditional ACE (`XA`/`ZA`) carries an
 * expression whose string literals may contain parentheses, and SDDL gives them
 * no escape. A quote-blind scan can therefore be fed two conditional ACEs whose
 * literals hold `"("` and `")"`, which merges every ACE between them into a
 * single group — and field 5 of the merged blob is the *first* ACE's trustee,
 * which the attacker sets to the owner. Verified before the fix: a descriptor
 * bracketing the real `BUILTIN\Users` and `Authenticated Users` grants that way
 * came back `restricted`.
 *
 * That is the previous version's truncating regex returning as a merging scan,
 * and it fails in the same unsafe direction, so the counting has to know about
 * quotes. SDDL string literals have no `"` escape, which makes a plain toggle
 * exact rather than approximate.
 */
function aceGroups(body: string): string[] | null {
  const groups: string[] = [];
  let depth = 0;
  let start = -1;
  let inQuotes = false;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (inQuotes) continue;
    if (ch === '(') {
      if (depth === 0) start = i + 1;
      depth++;
    } else if (ch === ')') {
      depth--;
      // A stray ')' means this is not a descriptor we understand.
      if (depth < 0) return null;
      if (depth === 0) {
        const group = body.slice(start, i);
        if (!quoteBlindBalanced(group)) return null;
        groups.push(group);
      }
    }
  }
  // An unterminated quote means the same thing as unbalanced parentheses: we do
  // not know where this ACE ends, so we do not know what it grants.
  return depth === 0 && !inQuotes ? groups : null;
}

/** Whether a DACL's own flag string is one we recognise. */
function daclFlagsAreValid(flags: string): boolean {
  return flags === 'NO_ACCESS_CONTROL' || DACL_CONTROL_FLAGS.test(flags);
}

/**
 * An ACE flag string as the set of two-character codes it is made of, or null if
 * it is not made of them.
 *
 * Returning the set rather than a boolean is what makes the inherit-only test
 * safe. `flags.includes('IO')` matched across a code boundary: `CIOI` — accepted
 * by this order-agnostic validator — contains the substring `IO` spanning CI and
 * OI, so a grant that does apply to the object was discarded as inherit-only.
 * Measured before the fix: `D:(A;CIOI;FA;;;WD)` came back restricted while
 * `D:(A;OICI;FA;;;WD)` correctly came back broad.
 */
function aceFlagCodes(flags: string): Set<string> | null {
  if (flags.length % 2 !== 0) return null;
  const codes = new Set<string>();
  for (let i = 0; i < flags.length; i += 2) {
    const code = flags.slice(i, i + 2);
    if (!ACE_FLAG_CODES.has(code)) return null;
    codes.add(code);
  }
  return codes;
}

/**
 * Trustees this parser is willing to act on: a SID, or an SDDL alias.
 *
 * Anything else is `unparsable` rather than "a principal named oddly". Two
 * reasons. It stops a trustee field from being trusted purely for being
 * non-empty, which is what the merged-group attack above relied on; and the
 * value is interpolated into an `icacls` command the operator is told to paste,
 * where `FOO"BAR` produced an unbalanced-quote command line.
 */
const TRUSTEE = /^(?:S-1-[0-9]+(?:-[0-9]+)*|[A-Z]{2})$/;

function nameFor(trustee: string): string {
  return PRINCIPAL_NAMES.get(trustee) ?? trustee;
}

/** The account a descriptor is judged for. */
export interface AclIdentity {
  /** SIDs that may hold access. */
  allowed: ReadonlySet<string>;
  /**
   * The account-domain portion of our own SID — everything before the final RID.
   * Lets `LA`, `DU` and friends resolve to real SIDs rather than staying opaque.
   */
  accountDomain?: string;
}

/** The SID a trustee names, resolving both kinds of alias. */
function resolveTrustee(trustee: string, accountDomain?: string): string | null {
  const fixed = ALIAS_SIDS.get(trustee);
  if (fixed) return fixed;
  const rid = DOMAIN_RELATIVE_RIDS.get(trustee);
  if (rid !== undefined && accountDomain) return `${accountDomain}-${rid}`;
  // A trustee that already *is* a SID resolves to itself; only an alias this cannot
  // expand comes back null.
  if (trustee.startsWith('S-1-')) return trustee;
  // Null, not the trustee. Returning the raw alias let it travel on as `Grant.sid` and
  // be printed as `/remove:g *OW` — and `*` declares a numeric SID to icacls, so that
  // command removes nothing. Reproduced for `AC` (on `C:\Program Files`), `OW` (on
  // redirected profiles), `RD`, `ED`, `PS`, `LW`, and for every domain-relative alias on
  // a host with no derivable account domain: a service identity or an Entra-joined
  // account. The operator restarted into the identical refusal, and
  // --allowUncheckedConfigAcl deliberately does not cover a `broad` verdict, so the
  // message was a dead end. Fifth instance of this defect in this change.
  return null;
}

/**
 * What a security descriptor's DACL grants, judged against the SIDs allowed to
 * hold access.
 *
 * Returns `unknown` for anything it cannot fully account for. That is the whole
 * point of the rewrite: the first version had one output — an empty list — for
 * "restricted to the owner" and for "I found nothing I recognise", which are
 * opposite security conclusions. It reported `D:NO_ACCESS_CONTROL` (full
 * control for everyone), a descriptor with no `D:` at all, a conditional ACE,
 * and the string `D:\` as safe.
 *
 * Exported so the parsing runs on every CI platform rather than only on the
 * Windows job. The fixtures are real `icacls /save` output.
 */
export function parseDacl(descriptor: string, identity: AclIdentity): AclVerdict {
  const { allowed: allowedSids, accountDomain } = identity;
  const unknown = (detail: string): AclVerdict => ({ status: 'unknown', reason: 'unparsable', detail });

  const marker = descriptor.indexOf('D:');
  if (marker === -1) return unknown('no DACL component');

  let body = descriptor.slice(marker + 2);
  // A SACL may follow. Cut at the boundary, which is the ')' closing the last
  // DACL ACE — or immediately, for a DACL with no ACEs at all.
  const saclAfterAce = body.search(/\)S:/);
  if (saclAfterAce !== -1) body = body.slice(0, saclAfterAce + 1);
  else if (body.startsWith('S:')) body = '';
  else {
    const bareSacl = body.indexOf('S:');
    if (bareSacl !== -1 && !body.slice(0, bareSacl).includes('(')) body = body.slice(0, bareSacl);
  }

  const firstAce = body.indexOf('(');
  const flags = (firstAce === -1 ? body : body.slice(0, firstAce)).trim();
  if (!daclFlagsAreValid(flags)) return unknown(`unrecognised DACL flags ${JSON.stringify(flags)}`);

  // A NULL DACL grants full control to every principal. It carries no ACEs, so
  // an ACE scan finds nothing and would call it restricted.
  if (flags === 'NO_ACCESS_CONTROL') return { status: 'no-dacl' };

  const groups = aceGroups(firstAce === -1 ? '' : body.slice(firstAce));
  if (groups === null) return unknown('unbalanced parentheses in the DACL');

  // An empty DACL is not a missing one: it denies everyone, which is private.
  if (groups.length === 0) return { status: 'restricted' };

  const grants = new Map<string, Grant>();
  for (const ace of groups) {
    const fields = ace.split(';');
    if (fields.length < 6) return unknown(`ACE with ${fields.length} fields: ${JSON.stringify(ace)}`);

    const type = fields[0].trim().toUpperCase();
    if (NON_GRANTING_ACE_TYPES.has(type)) continue;

    const aceFlags = fields[1].trim().toUpperCase();
    const flagCodes = aceFlagCodes(aceFlags);
    if (flagCodes === null) {
      return unknown(`unrecognised ACE flags ${JSON.stringify(aceFlags)}`);
    }
    // Inherit-only grants nothing on this object; it applies to children, whose
    // own descriptors are read separately.
    if (flagCodes.has('IO')) continue;

    const trustee = fields[5].trim().toUpperCase();
    if (!TRUSTEE.test(trustee)) {
      return unknown(`ACE with an unrecognised trustee ${JSON.stringify(fields[5])}`);
    }
    const sid = resolveTrustee(trustee, accountDomain);
    if (sid !== null && allowedSids.has(sid)) continue;

    grants.set(sid ?? trustee, {
      name: nameFor(trustee), trustee, sid, writes: grantsWrite(fields[2]),
    });
  }

  return grants.size === 0 ? { status: 'restricted' } : { status: 'broad', grants: [...grants.values()] };
}

/**
 * Which SIDs a descriptor may name, given the account we run as.
 *
 * Separate from `inspectAcl` so the rule is asserted rather than mirrored. While
 * it was inline, both test suites built a replica of this set by hand — so adding
 * `BUILTIN\Users` to the allowlist, or dropping the RID-500 entry, left every
 * off-Windows test green and failed only on the advisory Windows job. Two
 * mutations survived the required check that way.
 */
export function aclIdentity(sid: string): AclIdentity {
  // Classic account domains only: `S-1-5-21-A-B-C-1001` -> `S-1-5-21-A-B-C`. An
  // Entra-joined account is `S-1-12-1-…` and has no account domain, so the
  // domain-relative aliases stay unresolved there and fail closed.
  const accountDomain = /^(S-1-5-21-[0-9-]+)-\d+$/.exec(sid)?.[1];
  const allowed = new Set([...ALWAYS_ALLOWED_SIDS, sid]);
  // RID 500 is the built-in Administrator. In a default configuration it belongs
  // to the Administrators group, which is already allowed, so naming the account
  // directly grants nobody new access — while refusing it is a false positive,
  // and here that means refusing, or at best warning, about a config that is fine. (On a
  // domain-joined host the account domain is the domain, so this authorises
  // DOMAIN\Administrator, whose local-admin status comes from Domain Admins
  // nesting — a GPO default rather than a law.)
  if (accountDomain) allowed.add(`${accountDomain}-500`);
  return { allowed, accountDomain };
}
