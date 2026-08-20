import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync, realpathSync } from 'fs';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { tmpdir, userInfo } from 'os';
import { join, resolve, relative, isAbsolute, parse as parsePath } from 'path';
import { OperatorError } from '../errors.js';

const run = promisify(execFile);

const WINDOWS_ROOT = /^[A-Za-z]:\\Windows$/;
const CANONICAL_SYSTEM32 = 'C:\\Windows\\System32';

/**
 * Absolute paths, not bare names — and not paths the caller gets to choose.
 *
 * These subprocesses decide whether a config file is private, so who answers must
 * not be up to the ambient environment. Windows resolves a bare name through the
 * application directory, the working directory and then PATH, and the working
 * directory belongs to whichever MCP client spawned us; a planted `icacls.exe`
 * would run as the operator *and* dictate the verdict, since all it has to emit
 * is one line reading `D:(A;ID;FA;;;SY)`.
 *
 * The first version of this comment claimed the environment could not influence
 * the verdict and then read `%SystemRoot%`, which the same parent sets — the hole
 * moved one variable over rather than closing. So the value is accepted only in
 * the shape a real Windows root has, and `readDescriptor` will not treat "icacls
 * is missing here" as "icacls is missing on this machine" without checking the
 * canonical location, because that verdict is the one that loads anyway.
 *
 * One thing this does *not* close: `os.tmpdir()` reads `TEMP`/`TMP` from the same
 * environment, and that is where the descriptor is written and read back. A parent that
 * points `TEMP` somewhere it watches has the window between `icacls` writing `acl.sddl`
 * and our `readFile` to substitute one line reading `D:(A;ID;FA;;;SY)`. Taking the temp
 * root from another environment variable would move the problem rather than solve it,
 * and a parent with that much control already chooses our argv — it could simply pass
 * `--allowUncheckedConfigAcl`. A known limit of the threat model, not something handled.
 */
function systemDir(): string {
  // Canonical first. Shape is not integrity: the previous version accepted any
  // `%SystemRoot%` matching /^[A-Za-z]:\\Windows$/, and `Z:\Windows` on removable
  // media, a mapped drive, a `subst` alias or a mounted VHD satisfies that — so both
  // subprocesses became the attacker's, and a world-readable config was reported
  // `restricted` with no warning. Reproduced before this change. On any normal host
  // C:\Windows\System32\icacls.exe exists, so the environment cannot redirect at all.
  if (existsSync(join(CANONICAL_SYSTEM32, 'icacls.exe'))) return CANONICAL_SYSTEM32;
  const fromEnv = process.env.SystemRoot;
  return fromEnv && WINDOWS_ROOT.test(fromEnv) ? join(fromEnv, 'System32') : CANONICAL_SYSTEM32;
}

const SYSTEM32 = systemDir();
const ICACLS = join(SYSTEM32, 'icacls.exe');
const WHOAMI = join(SYSTEM32, 'whoami.exe');

/**
 * What these children inherit: nothing. They read no configuration of ours, and
 * `Path` is System32 alone so nothing they might start can be redirected either.
 */
const CHILD_ENV: NodeJS.ProcessEnv = { SystemRoot: join(SYSTEM32, '..'), Path: SYSTEM32 };

/**
 * One budget for the whole check — and for the check, not merely its children.
 *
 * Per-child was the first shape, which made the ceiling the sum of however many
 * children the check happens to spawn — three today, so 4.5s of dead air before
 * the server reports ready, against a measured happy path of 60-150ms.
 *
 * The first version passed the signal to `execFile` only, which left `mkdtemp`,
 * `readFile` and `rm` — six operations across the two subjects — outside the bound
 * the comment claimed. A `%TEMP%` redirected to a stalled share made startup
 * latency unbounded rather than five seconds. The deadline is now raced against the
 * whole per-subject check, so the number means what it says.
 *
 * Generous, because running out is not evidence about the file: five seconds across
 * three process creations plus two temp-directory round trips, so that on-access
 * virus scanning or a loaded host does not turn a private config into a finding.
 * Expiry gets its own verdict for the same reason — see `timed-out`.
 */
const ACL_TIMEOUT_MS = 5_000;

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
 * A finding the caller is told about, whether or not it also refuses.
 *
 * Discriminated because the two kinds are not the same statement and a reader of a log has
 * to tell them apart: "this ACL lets Authenticated Users modify your config" and "I could
 * not read this ACL" are different facts, and the first is the more actionable. The earlier
 * shape could only express the second, so the stronger finding went straight to
 * `console.error` and no caller could reach it — which is what `onFinding`'s own doc says
 * must not happen.
 */
export type AclFinding =
  | {
      path: string; kind: 'file' | 'directory';
      status: 'unchecked'; reason: UnknownReason; detail: string; message: string;
    }
  | {
      path: string; kind: 'file' | 'directory';
      status: 'broad' | 'no-dacl'; grants: Grant[]; message: string;
    };

export interface AclOptions {
  /**
   * Refuse rather than warn when the ACL is readable beyond its owner.
   * `--strictConfigAcl`. Off by default, and that default is the point.
   *
   * Refusing was the default in 2.3.0, and it blocked a reporter's config at the
   * documented `%APPDATA%` location on the first day — their ACL carried a fourth
   * principal, which the allowlist was built without knowing about because it was
   * measured on one machine. `--allowUncheckedConfigAcl` deliberately did not cover a
   * known-bad verdict, so there was no way past it at all: a security check whose worst
   * outcome is locking an operator out of their own config, over a guarantee Windows
   * states less clearly than POSIX does.
   *
   * So the finding is reported and the config loads. What the check knows is still worth
   * saying — a config under `C:\` really does grant `BUILTIN\Users` read and
   * `Authenticated Users` modify — but saying it and refusing are different things, and
   * only one of them can strand somebody.
   */
  enforce?: boolean;
  /**
   * Load the config even when the ACL could not be determined.
   * `--allowUncheckedConfigAcl`.
   */
  allowUnchecked?: boolean;
  /**
   * Where "this check did not run" goes.
   *
   * It used to go straight to `console.error` from inside the config loader, which
   * for a stdio MCP server is the client's log file — and this codebase has twice
   * ruled that stderr cannot be the only copy (`policy/engine.ts`,
   * `guard/elicitation.ts`). Handing the event to the caller lets `main()` decide,
   * which is also the only place that could ever reach the audit store. Defaults
   * to stderr so the module stands on its own.
   */
  onFinding?: (finding: AclFinding) => void;
}

/**
 * The SID of the account this process runs as.
 *
 * Needed because `icacls /save` emits the DACL alone — no `O:` owner component —
 * so "the owner" has to come from somewhere else, and Node exposes no SID
 * (`os.userInfo().uid` is -1 on Windows). Measured at 12-20ms, and paid once per
 * process *once it succeeds* — only a success is cached, so a failure retries.
 */
let cachedUserSid: string | null | undefined;

async function currentUserSid(signal?: AbortSignal): Promise<string | null> {
  if (cachedUserSid !== undefined) return cachedUserSid;
  try {
    const { stdout } = await run(WHOAMI, ['/user', '/fo', 'csv', '/nh'], {
      signal,
      windowsHide: true,
      env: CHILD_ENV,
    });
    // `"host\user","S-1-5-21-…-1001"`
    const sid = stdout.match(/"(S-1-[0-9-]+)"/)?.[1];
    // Only a success is remembered. Memoising the failure made one aborted or
    // transient `whoami` pin `identity-unknown` for the life of the process, so
    // every later check refused — and it forced a `resetIdentityCache` export
    // whose only callers were tests undoing that poisoning.
    if (sid) cachedUserSid = sid;
    return sid ?? null;
  } catch {
    return null;
  }
}

/**
 * Every line of the security descriptor file `icacls /save` writes.
 *
 * The saved file is UTF-16LE and holds the item's name on one line and its
 * descriptor on the next. Which line is which is not guessed here — the caller
 * hands each line to the parser and keeps the first that parses, so the reader
 * and the parser cannot disagree about what a descriptor looks like. They did
 * in the first version: the reader required a line *starting* with `D:` while
 * the parser accepted an `O:`/`G:` prefix, and the disagreement resolved to
 * "unchecked".
 *
 * SDDL via `/save` rather than PowerShell's `Get-Acl`, whose descriptor would carry an
 * `O:` owner component and save the second subprocess: measured at 8-22ms against
 * 740-830ms, on a check that runs at every start. And rather than plain `icacls` output,
 * which prints account names that depend on the installed language. That reasoning lived
 * only in the changeset, which is deleted at release.
 *
 * Microsoft documents `/save` against a directory; the single-file form is
 * undocumented but real, and windows-acl.live.test.ts covers it by asserting a
 * refusal that is only reachable if a descriptor came back parseable.
 */
/**
 * What a failed descriptor read means.
 *
 * Pure apart from the injected existence check, because the branch that matters most
 * is unreachable from any platform's tests otherwise: off Windows the identity lookup
 * fails first, and on the Windows job only the `read-refused` arm is exercised. The
 * canonical-location check *is* the security argument for pinning System32, and it was
 * executed by nothing.
 *
 * Two failures say nothing about the file — icacls being absent from the machine, and
 * the check running out of time — and those are the two the caller loads anyway even
 * under `--strictConfigAcl`.
 * Everything else (a non-zero exit, output we could not read) is about this path.
 *
 * Which makes "absent" worth being sure of: absent *here* is not enough, because a
 * redirected %SystemRoot% would otherwise reach a fail-open branch, and pinning the
 * path exists to prevent exactly that.
 */
export function classifyReadFailure(
  err: any,
  exists: (path: string) => boolean = existsSync,
): { failure: UnknownReason; detail: string } {
  const notHere = err?.code === 'ENOENT' && typeof err?.path === 'string' && err.path === ICACLS;
  const missing = notHere && !exists(join(CANONICAL_SYSTEM32, 'icacls.exe'));
  if (err?.name === 'AbortError') {
    return { failure: 'timed-out', detail: `the check exceeded its ${ACL_TIMEOUT_MS}ms budget` };
  }
  if (missing) return { failure: 'tool-missing', detail: String(err?.message ?? err).split('\n')[0] };
  if (notHere) {
    return {
      failure: 'read-refused',
      detail: `${ICACLS} is missing but ${CANONICAL_SYSTEM32}\\icacls.exe is not — %SystemRoot% looks wrong`,
    };
  }
  return { failure: 'read-refused', detail: String(err?.message ?? err).split('\n')[0] };
}

async function readDescriptor(
  path: string,
  signal?: AbortSignal,
): Promise<{ lines: string[] } | { failure: UnknownReason; detail: string }> {
  let dir: string | undefined;
  try {
    dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-acl-'));
    const saved = join(dir, 'acl.sddl');
    await run(ICACLS, [path, '/save', saved], { signal, windowsHide: true, env: CHILD_ENV });
    const text = await readFile(saved, { encoding: 'utf16le', signal });
    return { lines: text.split(/\r?\n/) };
  } catch (err: any) {
    return classifyReadFailure(err);
  } finally {
    // Not awaited: `rm` takes no signal, so awaiting it put an unbounded filesystem
    // operation on the path a server start waits for. The directory holds a security
    // descriptor, not a secret, and %TEMP% is per-user — so losing the race to a
    // stalled disk costs a stray directory, not correctness.
    if (dir) void rm(dir, { recursive: true, force: true }).catch(() => {});
  }
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
 * Whichever comes first: the verdict, or the deadline.
 *
 * The signal reaches the subprocesses, but `mkdtemp` and `rm` accept none, so
 * without this the budget bounded three of the nine operations the check performs.
 * Expiry resolves to the same verdict a subprocess timeout produces, which warns
 * and loads — a slow machine is not evidence about the file.
 */
function raceDeadline(verdict: Promise<AclVerdict>, signal?: AbortSignal): Promise<AclVerdict> {
  if (!signal) return verdict;
  const expired = new Promise<AclVerdict>((resolve) => {
    if (signal.aborted) resolve(TIMED_OUT);
    else signal.addEventListener('abort', () => resolve(TIMED_OUT), { once: true });
  });
  return Promise.race([verdict, expired]);
}

const TIMED_OUT: AclVerdict = {
  status: 'unknown',
  reason: 'timed-out',
  detail: `the check exceeded its ${ACL_TIMEOUT_MS}ms budget`,
};

/** Read one path's DACL and judge it. */
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

export async function inspectAcl(path: string, signal?: AbortSignal): Promise<AclVerdict> {
  const sid = await currentUserSid(signal);
  // The budget expiring has to mean the same thing wherever it lands. `whoami` runs
  // first and its failure is indistinguishable inside the catch, so without this an
  // expiry during the identity lookup became `identity-unknown` and *refused*, while
  // the identical expiry one subprocess later became `timed-out` and loaded. Only a
  // success is cached, so it refused a second time for the directory too.
  if (sid === null && signal?.aborted) return TIMED_OUT;
  if (sid === null) {
    return { status: 'unknown', reason: 'identity-unknown', detail: 'could not read this account\'s SID' };
  }
  const identity = aclIdentity(sid);

  const read = await readDescriptor(path, signal);
  if ('failure' in read) return { status: 'unknown', reason: read.failure, detail: read.detail };

  // The reader does not decide which line is the descriptor; the parser does.
  let lastDetail = 'no line parsed as a security descriptor';
  for (const line of read.lines) {
    const trimmed = line.trim();
    // A descriptor opens with one of its components. Without this, "first line that
    // parses" let an item-name line stand in for the descriptor: `parseDacl('D:')` is a
    // legitimately empty DACL and therefore `restricted`, and `icacls D: /save` for a
    // drive-relative `--config D:config.toml` writes a name line of exactly `D:`.
    if (!/^[OGDS]:/.test(trimmed)) continue;
    const verdict = parseDacl(trimmed, identity);
    if (verdict.status !== 'unknown') return verdict;
    lastDetail = verdict.detail;
  }
  return { status: 'unknown', reason: 'unparsable', detail: lastDetail };
}

/**
 * Whether a path is somewhere its ACL can reasonably be tightened.
 *
 * A drive root or the working directory is not: the remediation for a config at
 * `C:\config.toml` used to be printed as `icacls "C:\" /inheritance:d` followed
 * by a `/remove:g` of BUILTIN\Users — which, run as printed, breaks inheritance
 * across the volume and takes the drive away from every non-administrator. The
 * fix for a config in a place like that is to put it somewhere else.
 */
function isTightenable(path: string, kind: 'file' | 'directory'): boolean {
  // A file is always tightenable. Removing BUILTIN\Users from one config file
  // takes nothing away from anyone — the destructive case was only ever the
  // directory, and scoping this to both made the advice for the realistic case
  // ("your config is under C:\sshcfg") worse than what it replaced.
  if (kind === 'file') return true;

  const { root } = parsePath(path);
  if (path === root || path === '.' || path === '..') return false;
  // For a directory, not merely "is it a root". Everything under `C:\` inherits
  // BUILTIN\Users read-and-execute, so any directory outside the profile can come
  // back broad — and `C:\Users\config.toml` would then be answered with "strip
  // BUILTIN\Users from C:\Users", which removes every other account's traverse to
  // its own profile. The first version keyed on how the path was spelled, so it
  // caught only the two shapes that had been reported.
  //
  // Outside the profile the fix is described rather than printed. A directory the
  // operator does own — `D:\configs`, say — is perfectly tightenable, and telling
  // them to move the file would be poor advice; but that cannot be told apart from
  // a directory other accounts depend on, and only one of those two mistakes is
  // destructive.
  const home = process.env.USERPROFILE;
  // With no profile to compare against the honest answer is "cannot tell", and
  // relocation() is the message that says so without prescribing anything destructive.
  // Returning true here reinstated exactly the advice this function exists to prevent:
  // break inheritance on a shared directory and strip BUILTIN\Users from it.
  if (!home) return false;
  // Both sides through realpath, because Windows hands out 8.3 short names and the
  // two ends of this comparison need not agree on which form they use: on a GitHub
  // runner %TEMP% is `C:\\Users\\RUNNER~1\\AppData\\Local\\Temp` while %USERPROFILE% is
  // `C:\\Users\\runneradmin`, so comparing the text said "outside the profile" for a
  // directory squarely inside it, and the operator got "move the config" where the
  // fix was two commands. The Windows job caught that; the VM did not.
  //
  // path.relative rather than a prefix match: a hardcoded separator was wrong on
  // the platform the tests run on, and a bare startsWith would also accept a
  // sibling whose name merely begins with the profile's (`C:\\Users\\meloud`).
  const rel = relative(canonical(home), canonical(path));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * A path in the form the filesystem itself uses, lowercased.
 *
 * `realpathSync.native` is what expands an 8.3 short name. It needs the path to
 * exist, so a missing one falls back to lexical resolution.
 */
function canonical(path: string): string {
  try {
    return realpathSync.native(resolve(path)).toLowerCase();
  } catch {
    return resolve(path).toLowerCase();
  }
}

/**
 * The two commands that make a path private again.
 *
 * `grants` is empty for a NULL DACL, where there is nothing to remove and the
 * point is to give the object an ACL at all. Shared rather than written twice:
 * this text has the worst record in the change — three corrected versions so far
 * — and a second copy is a second thing to keep correcting.
 */
function remediation(path: string, kind: 'file' | 'directory', grants: Grant[] = []): string {
  const resolved = grants.filter((g) => g.sid !== null);
  const unresolved = grants.filter((g) => g.sid === null);
  const removals = resolved.length
    ? ` ${resolved.map((g) => `/remove:g *${g.sid}`).join(' ')}`
    : '';
  // Named rather than guessed at: `/remove:g *<alias>` is accepted and removes nothing,
  // which is worse than admitting we cannot name the SID.
  const byHand = unresolved.length
    ? `\nOne entry cannot be named as a SID from here: ${unresolved.map((g) => g.name).join(', ')}. ` +
      `Run \`icacls "${path}"\` to see it and remove it by the SID icacls prints.`
    : '';
  const rights = kind === 'file' ? 'F' : '(OI)(CI)F';
  // The account name is interpolated rather than left as %USERNAME%. That spelling
  // is cmd.exe's; pasted into PowerShell — the default shell on Windows 11 — it
  // reaches icacls literally, which reports "Failed processing 1 files" and
  // changes nothing. Measured. An instruction that only works in one shell is
  // the same defect as the `chmod 600` this whole change replaced.
  // Guarded because this is now on the *reporting* path, not only the throwing one. A
  // Windows service under a virtual account, or a container with no loaded profile, makes
  // `userInfo()` throw ENOENT — which escaped as a raw stack and cost the operator their
  // config, which is #138 one environment over. A message that cannot name the account is
  // still worth printing.
  let account: string;
  try {
    account = userInfo().username;
  } catch {
    account = process.env.USERNAME || '<your account>';
  }
  return (
    'Restrict it with these two commands, in this order:\n' +
    `  icacls "${path}" /inheritance:d\n` +
    `  icacls "${path}" /grant:r "${account}:${rights}"${removals}\n` +
    'The first converts inherited entries into entries this object owns — an inherited ' +
    'entry cannot be removed while it is still inherited, which is why it takes two ' +
    'commands. The second grants you full access and drops the broad ones. SYSTEM and ' +
    'Administrators keep theirs, which is what a file under %APPDATA% looks like.' +
    byHand
  );
}

function relocation(path: string, kind: 'file' | 'directory', grants: Grant[]): string {
  // The commands come from `remediation`, not from a copy, and they are printed rather
  // than referred to.
  //
  // Two reasons. Reaching this arm for a directory requires the *file* to have been
  // private — the loop reports the first offending subject — so the earlier wording,
  // "the same two commands shown for the file apply to it", pointed at text that was
  // absent every single time. And a hand-written pair here would have omitted the
  // `/remove:g` arguments, which is a command that reports success and leaves the
  // directory exactly as open as it was: the defect this whole change is about,
  // reproduced one arm over.
  return (
    'Move the config under %APPDATA%\\ssh-mcp instead, which inherits an ACL restricted ' +
    'to you, SYSTEM and Administrators.\n' +
    `${path} is a filesystem root, or sits outside your user profile, so removing the ` +
    'broad entries from it could take access away from every other account on the ' +
    'machine. If it is in fact yours alone, the commands below do it — but whether it ' +
    'is, only you can judge.\n' +
    remediation(path, kind, grants)
  );
}

/**
 * What a verdict means for one subject, as text and as data — and nothing else.
 *
 * Pure, so every message is assertable without a subprocess or a `console.error` spy, and
 * so the refusal and the report cannot drift apart: they sat fifteen lines apart and had
 * already diverged, one calling the same condition "was not checked" and the other "could
 * not be checked".
 */
function describe(path: string, kind: 'file' | 'directory', verdict: AclVerdict): AclFinding | null {
  if (verdict.status === 'restricted') return null;

  if (verdict.status === 'unknown') {
    return {
      path,
      kind,
      status: 'unchecked',
      reason: verdict.reason,
      detail: verdict.detail,
      message:
        `Config ${kind} ${path} could not be checked for access by other accounts ` +
        `(${verdict.reason}: ${verdict.detail}).\n` +
        'Either fix the cause, move the config under %APPDATA%\\ssh-mcp, or pass ' +
        '--allowUncheckedConfigAcl to accept it unverified.',
    };
  }

  // An empty grants list for a NULL DACL is deliberate: there is nothing to `/remove:g`,
  // and the fix is to give the object an ACL at all. `remediation` reads that emptiness.
  const grants = verdict.status === 'broad' ? verdict.grants : [];
  const writers = grants.filter((g) => g.writes);
  const readers = grants.filter((g) => !g.writes);
  const what = verdict.status === 'no-dacl'
    ? 'has no access control list at all, which on Windows means full control for every ' +
      'account on the machine.'
    : writers.length > 0
      // Named as modifiable, not "readable". Calling a modify grant readable understated an
      // integrity failure as a disclosure — and the two now decide different postures, so
      // the wording has to tell them apart.
      ? `can be modified by accounts other than its owner: ${writers.map((g) => g.name).join(', ')}` +
        `${readers.length ? `, and read by ${readers.map((g) => g.name).join(', ')}` : ''}. ` +
        'Required: this account, SYSTEM and Administrators only.'
      : `is readable beyond its owner: access is granted to ${grants.map((g) => g.name).join(', ')}. ` +
        'Required: this account, SYSTEM and Administrators only.';

  return {
    path,
    kind,
    status: verdict.status,
    grants,
    message:
      `Config ${kind} ${path} ${what}\n` +
      (isTightenable(path, kind) ? remediation(path, kind, grants) : relocation(path, kind, grants)),
  };
}

/**
 * Whether a finding is reported rather than refused.
 *
 * Three postures, two flags, and deliberately no combination that leaves an operator with
 * no exit — the lesson of #138, and why this is a function rather than one boolean.
 *
 * By default: a grant that only lets another account *read* is reported, because that is
 * where Windows is muddier than POSIX and refusing over it stranded a real operator. A
 * grant that lets another account *change* the config is refused, because that is an
 * authorization bypass and Windows is not muddy about it. An ACL that could not be
 * determined is refused too — #138 was a known-bad verdict, never an undeterminable one,
 * and flipping those open would let an attacker swap a loud finding for a vague one for
 * free. The two exceptions stay: `icacls` absent, and the check running out of time, both
 * statements about the machine rather than about the file.
 *
 * `--allowUncheckedConfigAcl` reports everything and refuses nothing — the single exit.
 * `--strictConfigAcl` refuses everything the check objects to, read-only grants included.
 */
function waived(finding: AclFinding, opts: AclOptions): boolean {
  if (opts.allowUnchecked) return true;
  if (opts.enforce) return false;
  if (finding.status === 'unchecked') {
    return finding.reason === 'tool-missing' || finding.reason === 'timed-out';
  }
  // A NULL DACL is full control for everyone, so it is never read-only.
  return finding.status === 'broad' && !finding.grants.some((g) => g.writes);
}

/**
 * Report what a config's ACL grants beyond its owner, and refuse when it is not merely
 * readable — the Windows half of `checkPermissions`.
 *
 * Both the file and its directory are examined. What happens to a finding is
 * `waived`'s decision; see it for the three postures and why the default is not to refuse
 * a read-only over-grant.
 */
export async function assertPrivateOnWindows(
  filePath: string,
  opts: AclOptions = {},
  inspect?: (path: string) => Promise<AclVerdict>,
): Promise<void> {
  // One deadline for the whole check, shared by every subprocess it starts.
  // A budget per subject, not one shared across both. Sharing it meant an expiry during
  // the file check aborted the directory check on entry, so one slow call did not degrade
  // the check — it disabled the rest of it.
  const look = inspect ?? ((p: string) => {
    const signal = AbortSignal.timeout(ACL_TIMEOUT_MS);
    return raceDeadline(inspectAcl(p, signal), signal);
  });
  const report = opts.onFinding ?? ((f: AclFinding) => console.error(`Warning: ${f.message}`));
  const subjects = [
    { path: filePath, kind: 'file' as const },
    { path: parsePath(filePath).dir || '.', kind: 'directory' as const },
  ];

  for (const { path, kind } of subjects) {
    const finding = describe(path, kind, await look(path));
    if (finding === null) continue;

    // One decision, read once. Refusing and reporting used to be decided in three places —
    // twice on the same flag for the same question — with two `continue`s and two throw
    // sites, and the advisory path wrote to stderr directly rather than through the sink.
    if (!waived(finding, opts)) throw new OperatorError(finding.message);
    report(finding);
  }
}
