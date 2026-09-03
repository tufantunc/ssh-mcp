import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync, realpathSync } from 'fs';
import { mkdtemp, readFile, rm } from 'fs/promises';
import { tmpdir, userInfo } from 'os';
import { join, resolve, parse as parsePath } from 'path';
import { OperatorError } from '../errors.js';
import { isWithinRoot } from './path-containment.js';
import {
  parseDacl,
  aclIdentity,
  type Grant,
  type UnknownReason,
  type AclVerdict,
} from './sddl.js';

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
  return isWithinRoot(canonical(home), canonical(path));
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
  //
  // Guarded because this is now on the *reporting* path, not only the throwing one. A
  // Windows service under a virtual account, or a container with no loaded profile, makes
  // `userInfo()` throw ENOENT — which escaped as a raw stack and cost the operator their
  // config, which is #138 one environment over. A message that cannot name the account is
  // still worth printing.
  //
  // A visible placeholder rather than `process.env.USERNAME`, which was the first spelling
  // of this fallback. In the environments where `userInfo()` actually throws the env var is
  // either unset or holds something icacls will not accept — a virtual service account, or
  // `MACHINE$` — so it would print a command that fails, which is the defect class this
  // whole change exists to remove. A placeholder the operator has to fill in cannot be
  // followed by mistake.
  let account: string;
  try {
    account = userInfo().username;
  } catch {
    account = '<your account>';
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
