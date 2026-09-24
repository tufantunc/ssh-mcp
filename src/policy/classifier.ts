import type { CommandClass, ParsedCommand } from '../types.js';
import { AWK_NAMES, readAwkInvocation, type AwkFindings } from './awk.js';

/**
 * Anything through which the shell can start a second command.
 *
 * This gate decides whether an allowlisted binary counts as read-only, and the
 * allowlist only vouches for the binary — never for what a shell might run
 * beside it. It used to test /[>;|]/, which let `ls $(touch /tmp/x)` through as
 * read-only: `ls` is allowlisted, no listed metacharacter appears, and the
 * remote shell expands the substitution and runs the inner command anyway
 * (GHSA-r8hm-vpm8-cfh6).
 *
 * Listing every dangerous construct is a losing game — `$()`, backticks,
 * `<(...)`, `${x:=...}`, `&&`, a bare newline — so this refuses every character
 * with syntactic meaning to the shell instead, and `$` wholesale rather than
 * just `$(`. The cost is that `echo $HOME` is no longer classified read-only.
 * That is the right trade for the tool whose entire promise is that it cannot
 * write: run-command still accepts it under policy.
 */
const SHELL_CONTROL_CHARS = /[;&|<>`$(){}\n\r]/;

/**
 * The binaries this classifier will vouch for, and what it vouches for about them.
 *
 * Two questions, kept apart because one Set answering both is how #217 turned the
 * interpreter carrier scan off for two verbs by adding them to a list about
 * classes:
 *
 *   readOnly         does this binary only read?  -> decides the class
 *   operandsAreData  can its operands hide a command?  -> decides whether the
 *                    carrier scan runs
 *
 * Both are `true` for every entry today. The value is not the contents but that
 * the type will not let the next person add a name without answering both.
 *
 * Two mechanisms answer the second question outside this table and are not
 * affected by it — `DISQUALIFYING_ARGS` and `FIND_EXEC_FLAGS` — which is why
 * `find` can carry `operandsAreData: true` while `find … -exec sudo id +` is
 * still `privileged`.
 *
 * The two-word entries are looked up only for the class: `operandsAreData` reads
 * a single word, so those rows never reach the second question.
 */
const READERS: Record<string, { readOnly: boolean; operandsAreData: boolean }> = {
  "arp":              { readOnly: true, operandsAreData: true },
  "basename":         { readOnly: true, operandsAreData: true },
  "cat":              { readOnly: true, operandsAreData: true },
  "comm":             { readOnly: true, operandsAreData: true },
  "cut":              { readOnly: true, operandsAreData: true },
  "date":             { readOnly: true, operandsAreData: true },
  "df":               { readOnly: true, operandsAreData: true },
  "diff":             { readOnly: true, operandsAreData: true },
  "dig":              { readOnly: true, operandsAreData: true },
  "dirname":          { readOnly: true, operandsAreData: true },
  "docker images":    { readOnly: true, operandsAreData: true },  // two-word: class only
  "docker inspect":   { readOnly: true, operandsAreData: true },  // two-word: class only
  "docker logs":      { readOnly: true, operandsAreData: true },  // two-word: class only
  "docker ps":        { readOnly: true, operandsAreData: true },  // two-word: class only
  "docker stats":     { readOnly: true, operandsAreData: true },  // two-word: class only
  "du":               { readOnly: true, operandsAreData: true },
  "echo":             { readOnly: true, operandsAreData: true },
  "false":            { readOnly: true, operandsAreData: true },
  "file":             { readOnly: true, operandsAreData: true },
  "find":             { readOnly: true, operandsAreData: true },
  "free":             { readOnly: true, operandsAreData: true },
  "git branch":       { readOnly: true, operandsAreData: true },  // two-word: class only
  "git diff":         { readOnly: true, operandsAreData: true },  // two-word: class only
  "git log":          { readOnly: true, operandsAreData: true },  // two-word: class only
  "git remote":       { readOnly: true, operandsAreData: true },  // two-word: class only
  "git show":         { readOnly: true, operandsAreData: true },  // two-word: class only
  "git status":       { readOnly: true, operandsAreData: true },  // two-word: class only
  "grep":             { readOnly: true, operandsAreData: true },
  "head":             { readOnly: true, operandsAreData: true },
  "host":             { readOnly: true, operandsAreData: true },
  "hostname":         { readOnly: true, operandsAreData: true },
  "htop":             { readOnly: true, operandsAreData: true },
  "id":               { readOnly: true, operandsAreData: true },
  "ifconfig":         { readOnly: true, operandsAreData: true },
  "iostat":           { readOnly: true, operandsAreData: true },
  "ip addr":          { readOnly: true, operandsAreData: true },  // two-word: class only
  "ip route":         { readOnly: true, operandsAreData: true },  // two-word: class only
  "journalctl":       { readOnly: true, operandsAreData: true },
  "ls":               { readOnly: true, operandsAreData: true },
  "netstat":          { readOnly: true, operandsAreData: true },
  "nslookup":         { readOnly: true, operandsAreData: true },
  "ping":             { readOnly: true, operandsAreData: true },
  "printenv":         { readOnly: true, operandsAreData: true },
  "printf":           { readOnly: true, operandsAreData: true },
  "ps":               { readOnly: true, operandsAreData: true },
  "pwd":              { readOnly: true, operandsAreData: true },
  "readlink":         { readOnly: true, operandsAreData: true },
  "realpath":         { readOnly: true, operandsAreData: true },
  "seq":              { readOnly: true, operandsAreData: true },
  "sort":             { readOnly: true, operandsAreData: true },
  "ss":               { readOnly: true, operandsAreData: true },
  "stat":             { readOnly: true, operandsAreData: true },
  "systemctl status": { readOnly: true, operandsAreData: true },  // two-word: class only
  "tail":             { readOnly: true, operandsAreData: true },
  "test":             { readOnly: true, operandsAreData: true },
  "top":              { readOnly: true, operandsAreData: true },
  "tr":               { readOnly: true, operandsAreData: true },
  "traceroute":       { readOnly: true, operandsAreData: true },
  "true":             { readOnly: true, operandsAreData: true },
  "uname":            { readOnly: true, operandsAreData: true },
  "uniq":             { readOnly: true, operandsAreData: true },
  "uptime":           { readOnly: true, operandsAreData: true },
  "vmstat":           { readOnly: true, operandsAreData: true },
  "wc":               { readOnly: true, operandsAreData: true },
  "whereis":          { readOnly: true, operandsAreData: true },
  "which":            { readOnly: true, operandsAreData: true },
  "who":              { readOnly: true, operandsAreData: true },
  "whoami":           { readOnly: true, operandsAreData: true },
};

/** The class half of READERS, as the shape its consumers already expect. */
const READ_ONLY_ALLOWLIST = new Set(
  Object.entries(READERS).filter(([, e]) => e.readOnly).map(([name]) => name),
);
// Deliberately NOT read-only: `env`, because it is an exec wrapper. `env <cmd>`
// runs <cmd>, so allowlisting the name `env` vouched for a command the
// classifier never looked at — `env sudo rm -f /etc/passwd` classified
// `read-only` and ran on a profile whose whole contract is that it cannot
// write. It carries no shell metacharacter, so the SHELL_CONTROL_CHARS gate
// below did not catch it either. Falls through to `safe`, so run-command can
// still reach it under policy; a bare `env` that only prints the environment
// loses read-only status with it, which is the price of a name-based allowlist.
//
// Deliberately NOT read-only: `curl` and `wget` fetch arbitrary URLs (SSRF to
// cloud metadata / internal services), post local files to a remote host
// (`curl -d @/etc/passwd`), and write remote files (`curl -o`, `wget -O`) —
// none of which need a shell metacharacter to escape the classifier. They fall
// through to the `safe` class, so run-command can still use them under policy.
//
// Residual risk kept on purpose: dig/nslookup/host/ping/traceroute can leak
// small amounts of data through DNS/ICMP queries. They cannot modify the host,
// so they stay read-only; tighten them via profile policy if egress matters.

/**
 * The SFTP read verbs, which the tool layer synthesises rather than a caller typing.
 *
 * A second set rather than two more entries in READ_ONLY_ALLOWLIST, and the
 * reason is that that Set is dual-purpose: `operandsAreData` reads it too, to
 * decide whether a segment's operands are data rather than commands. Putting
 * these verbs there silenced the carrier scan for them — measured,
 * `sftp:list /tmp sh -c 'sudo id'` fell from `privileged` to `read-only`,
 * because `nestedCommands` stopped extracting the `sh -c` payload. That is the
 * one carrier form carrying no character from SHELL_CONTROL_CHARS, i.e. exactly
 * the form the scan is load-bearing for.
 *
 * The suppression buys nothing here anyway. It exists so `grep python3 -c file`
 * is not read as invoking python; these verbs take a path nobody parses, so
 * there is no false positive to suppress.
 *
 * Why they are lowered at all: both carry `readOnlyHint: true`, the README marks
 * both read-only, `sftp-list`'s description ends "Read-only." — and `safe` is
 * refused outright by a `readOnly` profile, so the one profile class the
 * annotation targets was the one that could not run them (#217).
 * (`sftp-download`'s description makes no read-only claim; an earlier version of
 * this paragraph said both did, which is the overstatement this file keeps
 * catching.) The lowering grants that
 * profile nothing new: `cat /etc/shadow` and `ls /root` are already `read-only`,
 * so the authority to read any file the SSH user can read is already held.
 *
 * `sftp:upload`, `sftp:upload-file` and `sftp:download-file` stay out — the
 * first two write on the remote host, the third inside the transfer root.
 */
const READ_ONLY_SYNTHETIC = new Set(['sftp:list', 'sftp:download']);

/**
 * Commands that are never allowed, whatever the role or approval policy.
 *
 * This is the policy engine's denylist — the single definition of it. The
 * engine used to keep a parallel copy as regex *strings*, which had already
 * drifted (it was missing the fork bomb and the recursive chown, and its `rm`
 * pattern was narrower). Anything here is also destructive for classification
 * purposes; see DESTRUCTIVE_DENYLIST below.
 */
/*
 * These are the patterns that stayed regexes, and every one of them is linear.
 *
 * The four that were not — `dd\s.*\bof=/dev/`, the two `curl|wget …\|\s*(sh…)`
 * forms, and `chown\s+-R\s.*\s/\s*$` — are now segment checks below. An earlier
 * comment here reasoned that ambiguity *within* a match was the only cost, and
 * that was wrong: the engine also restarts at every offset where the cheap
 * literal head matches, so a command built from `dd curl wget chown -R x `
 * repeated ran at 4x per doubling. Measured on the real chain: 64 KB took
 * 255 ms, 1 MB took 65 seconds of blocked event loop, and the stall lands in
 * classifyCommand — before the approval gate and before the allow/deny
 * decision, so no role, approval mode or readOnly flag protects against it.
 *
 * The old note said sanitizeCommand's maxChars cap kept this cheap, "but a
 * policy check should not depend on a limit set three layers away and
 * configurable to any value". Once a config file could say `commandMaxChars = 0`
 * (#123) that limit went away, and the prediction came true. The rewrite below
 * is what that sentence was asking for: the policy check is now safe on its own
 * terms, whatever maxChars says.
 *
 * The existing cost test did not catch it because its seeds are runs of spaces,
 * which never match the literal heads and so never trigger the restart.
 */
const FORBIDDEN_PATTERNS: RegExp[] = [
  /rm\s+-rf?\s+\/(\s|$)/,          // rm -rf / — the filesystem root itself
  /mkfs\./,
  />\s*\/dev\/sd/,
  // Fork bomb, with whitespace allowed at the five positions bash allows it and the old
  // pattern did not: before the parentheses, inside them, either side of the pipe, and
  // before the ampersand. `: () { : | : & } ; :` ran and classified `safe`.
  //
  // What this still does not catch, so that nobody reads it as "fork bombs are handled":
  // the same bomb under another name (`f(){ f|f& };f`), a body that separates the two
  // calls with `&` or `;` rather than `|` (`:(){ :&:& };:`), and a comment between the
  // tokens (`:() # x\n{ :|:& };:`). Matching the first needs a backreference over an
  // unbounded body and this file has already shipped one ReDoS; the others would widen a
  // list no role, tier or approval mode can override. The impact is a denial of service
  // against the target host rather than against this server, which is not worth either
  // trade — but it is a hole, not a closed door.
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
  />\s*\/etc\/cron/,
  />\s*\/etc\/systemd/,
  />\s*~\/.ssh\/authorized_keys/,
  /\biptables\s+-F\b/,
  /\bchmod\s+-R\s+777\s+\//,
];

/**
 * Words that are forbidden when *invoked*, which the patterns above cannot
 * express.
 *
 * These used to be `/\breboot\b/` and friends, matching the word anywhere in
 * the string. `last reboot` reads a log and was refused for containing the
 * word; so were `grep -r reboot /etc/`, `cat /var/run/reboot-required` and
 * `journalctl | grep shutdown`. On a NAS an agent checking boot history trips
 * this on its first command, which is how it was reported (#91).
 *
 * Matching an invocation rather than a mention needs to know where a command
 * word can start, and that is a tokenizer's job, not a regex's — the regex
 * forms that come close all reintroduce the `\S*` backtracking the block above
 * exists to avoid.
 */
const FORBIDDEN_INVOCATIONS = new Set(['shutdown', 'reboot', 'halt', 'poweroff', 'eval']);

/** Binaries that take the dangerous action as an argument: `systemctl reboot`. */
const ACTION_MULTIPLEXERS = new Set(['systemctl', 'init', 'telinit']);

/**
 * Binaries that run the rest of the command as another user.
 *
 * The list is explicit rather than a pattern, because a pattern cannot tell
 * `sudoedit` — which edits a file and is not elevation — from `sudo-rs`, which
 * is sudo. It has to be maintained by hand as new implementations appear; the
 * cost of missing one is that its commands classify `safe`.
 *
 * The last five were added in 2.2.5 (#132). Until 2.2.4 the check was
 * `/^\s*su\b/` and friends, and `\b` matched between `su` and the hyphen, so
 * `su-exec` and `sudo-rs` were caught — by accident of the regex, not by
 * intent. Moving to exact membership dropped them, which narrowed a security
 * control inside a security release. `gosu` and `run0` were never caught by
 * either form.
 */
/**
 * Class ordering, so a command that contains another can take the higher of the two.
 *
 * Only used by the nesting scan below. Everything else in this file decides a single
 * class outright.
 */
const CLASS_RANK: Record<CommandClass, number> = {
  'read-only': 0,
  safe: 1,
  destructive: 2,
  privileged: 3,
};

/**
 * Interpreters, the flags that hand them a program, and whether this file can read it.
 *
 * One table rather than three overlapping name lists: adding an interpreter here is the
 * whole change, and a shell list that drifts out of step with a readability list is how a
 * new shell ends up treated as an unreadable interpreter.
 *
 * `readable` means the program is shell, so classifying it is this same job done again
 * and the class it earns is real. Python, Perl, Ruby, Node and PHP are not: their program
 * is a different language, and `os.system('sudo id')` carries an elevation the shell
 * classifier cannot see. Pretending to parse them would be a worse answer than admitting
 * we cannot, so an unreadable program makes the command `destructive` — "we cannot tell",
 * not "this is root", the same answer `hasUnnameableCommand` gives.
 *
 * `busybox` is not here: it takes an applet name, not `-c`, so `busybox sh -c …` is an
 * `sh` invocation behind a wrapper. It is in EXEC_WRAPPERS instead, which is what it is.
 */
// Null-prototype for the reason `mergePolicyRules` spells out (#172): this is indexed by
// a command word, which is a free string, so on a plain object `INTERPRETERS['toString']`
// resolves to a function and reading `.programBearingWords` off it throws inside the
// policy gate.
/** One entry of the interpreter table — named so the lookup helper below can share it. */
interface InterpreterSpec {
  programBearingWords: string[];
  readable: boolean;
}

const INTERPRETERS: Record<string, InterpreterSpec> = Object.assign(
  Object.create(null) as Record<string, InterpreterSpec>,
  {
  sh: { programBearingWords: ['-c'], readable: true },
  bash: { programBearingWords: ['-c'], readable: true },
  dash: { programBearingWords: ['-c'], readable: true },
  zsh: { programBearingWords: ['-c'], readable: true },
  ksh: { programBearingWords: ['-c'], readable: true },
  ash: { programBearingWords: ['-c'], readable: true },
  python: { programBearingWords: ['-c'], readable: false },
  python2: { programBearingWords: ['-c'], readable: false },
  python3: { programBearingWords: ['-c'], readable: false },
  perl: { programBearingWords: ['-e', '-E'], readable: false },
  ruby: { programBearingWords: ['-e'], readable: false },
  // `-p`/`--print` evaluate exactly as `-e` does and then print the result.
  node: { programBearingWords: ['-e', '--eval', '-p', '--print'], readable: false },
  php: { programBearingWords: ['-r'], readable: false },
  // Measured on 2.11.0: each of these classified `safe` while the identical
  // attack through python3 -c classified `destructive` (GHSA-qmx6-47vm-3vf7).
  // `readable: false` throughout, matching python/perl/node: the program is not
  // shell text, so its presence is what counts rather than its content.
  osascript: { programBearingWords: ['-e'], readable: false },
  lua: { programBearingWords: ['-e'], readable: false },
  Rscript: { programBearingWords: ['-e'], readable: false },
  bun: { programBearingWords: ['-e'], readable: false },
  tclsh: { programBearingWords: ['-c'], readable: false },
  // `eval` is a subcommand, not a flag — the field is named for what it holds.
  deno: { programBearingWords: ['eval'], readable: false },
  pwsh: { programBearingWords: ['-c', '-Command', '-e', '-EncodedCommand'], readable: false },
  powershell: { programBearingWords: ['-c', '-Command', '-e', '-EncodedCommand'], readable: false },
  },
);

/**
 * Every `INTERPRETERS` entry, keyed by its name lower-cased.
 *
 * A second index rather than lower-casing the lookup key against `INTERPRETERS`
 * directly, because that table's own keys are not uniformly lower-case —
 * `Rscript` is not `rscript` — so folding only the *input* would still miss it.
 * Built once at module load: the table is fixed, so there is nothing to keep in
 * sync.
 */
const INTERPRETERS_BY_LOWERCASE_NAME: Record<string, InterpreterSpec> = Object.assign(
  Object.create(null) as Record<string, InterpreterSpec>,
  Object.fromEntries(Object.entries(INTERPRETERS).map(([name, spec]) => [name.toLowerCase(), spec])),
);

/** A Windows executable suffix this table's keys never carry. */
const WINDOWS_EXE_SUFFIX = /\.(exe|cmd|bat)$/i;

/**
 * Resolve an interpreter table entry for a command word already stripped of
 * its path (`stripPath(unquote(word))`, as every call site already computes
 * it for the exact-match case below).
 *
 * The table's keys are exact, case-sensitive, extension-free spellings, so a
 * direct lookup is tried first and is the whole cost for the common case —
 * `sh`, `python3`, the bare lowercase `pwsh`. The fallback strips a trailing
 * `.exe`/`.cmd`/`.bat` and folds case, which is what a Windows target's own
 * shell hands back for the *same* binary: `powershell.exe`, `PWSH.EXE` and
 * `PowerShell` all name the interpreter this table already lists under
 * `powershell`/`pwsh`.
 *
 * Applied to every entry, not only pwsh/powershell. The measured bug is
 * about those two, but the gap is not specific to them: a target running
 * `python.exe` or `Node.EXE` carries the identical mismatch, and scoping the
 * fix to two names would leave the rest of the table exactly as blind as it
 * was. This is the binary-*name* question, answered once — it does not touch
 * flag matching, which stays case-sensitive per interpreter (`perl -E` and
 * `perl -e` are still two different flags) via the existing, separate
 * `caseInsensitive` parameter threaded through `programAfterFlag` and
 * friends.
 */
function resolveInterpreter(word: string): InterpreterSpec | undefined {
  const exact = INTERPRETERS[word];
  if (exact !== undefined) return exact;
  return INTERPRETERS_BY_LOWERCASE_NAME[word.replace(WINDOWS_EXE_SUFFIX, '').toLowerCase()];
}

/** `find … -exec <cmd> +` runs cmd. */
const FIND_EXEC_FLAGS = new Set(['-exec', '-execdir', '-ok', '-okdir']);

/**
 * How deep a substitution may nest before we stop reading and refuse to guess.
 *
 * Reached only by input no operator writes — the tests use two hundred levels. The
 * fallback is `privileged` rather than a lower class because the entire point of
 * this scan is that a command we cannot read must not be treated as one we can.
 */
const MAX_NESTING_DEPTH = 8;

/**
 * Split a command into segments of words, resolving quoting as a shell would.
 *
 * The classifier's regexes were written against the command as sent, but the transport
 * removes quoting before the command runs, so `rm -rf "/etc"` matched no destructive
 * pattern and `s"u"do id` named no privilege prefix. Every consumer that used to split on
 * `/[;&|\n]/` and `/\s+/` reads this instead, so quote removal happens once, in one
 * place, rather than being re-derived per rule.
 *
 * Not a shell parser. Variable expansion, arithmetic and here-documents are out of scope —
 * `hasUnnameableCommand` is what refuses a command word this cannot resolve.
 */
function tokenizeSegments(command: string): string[][] {
  return tokenizeSegmentsDetailed(command).map((segment) => segment.words);
}

/**
 * The same split, keeping the separator that introduced each segment.
 *
 * Only the pipe rules need it: `|` feeds one command's output into the next, while `;`
 * and `&` merely sequence, and a rule about pipes must not fire on a rule about sequences.
 * Deriving both views from one tokeniser is what stops the two from drifting apart.
 */
function tokenizeSegmentsDetailed(
  command: string,
  honorQuotes = true,
): Array<{ words: string[]; sep: string }> {
  const segments: Array<{ words: string[]; sep: string }> = [];
  let pending = '';
  let words: string[] = [];
  let current = '';
  let quote: string | null = null;
  let escaped = false;

  /**
   * Whether the word being built was quoted, so an *empty* one survives.
   *
   * `if (current)` alone dropped it, and a dropped word is not cosmetic for
   * anything that reads arguments by position: `awk -F '' 'BEGIN{system("sudo
   * id")}'` arrived as three words instead of four, so the awk reader consumed
   * the program as `-F`'s value and reported that the invocation ran no program
   * — `safe`, for a command real awk runs. Measured on BWK awk 20200816: it
   * warns "field separator FS is empty" on stderr and then executes both the
   * `system()` call and a file redirection.
   *
   * Only a *quoted* empty survives. Pushing every empty `current` would emit a
   * word per run of whitespace, which is not what a shell does.
   */
  let quotedWord = false;

  const endWord = () => {
    if (current || quotedWord) words.push(current);
    current = '';
    quotedWord = false;
  };
  const endSegment = (sep: string) => {
    endWord();
    if (words.length > 0) segments.push({ words, sep: pending });
    words = [];
    pending = sep;
  };

  for (const ch of command) {
    if (escaped) {
      // A backslash quotes the next character, so `\reboot` runs reboot. Keeping the
      // character and dropping the backslash is what the shell does.
      current += ch;
      escaped = false;
      continue;
    }
    if (quote) {
      // Backslash is literal inside single quotes; inside double quotes it escapes.
      if (ch === '\\' && quote === '"') { escaped = true; continue; }
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === '\\') { escaped = true; continue; }
    if (honorQuotes && (ch === '"' || ch === "'")) { quote = ch; quotedWord = true; continue; }
    if (ch === ';' || ch === '&' || ch === '|' || ch === '\n') { endSegment(ch); continue; }
    if (/\s/.test(ch)) { endWord(); continue; }
    current += ch;
  }
  endSegment('');

  // A quote left open at the end is not a command a shell would run — it is a syntax
  // error. Reading it as one long quoted argument is the dangerous reading: `echo "hi;
  // sudo id` then never splits on the `;` and the elevation disappears, which measured as
  // `privileged` before this tokeniser and `safe` after. So fall back to the scan that
  // treats the quote character as ordinary text, which splits and still sees `sudo id`.
  if (quote !== null) return tokenizeSegmentsDetailed(command, false);
  return segments;
}

/**
 * The command rebuilt from its tokens, for the regex rules to match against.
 *
 * Segments are rejoined with `; ` so a pattern cannot match across two commands that the
 * shell would run separately.
 */
let lastNormalizedInput: string | null = null;
let lastNormalizedOutput = '';

function normalizeCommand(command: string): string {
  // One evaluate asks for this about nineteen times, once per regex rule, and each ask
  // re-ran the tokeniser over the whole command. The asks arrive in a row on the same
  // input, so a one-entry cache removes almost all of it.
  if (command === lastNormalizedInput) return lastNormalizedOutput;
  lastNormalizedInput = command;
  lastNormalizedOutput = normalizeUncached(command);
  return lastNormalizedOutput;
}

function normalizeUncached(command: string): string {
  return tokenizeSegments(command)
    .map((words) => words.map((w) => (QUOTED_CONTENT.test(w) ? PLACEHOLDER : w)).join(' '))
    .join('; ');
}

/**
 * A character the tokeniser splits on or at, which a token can only hold if it was quoted.
 *
 * The tokeniser splits on unquoted separators and at unquoted whitespace, so a token
 * holding either came from inside quotes — the shell will not split there, and its contents are data. Rejoining it
 * into the pattern text is what makes an argument read as a command: `echo "hello; rm -rf
 * /"` prints a string, and normalising it produced `echo hello; rm -rf /`, which matched
 * the never-allowed list. Dropping those tokens keeps quote removal doing the job it was
 * added for — `rm -rf "/etc"`, whose tokens hold no separator — without letting a quoted
 * argument impersonate a command. A carrier that really does hand over a quoted command
 * (`sh -c "ls; rm -rf /etc"`) is read by `nestedCommands`, not by this.
 */
const QUOTED_CONTENT = /[\s;&|\n]/;

/**
 * What a quoted token becomes in the pattern text.
 *
 * Deleting it instead spliced its neighbours together and created an adjacency that appears
 * nowhere in the command: `echo rm 'a|b' -rf /` normalised to `echo rm -rf /` and landed on
 * the never-allowed list. A character no pattern contains and `\s` does not match stands in
 * its place, so the two sides can no longer be read as one phrase.
 */
const PLACEHOLDER = '\u0000';

/**
 * Try a regex against the command as written and against the tokenised form.
 *
 * Normalising alone is not enough. It rebuilds the command from tokens, so the shell
 * metacharacters between them are gone, and a pattern that matches across a separator no
 * longer fires — the fork bomb, whose `:|:&` needs the literal `|` and `&`, is the case
 * that shows this. Normalising is still what defeats `rm -rf "/etc"`. Neither form is a
 * superset of the other, so both are tried: for a pattern whose whole job is to notice
 * something, the union is the only direction that cannot lose a match.
 *
 * Deliberately scoped to regexes. The word-based rules in `FORBIDDEN_RULES` already
 * tokenise, and handing them the normalised string turns a separator that was safely
 * inside a quoted argument into a real one — `grep -E "warn|reboot" syslog` became an
 * unconditional refusal, which is the mention-vs-invocation bug of #91 all over again.
 */
function matchesEitherForm(command: string, test: (form: string) => boolean): boolean {
  return test(command) || test(normalizeCommand(command));
}

/**
 * The commands hiding inside a command.
 *
 * The elevation scan reads tokens produced by splitting on `;&|` and whitespace, so
 * it only ever saw the outer command: `echo $(sudo id)` tokenised to
 * `["echo", "$(sudo", "id)"]`, `echo` was taken to be the real command, and no
 * elevation was found (GHSA-v8jh-gv7v-3gvq). The destructive scan never had this
 * problem because it reads the raw text — which is why `echo $(rm -rf /)` was
 * classified correctly the whole time. This closes that asymmetry by pulling the
 * inner commands out so they can be classified in their own right.
 *
 * Four carriers, all of which a remote shell expands and runs:
 *   `$(...)`, backticks, process substitution `<(...)` / `>(...)`, and a shell
 *   given `-c`.
 *
 * @param speculativeOperands Whether the catch-all below — any multi-word,
 *   non-flag operand of a segment no more specific reader claimed — should be
 *   pushed. That catch-all is a guess about a binary this file does not
 *   recognise; the four carriers above are not guesses, the shell really does
 *   run what they hold, and are pushed regardless of this flag. Defaults to
 *   `true` for `classifyCommand`'s own recursion, where a guess may raise a
 *   command's *class* and leave role, tier and approval to weigh in.
 *   `findForbiddenMatch` passes `false`: its recursion feeds
 *   `FORBIDDEN_RULES`, the one unconditional denylist, and a guess must not
 *   be able to produce a refusal nobody can override (the maintainer's
 *   ruling — see the block comment above `findForbiddenMatch`). `$()`,
 *   backticks and `sh -c` are certain carriers and keep reaching the
 *   denylist either way.
 */
export function nestedCommands(command: string, speculativeOperands = true): string[] {
  const found: string[] = [];

  // `$(...)`, `<(...)`, `>(...)` — scanned rather than matched, because a regex
  // cannot balance parentheses and `echo $(echo $(sudo id))` is the case that
  // matters most.
  for (let i = 0; i < command.length; i++) {
    const opensSubstitution = command[i] === '$' && command[i + 1] === '(';
    const opensProcess = (command[i] === '<' || command[i] === '>') && command[i + 1] === '(';
    if (!opensSubstitution && !opensProcess) continue;

    // `$((1 + 1))` is arithmetic, not a command. Skipping it keeps the approval
    // prompt off `echo $((1 + 1))`.
    if (opensSubstitution && command[i + 2] === '(') continue;

    let depth = 0;
    for (let j = i + 1; j < command.length; j++) {
      if (command[j] === '(') depth++;
      else if (command[j] === ')') {
        depth--;
        if (depth === 0) {
          found.push(command.slice(i + 2, j));
          i = j;
          break;
        }
      }
    }
  }

  // Backticks. No nesting to balance — the shell requires escaping to nest them.
  const backticks = command.match(/`([^`]*)`/g);
  if (backticks) {
    for (const raw of backticks) found.push(raw.slice(1, -1));
  }

  // A carrier hands a program to something that runs it. Carries no substitution, so the
  // scan above does not see it. Read each segment's command word rather than scanning
  // every word: matching a mention rather than an invocation is #91, and
  // `cat /usr/bin/python3` names an interpreter without running one.
  const segments = tokenizeSegmentsDetailed(command);
  for (const { words } of segments) {
    // Every word, not just the command word. Stopping at the head lost the carrier behind
    // any wrapper this file does not list: `xargs -I {} sh -c 'sudo id'` stops on `{}`, and
    // `flock`, `chroot`, `nsenter` and `systemd-run` are not wrappers it knows — all six
    // went from `privileged` to `safe`. What keeps this from matching a *mention* is not
    // where it looks but what it requires: `programAfterFlag` returns null unless a
    // program-bearing flag actually follows, so `cat /usr/bin/python3` carries nothing.
    //
    // awk is handled below rather than in this loop, and the difference is the
    // point: this loop reads *every* word so a carrier behind an unlisted
    // wrapper is not lost, and doing that to awk is what made `man awk`
    // destructive. awk's program is a positional operand, so the only evidence
    // it was invoked is that it is the segment's command word (#184).
    const awk = awkFindings(words);
    for (const inner of awk?.commands ?? []) found.push(inner);
    // A pipe target is classified too, so `print … | "sudo tee /etc/passwd"`
    // still names `tee`. Whether the *direction* makes it worse is decided in
    // hasDangerousAwk, which is where this file already keeps that rule.
    for (const inner of awk?.pipedInto ?? []) found.push(inner);

    if (!operandsAreData(words)) {
      // Which operand *indices* an interpreter actually consumed as a program —
      // not whether the segment's head happens to be a name in the table, and not
      // a single segment-wide flag either. A set of indices rather than a boolean:
      // `unknownbin sh -c true 'sudo id'` has `sh -c` consume `true` (harmless,
      // pushed below) and leave `'sudo id'` untouched, and a boolean here defused
      // the catch-all for that second operand too — measured, it classified
      // `safe`. Only the specific word an interpreter actually read should be
      // excluded from the catch-all; every other operand in the segment is still
      // this binary's own, unclaimed by anything more specific.
      //
      // A binary being recognised is also not the same as this segment's
      // invocation of it being one the loop could parse:
      // `pwsh -ExecutionPolicy Bypass -Command 'sudo id'` has a recognised head
      // and a program on the line, but `-ExecutionPolicy` takes a value
      // (`Bypass`) that isn't itself a flag, and `programAfterFlag` gives up
      // rather than guess past it. Gating the catch-all below on "head is in the
      // table" excluded exactly the binaries this file just learned, and for
      // precisely the invocations its own flag-walk cannot follow — a net
      // regression, not a wash.
      const consumedOperands = new Set<number>();
      for (let i = 0; i < words.length; i++) {
        const spec = resolveInterpreter(stripPath(unquote(words[i])));
        // pwsh/powershell's own parameter binder resolves `-ENC`/`-Enc`/`-enc` to the
        // same parameter; every other interpreter's flags are exact letters (`-E` and
        // `-e` are different flags to perl). `-EncodedCommand` only ever appears on
        // the two entries whose own parameter binder works this way, so its presence
        // is the signal for which interpreter this is, not a hardcoded name check.
        const caseInsensitive = spec?.programBearingWords.includes('-EncodedCommand') ?? false;
        if (spec === undefined || isFlagValue(words, i, spec.programBearingWords, caseInsensitive)) continue;
        // Same signal, second job: pwsh/powershell's argument parser also does not stop
        // at an unrecognised option's bare value (`-ExecutionPolicy Bypass`) the way a
        // POSIX interpreter stops at its first positional argument. See
        // `programAfterFlag`'s `tolerateUnknownWordsAtHead` for why this is scoped to
        // `i === 0` there rather than here.
        const result = programAfterFlag(words, i, spec.programBearingWords, caseInsensitive, caseInsensitive);
        if (result !== null) {
          consumedOperands.add(result.index);
          found.push(result.program);
          // An encoded program is opaque to every text scan until it is decoded. Gated on
          // the word `programAfterFlag` actually matched — the table's own canonical
          // spelling, so every case-folded or clustered form of `-EncodedCommand`/`-e`
          // reaches this the same way a literal `-EncodedCommand` does — not a scan of
          // the whole segment for one long spelling.
          if (caseInsensitive && (result.flag === '-EncodedCommand' || result.flag === '-e')) {
            const decoded = decodedPowerShellCommand(result.program);
            if (decoded !== null) found.push(decoded);
          }
        }
      }

      // An operand of a binary nothing more specific has read is classified as a
      // command in its own right, rather than scanned as text.
      //
      // The gate is the awk reader's own result, and now which specific operands
      // an interpreter actually consumed, rather than a list of names: a name
      // list here would be the defect this change exists to fix
      // (GHSA-qmx6-47vm-3vf7), and "the head is a name in the table" turned out
      // to be one too — it answers a different question than "did this
      // invocation's program-bearing word actually resolve". `awk` is already
      // null for every non-awk segment.
      //
      // Whitespace is what separates an operand worth classifying from one that is
      // not: a single token is a path, a flag value or a subcommand, while a
      // multi-word operand has the shape of a command. Flags are skipped.
      //
      // Deliberately NOT a text scan for `sudo`. That version asserted elevations
      // the awk reader and the variable-command-word logic refuse to assert — both
      // cap at `destructive` on purpose — and it out-ranked the nested
      // classification that names the elevated binary, reporting `awk` where `id`
      // was correct.
      if (speculativeOperands && awk === null) {
        for (let i = 1; i < words.length; i++) {
          if (consumedOperands.has(i)) continue;
          if (words[i].startsWith('-')) continue;
          if (/\s/.test(words[i])) found.push(words[i]);
        }
      }
    }

    // `-exec` is a flag rather than a command word, so this one is still a scan.
    for (let i = 0; i < words.length; i++) {
      if (!FIND_EXEC_FLAGS.has(words[i]) || words[i + 1] === undefined) continue;
      const rest = words.slice(i + 1);
      const stop = rest.findIndex((w) => w === '+' || w === ';');
      found.push((stop === -1 ? rest : rest.slice(0, stop)).join(' '));
      // Step past what was consumed. Leaving `i` where it was emitted one child per
      // `-exec` token, each an overlapping suffix of the last and each still holding the
      // rest of them, so the recursion re-expanded the same tail once per token: twenty
      // `-ok` tokens in 81 bytes cost 17 seconds of a single-threaded event loop.
      i = stop === -1 ? words.length : i + 1 + stop;
    }
  }

  // A pipe stage whose command word is an interpreter with no program of its own runs
  // whatever the previous stage printed. Starts at 1: a leading `|` records its separator
  // on the first segment, and reading `segments[-1]` threw.
  for (let i = 1; i < segments.length; i++) {
    if (segments[i].sep !== '|') continue;
    if (!readsProgramFromStdin(segments[i].words)) continue;
    found.push(segments[i - 1].words.join(' '));
  }

  return found.filter((c) => c.trim().length > 0);
}

const PRIVILEGE_PREFIXES = new Set([
  'sudo', 'su', 'doas', 'pkexec',
  // BusyBox/Alpine, Docker entrypoints, the Rust sudo now default on some
  // distributions, systemd's replacement, and the Solaris/illumos spelling.
  'su-exec', 'gosu', 'sudo-rs', 'run0', 'pfexec',
  // Both reach root with the command otherwise classified `safe`.
  'runuser', 'setpriv',
]);

/**
 * Binaries whose job is to run another command.
 *
 * The allowlist and the privilege check both name a binary, so a wrapper hides
 * whatever it wraps: `env sudo id` was classified by the name `env`. These are
 * stepped over when deciding whether a segment elevates, so the check sees the
 * command that will actually run.
 *
 * `env` is the one that was also allowlisted, and it has been removed from
 * READ_ONLY_ALLOWLIST above. The rest were never read-only, so before this they
 * hid elevation rather than granting it — `nohup sudo systemctl stop nginx`
 * classified `safe`, which the default bindings grant to admin and operator on
 * every tier.
 */
const EXEC_WRAPPERS = new Set([
  'env', 'nohup', 'nice', 'ionice', 'command', 'exec', 'setsid', 'stdbuf',
  'timeout', 'chrt', 'taskset', 'xargs', 'watch',
  // `busybox <applet>` runs the applet, so it wraps rather than interprets.
  'busybox',
]);

/**
 * Arguments that turn an allowlisted binary into one that writes or executes.
 *
 * The allowlist vouches for a name; these are the flags that make the name a
 * lie. `find /var/www -delete` removes a directory tree and `find / -exec sudo
 * id +` runs a command as root, and both classified `read-only` — the `-exec …
 * \;` form only escaped because `;` happens to be a shell metacharacter, while
 * the `+` terminator carries none.
 */
// Null-prototype for the same reason as INTERPRETERS: indexed by the command word.
const DISQUALIFYING_ARGS: Record<string, RegExp> = Object.assign(
  Object.create(null) as Record<string, RegExp>,
  {
    find: /^-(exec|execdir|ok|okdir|delete|fprintf?|fls)$/,
    // GNU sort execs this for every temporary file it spills, so a reader
    // becomes a launcher. Measured against coreutils 9.11: an attacker-named
    // script ran 14,224 times for one 200k-line input, and the whole command
    // classified `read-only` — which a `readOnly` viewer is allowed to run,
    // while running that same program directly is denied.
    //
    // `-o FILE` / `--output=FILE` is the same shape of bug with a plainer
    // payoff: it creates and truncates FILE, which is a write a `readOnly`
    // profile must never reach through a command classified `read-only`.
    // Measured on HEAD before this rule: `sort -o /root/.ssh/authorized_keys
    // /tmp/key.pub` classified `read-only`.
    //
    // Three spellings, joined by the same alternation as `--compress-program`:
    // `--output=X` (one argument), `--output X` (two, flag alone), and the
    // short form, which GNU getopt lets cluster behind other single-letter
    // flags (`sort -nro out in` writes `out` exactly as `sort -o out in`
    // does) or attach its value directly (`-oFILE`).
    //
    // The cluster branch is deliberately narrower than "any `o` in a dash
    // word": `-[bcCdfghiMnRrsuVz]*o` only allows GNU sort's own *argument-less*
    // short flags ahead of the `o`, so it stops at the first flag that takes a
    // value of its own. Without that, `-tofile` — `-t` (field separator) with
    // its value attached, not `-o` — would be misread as a write. `-t`, `-k`,
    // `-S` and `-T` are exactly the short flags this excludes, because each
    // consumes the rest of a clustered word as its own argument, so a
    // following `o` is that argument's text, not `-o` invoked.
    sort: /^(--compress-program(=|$)|--output(=|$)|-[bcCdfghiMnRrsuVz]*o)/,
  },
);

/** A leading `NAME=value`, which a shell treats as an assignment, not a command. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** `timeout 5s`, `nice 10` — a bare argument some wrappers take before the command. */
const BARE_NUMERIC = /^\d+(\.\d+)?[smhd]?$/;

/**
 * Remove the quoting a shell would remove before looking up a command.
 *
 * `\sudo`, `'sudo'` and `"sudo"` all execute sudo — the backslash only
 * suppresses alias expansion — but a verbatim string comparison sees three
 * different words. Without this, a one-character edit walks around the check.
 */
function unquote(word: string): string {
  return word.replace(/^(['"])(.*)\1$/, '$2').replace(/\\(.)/g, '$1');
}

/**
 * Privilege-prefix flags that consume the next argument, so `sudo -u root
 * reboot` is not read as invoking `root`. Enumerable because it is one tool's
 * option set, unlike "every flag of every binary".
 */
const PREFIX_VALUE_FLAGS = new Set([
  '-u', '-g', '-p', '-C', '-h', '-r', '-t', '-U', '-c',
  '--user', '--group', '--prompt', '--close-from', '--host', '--role', '--type',
  '--other-user', '--command',
]);

/** `/sbin/reboot` and `reboot` are the same invocation. */
function stripPath(word: string): string {
  const slash = word.lastIndexOf('/');
  return slash === -1 ? word : word.slice(slash + 1);
}

/**
 * The command words a shell would actually execute — the head of every
 * `;`/`&&`/`||`/`|`/newline-separated segment, past any privilege prefix, plus
 * the arguments of a multiplexer like `systemctl`.
 *
 * Pure string work: split, trim, set lookups. No quantifiers, so nothing here
 * can backtrack.
 */
interface Segment {
  /** The binary being run, with any directory part and privilege prefix removed. */
  head: string;
  /** Everything after it, verbatim — `of=/dev/sda` must not be path-stripped. */
  args: string[];
}

function parseSegments(command: string): Segment[] {
  const segments: Segment[] = [];
  for (const words of tokenizeSegments(command)) {
    const segment = parseWords(words);
    if (segment !== null) segments.push(segment);
  }
  return segments;
}

/** The same, for callers that already hold the tokenised words. */
function parseWords(words: string[]): Segment | null {
  {
    let i = 0;
    while (i < words.length && PRIVILEGE_PREFIXES.has(stripPath(words[i]))) {
      i++;
      while (i < words.length && words[i].startsWith('-')) {
        const consumesValue = PREFIX_VALUE_FLAGS.has(words[i]);
        i++;
        if (consumesValue) i++;
      }
    }

    if (i < words.length) {
      return { head: stripPath(words[i]), args: words.slice(i + 1) };
    }
  }
  return null;
}

/**
 * Whether a segment asks for elevation, reading past anything that is not yet
 * the command.
 *
 * A shell resolves the command word after assignments, and a wrapper runs what
 * follows it, so all of these execute sudo while naming something else first:
 *
 *   env sudo id            nohup sudo id         timeout 5 sudo id
 *   FOO=1 sudo id          nice -n 10 sudo id    command sudo id
 *
 * The scan walks left to right and stops at the first word that is a real
 * command. Reaching a privilege prefix before that is elevation; reaching
 * anything else is not, which is what keeps `grep sudo /var/log/auth.log` a
 * mention rather than an invocation.
 */
function elevatedBinary(words: string[]): string | null {
  let i = 0;
  let prefix: string | null = null;

  while (i < words.length) {
    const raw = words[i];
    const word = stripPath(unquote(raw));

    if (PRIVILEGE_PREFIXES.has(word)) {
      prefix ??= word;
      i++;
      // The prefix's own options, some of which swallow the next word.
      while (i < words.length && words[i].startsWith('-')) {
        const consumesValue = PREFIX_VALUE_FLAGS.has(words[i]);
        i++;
        if (consumesValue) i++;
      }
      continue;
    }

    // Words that are not yet the command: an assignment, a wrapper, an option,
    // or the bare number `timeout`/`nice` take before theirs.
    if (ASSIGNMENT.test(raw) || EXEC_WRAPPERS.has(word)
      || raw.startsWith('-') || BARE_NUMERIC.test(raw)) {
      i++;
      continue;
    }

    // A real command. Before any prefix it means the segment does not elevate —
    // which is what keeps `grep sudo /var/log/auth.log` a mention. After one, it
    // is what actually runs as root.
    return prefix === null ? null : word;
  }

  // `sudo`, or `sudo -u root`, with nothing after it: the prefix is all there is
  // to name.
  return prefix;
}

/**
 * The binary this command runs under elevation, or null if it runs none.
 *
 * Returning the name rather than a boolean is what lets `ParsedCommand.binary`
 * describe the same command the class does. Until 2.2.4 a `privileged` class
 * implied a leading prefix, so the anchored `extractBinary` always named the
 * elevated binary; once elevation could be found in any segment that stopped
 * holding, and `echo hi; sudo id` recorded `binary: "echo"` against a
 * privileged decision — in the audit log, the OTel span and OPA's input (#134).
 */
function elevatedBinaryOf(command: string): string | null {
  for (const words of tokenizeSegments(command)) {
    const found = elevatedBinary(words);
    if (found !== null) return found;
  }
  return null;
}


/**
 * Does this command elevate anywhere a shell would act on it?
 *
 * Replaces four `^`-anchored regexes that only saw a *leading* prefix. Elevation
 * behind a wrapper, behind an assignment, or after a separator all reached root
 * with the command classified `safe` or `read-only`.
 */


/** An allowlisted binary carrying a flag that makes it write or execute. */
function hasDisqualifyingArgs(command: string): boolean {
  return parseSegments(command).some(({ head, args }) => {
    const rule = DISQUALIFYING_ARGS[head];
    return rule !== undefined && args.some((arg) => rule.test(arg));
  });
}

function invokedWords(command: string): string[] {
  const invoked: string[] = [];

  for (const { head, args } of parseSegments(command)) {
    invoked.push(head);

    // `systemctl reboot` restarts the host. Reading a unit that happens to be
    // named after a power action is rare enough that erring towards refusal
    // here costs little.
    if (ACTION_MULTIPLEXERS.has(head)) {
      invoked.push(...args.filter((w) => !w.startsWith('-')).map(stripPath));
    }
  }

  return invoked;
}

const SHELLS = new Set(['sh', 'bash', 'zsh']);
const DOWNLOADERS = new Set(['curl', 'wget']);

/**
 * A download piped into a shell.
 *
 * Split on `|` rather than reading the whole string, so cost is linear in the
 * command's length no matter how the two halves are spaced. `||` produces an
 * empty part between them, and this deliberately still matches: `curl x || sh`
 * runs a shell when the download fails, which is not meaningfully safer than
 * running one when it succeeds.
 */
function pipesDownloadIntoShell(command: string): boolean {
  // One head per pipe stage. Splitting on every separator would make `curl -O x;
  // bash build.sh` — download, then run a local script — match a rule whose label says
  // "piping a download into a shell", on a list that cannot be switched off.
  const segments = tokenizeSegmentsDetailed(command);
  const heads = segments
    .filter((segment, i) => i === 0 || segment.sep === '|')
    .map((segment) => parseWords(segment.words)?.head);
  const firstDownload = heads.findIndex((h) => h !== undefined && DOWNLOADERS.has(h));
  if (firstDownload === -1) return false;
  return heads.slice(firstDownload + 1).some((h) => h !== undefined && SHELLS.has(h));
}

/** `dd … of=/dev/sda` — writing an image straight onto a block device. */
function writesToDevice(command: string): boolean {
  return parseSegments(command).some(
    ({ head, args }) => head === 'dd' && args.some((a) => a.startsWith('of=/dev/')),
  );
}

/**
 * `chown -R … /` — a recursive chown whose target is the filesystem root.
 *
 * The last non-flag argument is the target; `chown -R app:app /srv/app` is
 * ordinary and stays allowed.
 */
function chownsRoot(command: string): boolean {
  return parseSegments(command).some(({ head, args }) => {
    if (head !== 'chown' || !args.includes('-R')) return false;
    const positional = args.filter((a) => !a.startsWith('-'));
    return positional[positional.length - 1] === '/';
  });
}

/** A forbidden rule, paired with wording a refusal can quote back. */
interface ForbiddenRule {
  label: string;
  test: (command: string) => boolean;
}

const FORBIDDEN_RULES: ForbiddenRule[] = [
  ...FORBIDDEN_PATTERNS.map((re) => ({
    label: String(re),
    test: (c: string) => matchesEitherForm(c, (form) => re.test(form)),
  })),
  {
    label: 'invoking a power-state command (shutdown, reboot, halt, poweroff) or eval',
    test: (command) => invokedWords(command).some((w) => FORBIDDEN_INVOCATIONS.has(w)),
  },
  {
    label: 'piping a download into a shell (curl or wget into sh, bash or zsh)',
    test: pipesDownloadIntoShell,
  },
  { label: 'dd writing to a block device (of=/dev/…)', test: writesToDevice },
  { label: 'a recursive chown of the filesystem root', test: chownsRoot },
];

/**
 * Which never-allowed rule this command trips, or null. The single entry point:
 * FORBIDDEN_PATTERNS is deliberately not exported, because half of the list
 * lives in FORBIDDEN_RULES and a caller checking only the regexes would quietly
 * permit `sudo reboot`.
 */
export function findForbiddenMatch(command: string, depth = 0): string | null {
  for (const rule of FORBIDDEN_RULES) {
    if (rule.test(command)) return rule.label;
  }

  // The same carriers the class scan reads, for the same reason. This list is the
  // one unconditional rule in the policy — forbidden regardless of role, tier or
  // approval — and it was decided from the outer command alone, so
  // `sh -c "shutdown -h now"` and `echo $(shutdown -h now)` were not forbidden.
  // They still classified `destructive`, which on the `prod` tier degrades an
  // absolute `deny` into `require-approval`: a rule that answers "never" became
  // one a human can click through.
  //
  // `speculativeOperands: false` — the maintainer's ruling. `nestedCommands`'
  // catch-all is a guess about an unrecognised binary's operands, and this loop
  // feeds the one unconditional rule in the policy: a guess may raise a
  // command's class, which role, tier and approval still get to weigh in on,
  // but it must not manufacture a refusal nobody can override. Measured before
  // this parameter existed: `git commit -m 'reboot the worker pool'` was a hard
  // deny on an admin profile with `approvalPolicy: 'auto'`, because the catch-all
  // read the quoted commit message as an operand starting with a forbidden word.
  // `$()`, backticks and `sh -c` are certain carriers, not guesses — the shell
  // really does run what they hold — and are unaffected: they are pushed by
  // `nestedCommands` regardless of this flag.
  if (depth >= MAX_NESTING_DEPTH) return null;
  for (const inner of nestedCommands(command, false)) {
    const match = findForbiddenMatch(inner, depth + 1);
    if (match !== null) return match;
  }
  return null;
}

export function isForbidden(command: string): boolean {
  return findForbiddenMatch(command) !== null;
}

/**
 * Commands that are destructive but legitimate under approval — e.g.
 * `rm -rf /tmp/build`, which must NOT be confused with `rm -rf /`.
 */
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /rm\s+-rf?\s+\//,
];

/**
 * Everything that classifies as destructive: forbidden commands included.
 *
 * Goes through isForbidden() rather than the regex list, so a command caught by
 * an invocation rule is classified destructive too — and, just as importantly,
 * reading a log that mentions `reboot` is no longer classified destructive
 * either.
 */
function isDestructive(command: string): boolean {
  return (
    isForbidden(command) ||
    matchesEitherForm(command, (form) => DESTRUCTIVE_PATTERNS.some((re) => re.test(form)))
  );
}

const LEADING_PRIVILEGE_PREFIXES = [
  /^\s*sudo\b/,
  /^\s*su\b/,
  /^\s*doas\b/,
  /^\s*pkexec\b/,
];

export function extractBinary(command: string): string {
  // The first segment's words, so quoting is resolved — `s"u"do id` used to report
  // `s"u"do` in the audit record and the refusal message. Reading the normalised whole
  // command instead would be wrong in the other direction: it rejoins segments with
  // `; `, so `ls | grep x` would report `ls;`, and this name reaches the audit record,
  // the OTel span and OPA's input (#134). A separator is not a binary.
  let cmd = (tokenizeSegments(command)[0] ?? []).join(' ').trim();
  for (const prefix of LEADING_PRIVILEGE_PREFIXES) {
    cmd = cmd.replace(prefix, '').trim();
  }
  if (cmd.startsWith('-c ')) {
    cmd = cmd.slice(3).trim();
  }
  const parts = cmd.split(/\s+/);
  return parts[0] || '';
}

/**
 * The word a segment will actually execute, read past anything that is not it.
 *
 * Distinct from `elevatedBinary`, which answers "does this ask for elevation".
 * This answers "what is the name of the thing that runs", so it can be asked
 * whether that name is knowable at all.
 */
function effectiveCommandWord(words: string[]): string | null {
  const i = effectiveCommandIndex(words);
  return i === -1 ? null : words[i];
}

/**
 * The position of that word, for callers that need to read its arguments.
 *
 * Deriving the word from the index rather than searching for it afterwards is what keeps
 * `sh x sh -c 'sudo id'` from finding the wrong `sh`.
 */
function effectiveCommandIndex(words: string[]): number {
  let i = 0;
  while (i < words.length) {
    const raw = words[i];
    const word = stripPath(unquote(raw));

    if (PRIVILEGE_PREFIXES.has(word) || EXEC_WRAPPERS.has(word)) {
      i++;
      while (i < words.length && words[i].startsWith('-')) {
        const consumesValue = PREFIX_VALUE_FLAGS.has(words[i]);
        i++;
        if (consumesValue) i++;
      }
      continue;
    }
    if (ASSIGNMENT.test(raw) || raw.startsWith('-') || BARE_NUMERIC.test(raw)) {
      i++;
      continue;
    }
    return i;
  }
  return -1;
}

/**
 * Whether this segment's command word is one whose operands are data.
 *
 * The carrier scan reads every word, because a wrapper this file does not list would
 * otherwise hide `sh -c`. The cost is that an outer tool's own flag can be mistaken for an
 * interpreter's: `grep python3 -c /var/log/x` counts lines, and `-c` is also python's
 * program flag. An allowlisted command is one this file already vouches for as reading
 * rather than running, so its arguments are subjects, not commands — the positive form of
 * the mention-vs-invocation rule at #91. `find` keeps its `-exec` scan, which is separate.
 */
function operandsAreData(words: string[]): boolean {
  const idx = effectiveCommandIndex(words);
  if (idx === -1) return false;
  return READERS[stripPath(unquote(words[idx]))]?.operandsAreData === true;
}

/**
 * Whether an interpreter name is the value of the flag before it rather than a command.
 *
 * The scan looks at every word so that a carrier behind an unlisted wrapper is not lost,
 * and requires a program-bearing flag to follow before it believes one. That is not quite
 * enough: `grep -e perl -e python` puts `perl` after a flag and a second `-e` after it,
 * which reads as perl being handed a program. A search term is not a command.
 *
 * The test is deliberately narrow — the preceding flag must be one of *this interpreter's*
 * program flags. Any flag at all was too much: `nsenter -t 1 -m sh -c 'sudo id'` puts the
 * shell after `-m`, which takes no value, and dropping it lost a real elevation. Nothing
 * here can know an arbitrary tool's grammar, so `sed -n perl -e p` — a shape no one
 * writes — is still read as a carrier.
 */
/**
 * Words that may sit between an interpreter and its program flag.
 *
 * A quoted empty word survives tokenization now, because a positional reader
 * cannot work with an argument list that silently drops operands. That made an
 * empty word break this chain: `sh '' -c 'sudo id'` stopped finding the program
 * and fell from `privileged` to `safe`. Real `sh` does not run it either — it
 * reports "No such file or directory" and exits, measured — but over-reporting a
 * command that fails costs nothing and under-reporting one is the whole hazard,
 * so the chain keeps the answer it had.
 */
function skippableBetweenFlags(word: string): boolean {
  return word === '' || word.startsWith('-');
}

/**
 * Whether `word` is a spelling of `flag`, honouring case-insensitivity when asked.
 *
 * Scoped per call, never globally: pwsh/powershell's own parameter binder resolves
 * `-ENC`, `-Enc` and `-enc` to the same parameter, but `-E` and `-e` are two different
 * flags to perl. Every caller here is told explicitly, per invocation, whether the
 * interpreter it is matching against is one of the case-insensitive ones — folding case
 * is never the default.
 */
function sameFlag(word: string, flag: string, caseInsensitive: boolean): boolean {
  return caseInsensitive ? word.toLowerCase() === flag.toLowerCase() : word === flag;
}

function isFlagValue(words: string[], i: number, flags: string[], caseInsensitive = false): boolean {
  if (i === 0) return false;
  const previous = words[i - 1];
  if (!(previous.length > 1 && previous.startsWith('-'))) return false;
  return flags.some((f) => sameFlag(previous, f, caseInsensitive));
}

/**
 * A program an interpreter was handed on its command line, and the word that carried it.
 */
interface FlaggedProgram {
  program: string;
  /**
   * The canonical entry of `flags` that matched — the spelling in the table, not
   * necessarily the literal word on the command line. `-EC` case-insensitively matches
   * `-e`, and this reports `-e`, so a caller comparing against the table's own spellings
   * (deciding whether to decode, say) never has to re-derive which flag a case-folded or
   * clustered word stood for.
   */
  flag: string;
  /**
   * The index into `words` of the word that carried `program` — the whole word, whether
   * the program is that word verbatim or embedded in it (`-csudo id` attaches the program
   * to the flag's own word, so `index` names that word, not a later one). A caller tracking
   * which operands an interpreter actually consumed, rather than merely "some interpreter
   * consumed something in this segment", needs the position, not just the text.
   */
  index: number;
}

/**
 * The program an interpreter was handed on its command line, or null.
 *
 * Only flags may sit between the interpreter and its flag; anything else means this was
 * not that kind of invocation, which is what keeps `python3 script.py` — a program this
 * cannot read either, but one every deployment runs — out of the gate. That rule holds
 * for every interpreter here except pwsh/powershell (see `tolerateUnknownWordsAtHead`):
 * real POSIX interpreters stop parsing their own options at the first positional
 * argument — `python3 script.py -c 'evil'` hands `-c evil` to the script as `argv`, not
 * to python — so treating a bare word as "not this kind of invocation" is correct for
 * them, not merely convenient.
 *
 * Returns which of `flags` matched alongside the program, not just the program text, so
 * a caller can tell `-EncodedCommand` from its `-e` abbreviation apart from every other
 * program-bearing word — decoding is specific to that one flag, and both spellings reach
 * here as an ordinary match.
 *
 * @param tolerateUnknownWordsAtHead pwsh/powershell's own argument parser walks the
 *   whole command line looking for named parameters it recognises and does not stop at
 *   an unrecognised one's value (`-ExecutionPolicy Bypass`) the way a POSIX interpreter
 *   stops at its first positional argument. Only takes effect when `from` is the
 *   segment's *effective* command word — `effectiveCommandIndex(words)`, which reads
 *   past a privilege prefix or an exec wrapper (`env`, `nohup`, `timeout`, …), not merely
 *   position 0. `from === 0` missed exactly the shape those wrappers exist to describe:
 *   `env pwsh -ExecutionPolicy Bypass -EncodedCommand …` put `pwsh` at index 1, the
 *   tolerance never engaged, and the interpreter loop's own flag-walk gave up at
 *   `Bypass` before ever reaching `-EncodedCommand` — classified `safe`. Still unambiguous
 *   about *which* word is being invoked, not a value or a search term this file has no
 *   business reinterpreting (`grep -e perl -e python` never reaches here with this set,
 *   because `perl` is not the segment's effective command word and isn't pwsh-family
 *   regardless; nor is `customtool --search pwsh …`, where `customtool` is). Structural,
 *   not a list of pwsh's value-taking flags: this file does not need to know
 *   `-ExecutionPolicy` exists to stop being confused by it.
 */
function programAfterFlag(
  words: string[], from: number, flags: string[], caseInsensitive = false,
  tolerateUnknownWordsAtHead = false,
): FlaggedProgram | null {
  const tolerateUnknownWords = tolerateUnknownWordsAtHead && from === effectiveCommandIndex(words);
  for (let j = from + 1; j < words.length; j++) {
    const word = words[j];
    const exact = flags.find((f) => sameFlag(word, f, caseInsensitive));
    if (exact !== undefined) {
      // A subcommand — a program-bearing word that is not itself a `-` flag, such as
      // `deno`'s `eval` — may still have its own options before the code: `deno eval
      // --unstable <code>` is one invocation, not two. A real flag like `-c` or
      // `-Command` never has anything of its own between it and the program, so this
      // only widens the subcommand case.
      let k = j + 1;
      if (!exact.startsWith('-')) {
        while (k < words.length && skippableBetweenFlags(words[k])) k++;
      }
      const program = words[k];
      return program === undefined ? null : { program, flag: exact, index: k };
    }
    // Deliberately case-SENSITIVE even for pwsh/powershell: this branch exists for a
    // value glued directly onto a short flag with no separating space (`-csudo id`).
    // Folding case here as well made `-ExecutionPolicy` — a real pwsh option this file
    // does not otherwise track — case-insensitively start with `-e` and get read as
    // `-e` plus an attached `xecutionPolicy`, which swallowed `-ExecutionPolicy Bypass
    // -Command 'sudo id'` into `destructive` and, worse, made `foundProgram` true so
    // the catch-all below never ran. Every case-insensitive spelling the table needs
    // to accept (`-enc`, `-ec`, `-EC`, `-ENC`, `-E`, `-EncodedCOMMAND`, `-COMMAND`,
    // `-C`, …) is already reached through the exact match above or the cluster match
    // below, so this branch does not need to fold case to cover them.
    const attached = flags.find((f) => word.startsWith(f) && word.length > f.length);
    if (attached !== undefined) {
      const rest = word.slice(attached.length);
      // `sh -c'sudo id'` tokenises to `-csudo id`, so the program is attached. `bash -cx`
      // is a flag cluster and the program is the next word. A space, or the `=` of
      // `--eval=…`, is what tells them apart: a cluster is letters only.
      if (/\s/.test(rest) || rest.startsWith('=')) {
        return { program: rest.replace(/^=/, ''), flag: attached, index: j };
      }
      const program = words[j + 1];
      return program === undefined ? null : { program, flag: attached, index: j + 1 };
    }
    // The program flag need not lead the cluster: `bash -xc 'sudo id'` runs exactly what
    // `bash -cx 'sudo id'` runs, and a prefix test saw the second and missed the first.
    const clusterFlag = clusterCarriesFlag(word, flags, caseInsensitive);
    if (clusterFlag !== null) {
      const program = words[j + 1];
      return program === undefined ? null : { program, flag: clusterFlag, index: j + 1 };
    }
    if (!skippableBetweenFlags(word) && !tolerateUnknownWords) return null;
  }
  return null;
}

/** How much base64 is worth decoding before the answer stops changing. */
const MAX_ENCODED_CHARS = 64 * 1024;

/**
 * The command inside `-EncodedCommand`, or null.
 *
 * PowerShell encodes UTF-16LE, so decoding as utf8 yields text with a NUL between
 * every character and no pattern matches it. `Buffer.from(x, 'base64')` never
 * throws — it drops characters outside the alphabet — so malformed input produces
 * a wrong answer rather than an exception, and the caller must treat null and
 * nonsense alike: the flag alone has already made the command `destructive`.
 *
 * Reads a bounded, 4-aligned PREFIX rather than refusing outright past the limit. A
 * refusal is a downgrade path: it turns "pad the payload past 64 KiB" into a way to
 * trade `privileged` for `destructive`, which is strictly better for whoever is padding
 * it. 4-aligned because base64 decodes in groups of four characters to three bytes;
 * truncating mid-group corrupts the last partial character instead of just dropping
 * trailing content the decode was never going to reach anyway.
 */
function decodedPowerShellCommand(operand: string): string | null {
  const prefix = operand.length > MAX_ENCODED_CHARS
    ? operand.slice(0, MAX_ENCODED_CHARS - (MAX_ENCODED_CHARS % 4))
    : operand;
  const decoded = Buffer.from(prefix, 'base64').toString('utf16le');
  return decoded.includes('�') || decoded.trim() === '' ? null : decoded;
}

/**
 * What follows a short flag inside a single-dash cluster, or the `flags` entry it
 * carries, or null if it carries none.
 *
 * Clusters only — a run of single letters after one dash. Long flags and attached values
 * are handled before this is reached. Returns the canonical flag rather than a boolean
 * for the same reason `programAfterFlag` does: a caller deciding whether to decode
 * compares against the table's own spellings, not against whatever letters happened to
 * be clustered together.
 */
function clusterCarriesFlag(word: string, flags: string[], caseInsensitive = false): string | null {
  // Three letters at most. `/^-[A-Za-z]+$/` alone also matches every single-dash long
  // option, and `find`'s predicates are full of them: `-type` contains perl's `-e`, so
  // `find . -name perl -type f` read as a carrier and asked for approval.
  if (!/^-[A-Za-z]{2,3}$/.test(word)) return null;
  const body = caseInsensitive ? word.slice(1).toLowerCase() : word.slice(1);
  const shortFlags = flags.filter((flag) => flag.length === 2);
  // A cluster is letters only, so whatever follows the program flag is more flags — the
  // program itself is always the next word.
  //
  // Scanned by the BODY's own character order, not the table's order: `-ec` must
  // resolve to `-e` (so a caller deciding whether to decode sees `-e`), not to `-c`
  // just because `-c` happens to sit first in pwsh's `programBearingWords`. The first
  // letter in the cluster is the one the invocation leads with.
  for (const letter of body) {
    const match = shortFlags.find((flag) => (caseInsensitive ? flag[1].toLowerCase() : flag[1]) === letter);
    if (match !== undefined) return match;
  }
  return null;
}

/** Spellings of "the program is on standard input" that look like a file operand. */
const STDIN_PATHS = new Set(['-', '/dev/stdin', '/dev/fd/0', '/proc/self/fd/0']);

/**
 * Whether a segment's command word is an interpreter with no program of its own.
 *
 * `echo "sudo id" | bash` hands the program over on stdin, where there is nothing to
 * read. This holds for the shells too — `readable` is about a `-c` argument, and there is
 * no `-c` here. Requiring that no operand follow is what keeps `cat data | python3
 * app.py` out of it: there the pipe carries data, not a program.
 */
function readsProgramFromStdin(words: string[]): boolean {
  const idx = effectiveCommandIndex(words);
  if (idx === -1) return false;
  const bin = stripPath(words[idx]);
  // Interpreters only. awk's one program-from-stdin form is `awk -f -`, already gated as a
  // file flag; every other piped awk reads data, not a program.
  const spec = resolveInterpreter(bin);
  if (spec === undefined) return false;
  const flags = spec.programBearingWords;
  let sawStdinFlag = false;
  for (let j = idx + 1; j < words.length; j++) {
    const word = words[j];
    if (flags.some((f) => word === f || word.startsWith(f))) return false;
    // `--` ends the interpreter's own arguments; what follows is `$1..$n`, so a program
    // still has to come from somewhere and `bash -s -- arg` reads stdin.
    // `-s` says outright that the script comes from stdin, so everything after it is
    // `$1..$n` whatever it looks like.
    if (word === '-s') { sawStdinFlag = true; continue; }
    // `--` ends the interpreter's own arguments. Without `-s` the next word is the script
    // itself, so `bash -- process.sh` reads a file while `bash -s -- arg` reads stdin.
    if (word === '--') {
      const next = words[j + 1];
      return sawStdinFlag || next === undefined || STDIN_PATHS.has(next);
    }
    if (STDIN_PATHS.has(word)) return true;
    if (!word.startsWith('-')) return false;
  }
  return true;
}

/**
 * Whether any segment hands a program to something this file cannot read.
 *
 * Keyed on the segment's command word, never on any word that happens to name an
 * interpreter: matching a mention rather than an invocation is the defect this file
 * records fixing as #91, and `cat /usr/bin/python3` names an interpreter without running
 * one. A program-bearing flag must actually be present, so naming one is not enough.
 */
/**
 * What this segment's awk program does, or null when it runs no awk program.
 *
 * Keyed on `effectiveCommandIndex` — the word that actually runs — never on any
 * word that happens to say "awk". `readlink -f /usr/bin/awk` and `man awk` name
 * an interpreter without invoking one, and an earlier attempt that scanned every
 * word classified both destructive.
 */
function awkFindings(words: string[]): AwkFindings | null {
  const idx = effectiveCommandIndex(words);
  if (idx === -1) return null;
  if (!AWK_NAMES.has(stripPath(unquote(words[idx])))) return null;
  // No second `unquote`. `tokenizeSegmentsDetailed` has already resolved shell
  // quoting, and inside single quotes a backslash is literal — so the program
  // word arrives exactly as awk will see it. Unquoting again ran
  // `.replace(/\\(.)/g, '$1')` over the *awk program*, which deleted the
  // backslash of every escape it contains. Measured, all three ways that broke:
  // `system("\163udo id")` became `system("163udo id")` and classified `safe`;
  // `s="\""` collapsed and re-paired the string delimiters so the code between
  // them was read as string content; and `print "\\"` became an unterminated
  // string, gating ordinary awk as unreadable.
  return readAwkInvocation(words.slice(idx + 1));
}

/**
 * Whether any segment's awk program writes a file, or could not be read.
 *
 * The commands an awk program hands to a shell are not here: `nestedCommands`
 * emits those so they are classified as themselves, which is how
 * `awk 'BEGIN{system("sudo id")}'` comes out `privileged` rather than flattened
 * to the `destructive` this function reports.
 */
function hasDangerousAwk(command: string): boolean {
  for (const { words } of tokenizeSegmentsDetailed(command)) {
    const findings = awkFindings(words);
    if (findings === null) continue;
    if (findings.writesFile || findings.unreadable) return true;
    // `print … | "sh"` is the awk spelling of `echo "sudo id" | sh`, which this
    // file already gates through `readsProgramFromStdin`. Classifying the target
    // alone says `sh`, which is not dangerous; what is dangerous is what awk
    // prints into it, and that is assembled at run time. So it is the same
    // "we cannot tell" this module reports for `-f progfile`.
    for (const target of findings.pipedInto) {
      const stage = tokenizeSegmentsDetailed(target)[0];
      if (stage !== undefined && readsProgramFromStdin(stage.words)) return true;
    }
  }
  return false;
}

function hasUnreadableProgram(command: string): boolean {
  const segments = tokenizeSegmentsDetailed(command);
  for (let i = 0; i < segments.length; i++) {
    const { words, sep } = segments[i];
    if (sep === '|' && readsProgramFromStdin(words)) return true;

    if (!operandsAreData(words)) {
      for (let j = 0; j < words.length; j++) {
        const spec = resolveInterpreter(stripPath(unquote(words[j])));
        if (spec === undefined || spec.readable) continue;
        // Same case-insensitivity as `nestedCommands`'s interpreter loop, and for the
        // same reason: pwsh/powershell's own parameter binder does not distinguish
        // `-EC` from `-ec`, so neither should this.
        const caseInsensitive = spec.programBearingWords.includes('-EncodedCommand');
        if (isFlagValue(words, j, spec.programBearingWords, caseInsensitive)) continue;
        if (programAfterFlag(words, j, spec.programBearingWords, caseInsensitive, caseInsensitive) !== null) return true;
      }
    }

  }
  return false;
}

/**
 * Whether any segment runs a command this process cannot name.
 *
 * The class — and with it the approval gate — is decided from the literal text of
 * the command word. A word carrying `$` or a backtick is a name the shell resolves
 * at run time, so `$S id` was classified as though `$S` were a binary, and came
 * out `safe` (GHSA-fj9r-f47j-c73x).
 *
 * Resolving the variable is not the answer and cannot be: a session run keeps the
 * caller's shell state, so `S=sudo` and `$S id` can arrive as two separate calls,
 * and a variable exported in the target's own profile is never visible here at
 * all. What is answerable is whether we know the name — and when we do not, saying
 * so is the only honest class.
 *
 * Only the command word, never the arguments. `echo $HOME` names a command we know;
 * promoting that would put a prompt on most ordinary shell usage.
 */
function hasUnnameableCommand(command: string): boolean {
  for (const words of tokenizeSegments(command)) {
    const head = effectiveCommandWord(words);
    if (head !== null && /[$`]/.test(head)) return true;
  }
  return false;
}

/**
 * Commands this server synthesises rather than a user typing them.
 *
 * These reach the classifier as text like `sftp:upload /etc/passwd`, and no rule named
 * them, so every one fell through to the default `safe` — a class the default rules grant
 * to `operator` on `prod`. Writing an arbitrary file to the target is not `safe`: it is
 * the same authority as `rm`, spelled through a different tool, and it reaches
 * `~/.ssh/authorized_keys` without touching a shell. Opening a session is the same
 * argument, since it hands over an interactive shell.
 *
 * `session:close` is deliberately absent: it is a release rather than an acquisition, and
 * no tool advertises it as a read.
 *
 * `sftp:download` and `sftp:list` are absent for a different reason now. They *are*
 * lowered to `read-only` — by `READ_ONLY_SYNTHETIC` near the top of this file — because
 * both tools advertise `readOnlyHint: true` and `safe` is refused outright by a `readOnly`
 * profile, so the one profile class the annotation targeted was the one that could not run
 * them (#217). They cannot be lowered *here*, because this table is a floor and a floor
 * can only raise; an entry would be inert. That inertness is the trap worth keeping
 * written down — it produced two wrong attempts during #212.
 *
 * What this paragraph used to say, and what was wrong with it: that the effect anyone
 * wants from lowering `sftp:list` — letting a `viewer` list a remote directory — is "a
 * binding change, not a classification one". It is a classification one, because the tool
 * ships an annotation and a description that both claim read-only, and a policy that
 * disagreed with them was the defect rather than the binding.
 *
 * `sftp:upload-file` and `sftp:download-file` are `destructive` because each writes a
 * file: the first on the remote host, the second inside the operator's transfer root.
 * Without a floor both classify `safe` from the verb alone, which would let an `operator`
 * write to disk through a tool nobody had approved for it.
 */
const SYNTHETIC_CLASSES: Record<string, CommandClass> = Object.assign(
  Object.create(null) as Record<string, CommandClass>,
  {
    'sftp:upload': 'destructive',
    'sftp:upload-file': 'destructive',
    'sftp:download-file': 'destructive',
    'session:open': 'destructive',
  },
);

/** The first word, tokenised — the synthetic verb when there is one. */
function syntheticVerb(command: string): string {
  return tokenizeSegments(command)[0]?.[0] ?? '';
}

/**
 * The class of a command, and of everything it carries.
 *
 * A command that carries another decides nothing on its own: the remote shell expands
 * `$(...)`, backticks, `<(...)` and `sh -c` and runs what is inside, so the class is the
 * higher of the two. The scan for carriers already existed, but it *replaced* the outer
 * class instead of raising it, and only when the inner class was above `safe` — so
 * `sudo sh -c 'rm -rf /etc'` reported the inner `destructive` and lost the outer
 * `privileged`, which on `prod` is the difference between a prompt and a refusal.
 * Taking the maximum is what makes the scan unable to lower anything.
 */
export function classifyCommand(command: string, depth = 0): ParsedCommand {
  const trimmed = command.trim();
  const outer = classifyOuter(trimmed);

  if (depth >= MAX_NESTING_DEPTH) {
    // Nesting this deep is not something an operator writes, and we have stopped
    // reading. Refusing to guess is the only answer consistent with the rest of this
    // file.
    return { binary: outer.binary, fullCommand: trimmed, class: 'privileged' as CommandClass };
  }

  let highest = outer;

  // A floor, not a verdict. Returning the synthetic class outright would put it above
  // the elevation and never-allowed checks, so `sftp:upload /tmp/x; sudo id` would
  // record `destructive` where the command is `privileged`.
  const verb = syntheticVerb(trimmed);
  const floor = SYNTHETIC_CLASSES[verb];
  if (floor !== undefined && CLASS_RANK[floor] > CLASS_RANK[highest.class]) {
    highest = { binary: verb, fullCommand: trimmed, class: floor };
  }

  for (const inner of nestedCommands(trimmed)) {
    const parsed = classifyCommand(inner, depth + 1);
    // `binary` follows the winning side deliberately: it is what the audit record and
    // the refusal message name, and naming the outer `echo` would describe the wrong
    // process as the one that ran as root.
    if (CLASS_RANK[parsed.class] > CLASS_RANK[highest.class]) highest = parsed;
  }

  return { binary: highest.binary, fullCommand: trimmed, class: highest.class };
}

/** The class of the command itself, reading none of what it carries. */
function classifyOuter(trimmed: string): ParsedCommand {
  const binary = extractBinary(trimmed);
  const fullCommand = trimmed;

  // `binary` names the subject of the class. For everything below it is the
  // leading command; here it is the one that runs as root, which are the same
  // thing only when the prefix leads.
  const elevated = elevatedBinaryOf(trimmed);
  if (elevated !== null) {
    return { binary: elevated, fullCommand, class: 'privileged' as CommandClass };
  }

  if (hasUnreadableProgram(trimmed) || hasDangerousAwk(trimmed)
    || isDestructive(trimmed) || hasDisqualifyingArgs(trimmed)) {
    return { binary, fullCommand, class: 'destructive' as CommandClass };
  }

  // Below this point every branch assumes the command word names something we
  // recognised. When it is a variable expansion it names nothing we can check, so
  // the allowlist must not be consulted — `$S` is not on it, and falling through to
  // the default made an unknown command `safe`.
  //
  // `destructive` rather than `privileged`: this is "we cannot tell", not "this is
  // root". It gates on approval instead of refusing outright, which keeps
  // `$PREFIX/bin/tool` usable for a role that holds `destructive` on the tier.
  if (hasUnnameableCommand(trimmed)) {
    return { binary, fullCommand, class: 'destructive' as CommandClass };
  }

  const twoWordPrefix = (tokenizeSegments(fullCommand)[0] ?? []).slice(0, 2).join(' ');
  if (READ_ONLY_ALLOWLIST.has(binary) || READ_ONLY_ALLOWLIST.has(twoWordPrefix)
    || READ_ONLY_SYNTHETIC.has(binary)) {
    if (SHELL_CONTROL_CHARS.test(trimmed)) {
      return { binary, fullCommand, class: 'safe' as CommandClass };
    }
    return { binary, fullCommand, class: 'read-only' as CommandClass };
  }

  return { binary, fullCommand, class: 'safe' as CommandClass };
}

export { READ_ONLY_ALLOWLIST, READERS, READ_ONLY_SYNTHETIC, isDestructive };
