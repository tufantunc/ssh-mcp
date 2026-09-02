import type { CommandClass, ParsedCommand } from '../types.js';

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

const READ_ONLY_ALLOWLIST = new Set([
  'ls', 'cat', 'grep', 'find', 'stat', 'df', 'du', 'head', 'tail', 'wc',
  'ps', 'uname', 'uptime', 'hostname', 'id', 'who', 'whoami', 'date',
  'printenv', 'pwd', 'echo', 'printf', 'test', 'true', 'false',
  'which', 'whereis', 'file', 'readlink', 'realpath', 'basename', 'dirname',
  'seq', 'sort', 'uniq', 'cut', 'tr', 'diff', 'comm',
  'systemctl status', 'journalctl', 'docker ps', 'docker logs', 'docker inspect',
  'docker stats', 'docker images', 'free', 'top', 'htop', 'iostat', 'vmstat',
  'netstat', 'ss', 'ifconfig', 'ip addr', 'ip route', 'arp', 'dig', 'nslookup',
  'host', 'ping', 'traceroute', 'git status', 'git log',
  'git diff', 'git branch', 'git show', 'git remote',
]);
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
  /:\(\)\s*\{\s*:\|:\&\s*\}\s*;\s*:/,   // fork bomb
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

/** Shells that run their next argument as a command when given `-c`. */
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
// resolves to a function and reading `.flags` off it throws inside the policy gate.
const INTERPRETERS: Record<string, { flags: string[]; readable: boolean }> = Object.assign(
  Object.create(null) as Record<string, { flags: string[]; readable: boolean }>,
  {
  sh: { flags: ['-c'], readable: true },
  bash: { flags: ['-c'], readable: true },
  dash: { flags: ['-c'], readable: true },
  zsh: { flags: ['-c'], readable: true },
  ksh: { flags: ['-c'], readable: true },
  ash: { flags: ['-c'], readable: true },
  python: { flags: ['-c'], readable: false },
  python2: { flags: ['-c'], readable: false },
  python3: { flags: ['-c'], readable: false },
  perl: { flags: ['-e', '-E'], readable: false },
  ruby: { flags: ['-e'], readable: false },
  // `-p`/`--print` evaluate exactly as `-e` does and then print the result.
  node: { flags: ['-e', '--eval', '-p', '--print'], readable: false },
  php: { flags: ['-r'], readable: false },
  },
);

/** Flags whose value is a separate word, which is not the program. `awk -F ':' '{…}'`. */
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

  const endWord = () => {
    if (current) words.push(current);
    current = '';
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
    if (honorQuotes && (ch === '"' || ch === "'")) { quote = ch; continue; }
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
 */
export function nestedCommands(command: string): string[] {
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
    // awk is deliberately absent. Its program is a positional operand rather than the
    // value of a flag, so nothing distinguishes running awk from naming it, and its four
    // implementations disagree about which flags consume a value — modelling that wrongly
    // opened five separate holes across two review rounds. `awk` keeps the class it has on
    // 2.5.1 and is tracked separately.
    if (!operandsAreData(words)) {
      for (let i = 0; i < words.length; i++) {
        const spec = INTERPRETERS[stripPath(unquote(words[i]))];
        if (spec === undefined || isFlagValue(words, i, spec.flags)) continue;
        const program = programAfterFlag(words, i, spec.flags);
        if (program !== null) found.push(program);
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
  { find: /^-(exec|execdir|ok|okdir|delete|fprintf?|fls)$/ },
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
  if (depth >= MAX_NESTING_DEPTH) return null;
  for (const inner of nestedCommands(command)) {
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
  return idx !== -1 && READ_ONLY_ALLOWLIST.has(stripPath(unquote(words[idx])));
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
function isFlagValue(words: string[], i: number, flags: string[]): boolean {
  if (i === 0) return false;
  const previous = words[i - 1];
  return previous.length > 1 && previous.startsWith('-') && flags.includes(previous);
}

/**
 * The program an interpreter was handed on its command line, or null.
 *
 * Only flags may sit between the interpreter and its flag; anything else means this was
 * not that kind of invocation, which is what keeps `python3 script.py` — a program this
 * cannot read either, but one every deployment runs — out of the gate.
 */
function programAfterFlag(words: string[], from: number, flags: string[]): string | null {
  for (let j = from + 1; j < words.length; j++) {
    const word = words[j];
    if (flags.includes(word)) return words[j + 1] ?? null;
    const attached = flags.find((f) => word.startsWith(f) && word.length > f.length);
    if (attached !== undefined) {
      const rest = word.slice(attached.length);
      // `sh -c'sudo id'` tokenises to `-csudo id`, so the program is attached. `bash -cx`
      // is a flag cluster and the program is the next word. A space, or the `=` of
      // `--eval=…`, is what tells them apart: a cluster is letters only.
      if (/\s/.test(rest) || rest.startsWith('=')) return rest.replace(/^=/, '');
      return words[j + 1] ?? null;
    }
    // The program flag need not lead the cluster: `bash -xc 'sudo id'` runs exactly what
    // `bash -cx 'sudo id'` runs, and a prefix test saw the second and missed the first.
    if (clusterCarriesFlag(word, flags)) return words[j + 1] ?? null;
    if (!word.startsWith('-')) return null;
  }
  return null;
}

/**
 * What follows a short flag inside a single-dash cluster, or null if it holds none.
 *
 * Clusters only — a run of single letters after one dash. Long flags and attached values
 * are handled before this is reached.
 */
function clusterCarriesFlag(word: string, flags: string[]): boolean {
  // Three letters at most. `/^-[A-Za-z]+$/` alone also matches every single-dash long
  // option, and `find`'s predicates are full of them: `-type` contains perl's `-e`, so
  // `find . -name perl -type f` read as a carrier and asked for approval.
  if (!/^-[A-Za-z]{2,3}$/.test(word)) return false;
  const body = word.slice(1);
  // A cluster is letters only, so whatever follows the program flag is more flags — the
  // program itself is always the next word.
  return flags.some((flag) => flag.length === 2 && body.includes(flag[1]));
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
  const spec = INTERPRETERS[bin];
  if (spec === undefined) return false;
  const flags = spec.flags;
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
function hasUnreadableProgram(command: string): boolean {
  const segments = tokenizeSegmentsDetailed(command);
  for (let i = 0; i < segments.length; i++) {
    const { words, sep } = segments[i];
    if (sep === '|' && readsProgramFromStdin(words)) return true;

    if (!operandsAreData(words)) {
      for (let j = 0; j < words.length; j++) {
        const spec = INTERPRETERS[stripPath(unquote(words[j]))];
        if (spec === undefined || spec.readable) continue;
        if (isFlagValue(words, j, spec.flags)) continue;
        if (programAfterFlag(words, j, spec.flags) !== null) return true;
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
 * `sftp:download` and `session:close` are deliberately absent. Both would move *down*
 * from `safe` — download to `read-only`, matching its `readOnlyHint`, and close being a
 * release rather than an acquisition. Lowering a class is a widening, and a security
 * release is the wrong place for one; they keep the class they have today.
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

  if (hasUnreadableProgram(trimmed) || isDestructive(trimmed) || hasDisqualifyingArgs(trimmed)) {
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
  if (READ_ONLY_ALLOWLIST.has(binary) || READ_ONLY_ALLOWLIST.has(twoWordPrefix)) {
    if (SHELL_CONTROL_CHARS.test(trimmed)) {
      return { binary, fullCommand, class: 'safe' as CommandClass };
    }
    return { binary, fullCommand, class: 'read-only' as CommandClass };
  }

  return { binary, fullCommand, class: 'safe' as CommandClass };
}

export { READ_ONLY_ALLOWLIST, isDestructive };
