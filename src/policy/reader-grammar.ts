/**
 * Deciding whether a reader's arguments are provably data, not more commands.
 *
 * `READERS` in the classifier grants `read-only` to any command whose first
 * word is allowlisted, without looking at the words after it. That is safe
 * only because a later stage rejects shell metacharacters, but `cat -- "$x"`
 * and `cat $(id)` both clear that gate today; only the outer shell-control
 * scan (or the caller's own audit) stands between an allowlisted reader and
 * an argument that isn't data. This module is the piece that closes that gap
 * for readers whose flags are simple enough to describe with a grammar: given
 * the argv words that follow the command name and a description of what the
 * binary accepts, say whether every word is an option this grammar
 * recognises, a value an option consumes, or an operand that satisfies the
 * `operands` shape. Nothing here decides *class* — that stays the caller's
 * job, together with the correctness conditions in the design doc (an
 * optional-argument flag never goes in `valueFlags`; an option is listed only
 * if every implementation the command name can resolve to reads it the same
 * way).
 *
 * Pure and side-effect free: no filesystem, no `classifier.ts` import. The
 * table that wires this into a command's class is a later task.
 */

/**
 * What a reader's argument grammar looks like.
 *
 * `'any'` opts a reader out of this matcher entirely — its arguments are
 * trusted as data by some other means, and `audit` is required so that trust
 * can't be asserted without saying which implementations were checked and
 * what was found.
 *
 * `flags` take no value; `valueFlags` require one; `optionalValueFlags` model
 * getopt's optional argument (`::`) and never consume the next word. Short
 * entries carry their dash (`'-n'`), long entries carry both (`'--since'`) —
 * the matcher does not add or strip dashes, so a grammar that gets this wrong
 * simply matches nothing. A name present in more than one of `flags`,
 * `valueFlags` and `optionalValueFlags` is refused on every path.
 */
export type ArgGrammar =
  | { args: 'any'; audit: string }
  | {
      args: 'getopt' | 'exact';
      flags?: readonly string[];
      valueFlags?: readonly string[];
      optionalValueFlags?: readonly string[]; // value optional: never consumes the next word
      numericShort?: boolean;           // getopt only: accept `-<digits>` (git -<n>)
      optionsBeforeOperands?: boolean;  // refuse an option-looking word after the first operand
      operands?: {
        max?: number;
        first?: readonly string[];
        each?: RegExp;
      };
    };

/** The operand shape carried by the non-`'any'` arm of {@link ArgGrammar}. */
type OperandRules = NonNullable<Extract<ArgGrammar, { args: 'getopt' | 'exact' }>['operands']>;

/**
 * `ok: true`, or `ok: false` with the first word the matcher would not
 * accept — the value an option consumed still counts as accepted, so it
 * never appears here. For a value flag left with nothing to consume, `word`
 * is that flag, not the word before it. For an operand-count, `first`, or
 * `each` violation, `word` is the offending operand. A later task turns this
 * into the text of a refusal, which is why the word — not just a boolean —
 * is what this returns.
 */
type MatchResult = { ok: true } | { ok: false; word: string };

/**
 * Does every word in `words` come from what `grammar` describes?
 *
 * The scan is word-by-word, left to right, mirroring how getopt (or, for
 * `exact`, the binary's own hand-rolled parser) actually reads argv: a lone
 * `-` is always an operand (stdin), and everything left over after options
 * are stripped is checked against `operands`. `--` ends option parsing for
 * every later word under `getopt` only — an `exact` parser keeps evaluating
 * its option words after `--` (measured: GNU `find -- d -fprint /tmp/x`
 * wrote the file), so there `--` is refused as an unrecognised word rather
 * than treated as end-of-checks.
 */
export function matchesGrammar(words: readonly string[], grammar: ArgGrammar): MatchResult {
  if (grammar.args === 'any') {
    return { ok: true };
  }

  const flags = new Set(grammar.flags ?? []);
  const valueFlags = new Set(grammar.valueFlags ?? []);
  const optionalValueFlags = new Set(grammar.optionalValueFlags ?? []);
  const operands: string[] = [];
  let optionsEnded = false;

  for (let i = 0; i < words.length; i++) {
    const word = words[i];

    // A lone '-' is stdin, not an option — and once '--' has been seen,
    // nothing looks like an option any more.
    const looksLikeOption = !optionsEnded && word.length > 1 && word.startsWith('-');

    // POSIX option order, opt-in per entry — and ahead of the getopt `--`
    // branch below on purpose: `--` is itself an option-looking word, and an
    // implementation that does not permute (macOS uniq's `+`-prefixed
    // optstring, BSD ifconfig) has already stopped option scanning at the
    // first operand, so it reads `--` as an operand — uniq's is the OUTFILE
    // it overwrites (a file literally named `--`), ifconfig's is an interface
    // configuration word. A permuting implementation (GNU) would treat the
    // same word as the terminator it spells, so the word cannot be judged one
    // way for both: `optionsBeforeOperands` refuses it, and only entries
    // where some implementation does not permute set the flag.
    if (grammar.optionsBeforeOperands && operands.length > 0 && looksLikeOption) {
      return { ok: false, word };
    }

    // getopt only. An `exact` parser never hands `--` this meaning: find
    // keeps reading primaries after it, so accepting `--` there would end
    // the checks at exactly the word an attacker can hide behind.
    if (grammar.args === 'getopt' && !optionsEnded && word === '--') {
      optionsEnded = true; // every later word is an operand, `--` itself is not one
      continue;
    }

    if (!looksLikeOption) {
      operands.push(word);
      continue;
    }

    // git's `-<n>` revision limit (`-20`): a whole word of digits, accepted
    // as a no-value option before any cluster or long-option parsing sees it.
    // `-2x` is not all digits, so it falls through to the cluster path below
    // and is refused unless its characters are listed. getopt style only.
    //
    // An explicit entry always wins over this shortcut, but only the leading
    // `-<digit>` *character* is effective: the cluster parser below reads
    // getopt's way, one character at a time, and never the whole word. An
    // entry naming just `-20` therefore does not make `-20` pass — the
    // shortcut stands down (the word is "explicitly listed") and the cluster
    // parser then refuses it unless `-2` is listed too. Fail-closed, which is
    // the right failure for a listing the binary would not read that way.
    // Ambiguity is refused here as well, the same as every other path —
    // otherwise a name the caller listed in more than one list would be
    // silently accepted through this shortcut instead of being caught.
    if (grammar.args === 'getopt' && grammar.numericShort && /^-\d+$/.test(word)) {
      const shortChar = word.slice(0, 2); // '-' + first digit
      if (
        isAmbiguousName(word, flags, valueFlags, optionalValueFlags) ||
        isAmbiguousName(shortChar, flags, valueFlags, optionalValueFlags)
      ) {
        return { ok: false, word };
      }
      const explicitlyListed =
        flags.has(word) ||
        valueFlags.has(word) ||
        optionalValueFlags.has(word) ||
        flags.has(shortChar) ||
        valueFlags.has(shortChar) ||
        optionalValueFlags.has(shortChar);
      if (!explicitlyListed) {
        continue; // no explicit entry claims this digit — take the numeric shortcut
      }
      // An explicit entry claims this word or its leading digit character:
      // fall through to ordinary short-cluster parsing below, which applies
      // it correctly (including consuming a separate value word for a
      // `valueFlags` entry, which this shortcut must never do).
    }

    if (grammar.args === 'getopt' && !word.startsWith('--')) {
      // Short cluster: read character by character, the way getopt does.
      const cluster = matchShortCluster(word, words, i, flags, valueFlags, optionalValueFlags);
      if (!cluster.ok) return cluster;
      i = cluster.nextIndex; // the `for` loop's own i++ then lands on the next unread word
      continue;
    }

    // A long option (getopt) or any '-'-prefixed word (exact — there is no
    // separate short-cluster path, so this is also where '-n' is checked).
    // Only getopt splits '=value' off the name; exact matches the raw word,
    // so '--name=value' matches only if that whole string was listed.
    const eqIndex = grammar.args === 'getopt' ? word.indexOf('=') : -1;
    const name = eqIndex === -1 ? word : word.slice(0, eqIndex);

    // A name in more than one of the three lists is a grammar bug, not a
    // call this matcher can make on the binary's behalf — accepting it would
    // have to pick a side (does it take a value, an optional value, or
    // none?), and picking wrong is exactly the hole the correctness
    // conditions warn about. Refuse rather than guess.
    if (isAmbiguousName(name, flags, valueFlags, optionalValueFlags)) {
      return { ok: false, word };
    }

    if (valueFlags.has(name)) {
      if (eqIndex !== -1) {
        continue; // '--name=value': the value is attached, nothing left to consume
      }
      if (i + 1 >= words.length) {
        return { ok: false, word: name }; // a value flag with nothing after it
      }
      i++; // consume the next word as the value
      continue;
    }

    if (optionalValueFlags.has(name)) {
      // Bare, or (getopt) '--name=value' with the value already attached to
      // this same word via `name`/`eqIndex` above. Either way there is
      // nothing left to consume, and the next word is never touched.
      continue;
    }

    if (flags.has(name) && eqIndex === -1) {
      continue; // a no-value flag never accepts an attached '=value'
    }

    return { ok: false, word };
  }

  return checkOperands(operands, grammar.operands);
}

/**
 * True when `name` appears in more than one of the three option lists — the
 * ambiguity the correctness conditions require every path to refuse.
 */
function isAmbiguousName(
  name: string,
  flags: ReadonlySet<string>,
  valueFlags: ReadonlySet<string>,
  optionalValueFlags: ReadonlySet<string>,
): boolean {
  const inFlags = flags.has(name);
  const inValueFlags = valueFlags.has(name);
  const inOptionalValueFlags = optionalValueFlags.has(name);
  return (
    (inFlags && inValueFlags) || (inFlags && inOptionalValueFlags) || (inValueFlags && inOptionalValueFlags)
  );
}

/**
 * Reads one getopt-style short-option cluster (`-rn5`) character by
 * character. `flags` characters just continue the scan; a `valueFlags`
 * character takes the rest of the word as its value, or the next word if
 * the rest is empty; an `optionalValueFlags` character takes the rest of the
 * word as its value if there is any, never the next word, and either way
 * ends the scan of this word; anything else refuses the whole cluster.
 *
 * Returns the index the outer loop's own `i++` should land past — unchanged
 * when the value was attached, optional, or there was none to take,
 * `index + 1` only when a required value flag consumed the next word.
 */
function matchShortCluster(
  word: string,
  words: readonly string[],
  index: number,
  flags: ReadonlySet<string>,
  valueFlags: ReadonlySet<string>,
  optionalValueFlags: ReadonlySet<string>,
): { ok: true; nextIndex: number } | { ok: false; word: string } {
  for (let c = 1; c < word.length; c++) {
    const ch = '-' + word[c];
    // Same ambiguity refusal as the long/exact path, checked first so a
    // char present in more than one list is refused here too, not silently
    // treated as belonging to just one of them (which the long/exact path
    // would not do either).
    if (isAmbiguousName(ch, flags, valueFlags, optionalValueFlags)) return { ok: false, word };
    if (flags.has(ch)) continue;
    if (valueFlags.has(ch)) {
      const rest = word.slice(c + 1);
      if (rest.length > 0) return { ok: true, nextIndex: index };
      if (index + 1 >= words.length) return { ok: false, word: ch };
      return { ok: true, nextIndex: index + 1 };
    }
    if (optionalValueFlags.has(ch)) {
      // The rest of the word (if any) is this option's value; the scan of
      // this word ends here either way, and the next word is never consumed.
      return { ok: true, nextIndex: index };
    }
    return { ok: false, word };
  }
  return { ok: true, nextIndex: index };
}

/**
 * Checks the operands collected from a pass over `words` against `rules`.
 * `first` is checked only against `operands[0]` — a reader with no operands
 * at all has nothing to violate it with — `each` against every operand, and
 * `max` last, since going over budget is a property of the whole list rather
 * than of any one word.
 */
function checkOperands(operands: readonly string[], rules: OperandRules | undefined): MatchResult {
  if (!rules) return { ok: true };

  for (let i = 0; i < operands.length; i++) {
    const operand = operands[i];
    if (i === 0 && rules.first && !rules.first.includes(operand)) {
      return { ok: false, word: operand };
    }
    if (rules.each) {
      // A caller's /g or /y regex makes RegExp#test stateful: lastIndex
      // carries over from the previous call, so without resetting it here
      // one operand's match position can leak into the next — accepting an
      // operand that should be refused, or the reverse. Reset before every
      // test so each operand is checked fresh, the way a plain (non-sticky,
      // non-global) pattern already behaves.
      rules.each.lastIndex = 0;
      if (!rules.each.test(operand)) {
        return { ok: false, word: operand };
      }
    }
  }

  if (rules.max !== undefined) {
    // A `max` that isn't a non-negative integer (NaN, 1.5, -1, ...) can't be
    // compared against a count safely: `length > NaN` is always false,
    // which would accept any number of operands, and a fractional max reads
    // back out of the operands array at a non-existent index. Treat any
    // such value as the strictest possible bound — no operand is safe to
    // let through under a limit that couldn't be checked — rather than let
    // a malformed grammar entry accept (or silently under-report) unbounded
    // operands.
    const validMax = Number.isInteger(rules.max) && rules.max >= 0;
    const limit = validMax ? rules.max : 0;
    if (operands.length > limit) {
      return { ok: false, word: operands[limit] };
    }
  }

  return { ok: true };
}
