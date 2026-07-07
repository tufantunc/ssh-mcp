/**
 * Secret redactor.
 *
 * Applied to `command`, `description`, `stdout`, and `stderr` BEFORE the
 * audit record is serialized to disk. Rules are intentionally
 * over-aggressive — false positives ("<redacted>" in normal output) are
 * vastly preferable to credentials leaking into the JSONL.
 *
 * Rule order (each runs on the previous step's output):
 *   1. CLI flag patterns: `--password=VALUE`, `--token=VALUE`, `-p VALUE`,
 *      `--api-key=VALUE`, `--secret VALUE`, `Authorization: Bearer ...`.
 *   2. Inline `KEY=value` env-style pairs (KEY matches PASSWORD/TOKEN/SECRET/...).
 *   3. JSON / TOML quoted `"key": "value"` pairs for the same key set.
 *   4. PEM blocks (BEGIN/END *PRIVATE KEY*).
 *   5. AWS access-key-id shapes (AKIA/ASIA + 16 chars).
 *   6. AWS secret-access-key when on the same line as a hint.
 *   7. JWT tokens (three base64url segments).
 *   8. GitHub PATs (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`).
 *   9. Slack tokens (`xox[abprs]-...`).
 *  10. Google API keys (`AIza...`, 39 chars).
 */

const REDACTED = '<redacted>';

// 1a. --password=VALUE (and friends), value can be quoted or bare.
const CLI_LONG_EQ_RE =
  /(--(?:password|passwd|pass|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret|auth[-_]?token|bearer)\s*=)\s*(?:"[^"]*"|'[^']*'|\S+)/gi;

// 1b. --password VALUE (space-separated)
const CLI_LONG_SPACE_RE =
  /(--(?:password|passwd|pass|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret|auth[-_]?token|bearer))\s+(?:"[^"]*"|'[^']*'|\S+)/gi;

// 1c. -p VALUE  (MySQL-style short flag).
const CLI_SHORT_P_RE = /(^|\s)(-p)\s+(?:"[^"]*"|'[^']*'|[^\s]+)/g;

// 1d. -p"VALUE" / -p'VALUE' — quote *after* -p, value may contain whitespace.
//     `mysql -p"secret with space"` / `mysql -p'secret with space'`. The
//     attached rule below only accepts non-space chars, so quoted attached
//     values with spaces would otherwise bypass redaction.
const CLI_SHORT_P_ATTACHED_QUOTED_VALUE_RE =
  /(^|\s)-p("(?:[^"\\]|\\.)*"|'[^']*')/g;

// 1e. "-pVALUE" / '-pVALUE' — whole arg quoted (quote *before* -p), value may
//     contain whitespace. `mysql '-psecret with space'` / `"-psecret with space"`.
const CLI_SHORT_P_QUOTED_ARG_RE = /(^|\s)(["'])-p[^"']*\2/g;

// 1f. -pVALUE / "-pVALUE" / '-pVALUE' (MySQL attached password form, no space).
const CLI_SHORT_P_ATTACHED_RE = /(^|\s)(["']?)-p([^\s"']+)(\2)/g;

// 1g. Authorization: Bearer ***  / Authorization: Basic ***
const AUTH_HEADER_RE =
  /(Authorization\s*:\s*)(Bearer|Basic|Token)\s+([A-Za-z0-9_\-\.=+\/]+)/gi;

// 2. Shell env-style assignment, e.g. MY_PASSWORD=foo or API_TOKEN='x y'.
const SHELL_ASSIGN_RE =
  /\b([A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*)=(?:"[^"]*"|'[^']*'|\S+)/g;

// 3. JSON / TOML "key": "value" (case-insensitive).
const JSON_KV_RE =
  /("[^"\\]*(?:password|passwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token)[^"\\]*"\s*[:=]\s*)"(?:[^"\\]|\\.)*"/gi;

// 3b. TOML / dotenv bare keys: password = "value", token='value'.
const BARE_KV_RE =
  /\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token)[A-Za-z0-9_.-]*\s*[:=]\s*)(?:"[^"]*"|'[^']*'|\S+)/gi;

// 3c. Human prose: "password hunter2", "token abc".
const SIMPLE_SECRET_WORD_RE =
  /\b(password|passwd|secret|token)\s+(?:"[^"]*"|'[^']*'|\S+)/gi;

// 4. PEM private-key blocks.
const PEM_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;

// 4b. Dangling PEM private-key header with no matching END terminator — e.g. a
//     key whose `END` marker was truncated away or falls past a bounded scan
//     window. Redact from the BEGIN marker to end-of-string so raw key material
//     can never persist when the terminator is unreachable.
const PEM_OPEN_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*$/g;

// 5. AWS access-key-id
const AWS_ACCESS_KEY_RE = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;

// 6. AWS secret on the same line as a hint (key=value or similar).
const AWS_SECRET_HINT_RE =
  /(aws[_-]?secret[_-]?access[_-]?key\s*[:=]?\s*["']?)([A-Za-z0-9/+]{40})(["']?)/gi;

// 7. JWT (three base64url segments).
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

// 8. GitHub PATs — classic (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) and
//    fine-grained (`github_pat_...`, which embeds underscores in its body).
const GITHUB_TOKEN_RE =
  /\b(?:gh[opusr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g;

// 9. Slack tokens
const SLACK_TOKEN_RE = /\bxox[abprs]-[A-Za-z0-9\-]{10,}\b/g;

// 10. Google API keys
const GOOGLE_API_KEY_RE = /\bAIza[0-9A-Za-z_\-]{35}\b/g;

interface Rule {
  re: RegExp;
  replace: string | ((substring: string, ...groups: string[]) => string);
}

const RULES: Rule[] = [
  { re: CLI_LONG_EQ_RE, replace: (_m, key) => `${key}${REDACTED}` },
  { re: CLI_LONG_SPACE_RE, replace: (_m, key) => `${key} ${REDACTED}` },
  { re: CLI_SHORT_P_RE, replace: (_m, lead, flag) => `${lead}${flag} ${REDACTED}` },
  // Quoted attached -p forms (value may contain whitespace) must run before the
  // plain attached rule, which only consumes non-space chars.
  { re: CLI_SHORT_P_ATTACHED_QUOTED_VALUE_RE, replace: (_m, lead, val) => `${lead}-p${val[0]}${REDACTED}${val[0]}` },
  { re: CLI_SHORT_P_QUOTED_ARG_RE, replace: (_m, lead, quote) => `${lead}${quote}-p${REDACTED}${quote}` },
  { re: CLI_SHORT_P_ATTACHED_RE, replace: (_m, lead, quote) => `${lead}${quote}-p${REDACTED}${quote}` },
  { re: AUTH_HEADER_RE, replace: (_m, hdr, scheme) => `${hdr}${scheme} ${REDACTED}` },
  { re: SHELL_ASSIGN_RE, replace: (_m, key) => `${key}=${REDACTED}` },
  { re: JSON_KV_RE, replace: (_m, head) => `${head}"${REDACTED}"` },
  { re: BARE_KV_RE, replace: (_m, head) => `${head}${REDACTED}` },
  { re: SIMPLE_SECRET_WORD_RE, replace: (_m, word) => `${word} ${REDACTED}` },
  { re: PEM_RE, replace: REDACTED },
  { re: AWS_ACCESS_KEY_RE, replace: REDACTED },
  { re: AWS_SECRET_HINT_RE, replace: (_m, head, _val, tail) => `${head}${REDACTED}${tail}` },
  { re: JWT_RE, replace: REDACTED },
  { re: GITHUB_TOKEN_RE, replace: REDACTED },
  { re: SLACK_TOKEN_RE, replace: REDACTED },
  { re: GOOGLE_API_KEY_RE, replace: REDACTED },
];

export function redact(input: string | undefined | null): string {
  if (!input) return '';
  let out = input;
  for (const rule of RULES) {
    out = out.replace(rule.re as RegExp, rule.replace as any);
  }
  return out;
}

/**
 * Redact PEM private-key blocks over the FULL input, independent of any
 * downstream byte cap.
 *
 * `PEM_RE` is terminator-anchored (`BEGIN...END`), so a key whose `END` marker
 * falls past a bounded pre-redaction scan window would never match and its raw
 * prefix could persist in the capped audit output. Callers that cap before
 * redacting (see `capThenRedact`) must run this on the un-capped text first:
 *   1. Redact every complete `BEGIN...END` block.
 *   2. Redact any remaining dangling `BEGIN` with no reachable `END` (truncated
 *      key / terminator beyond the buffer) all the way to end-of-string.
 *
 * Scanning the full output with a single BEGIN-anchored regex is cheap when no
 * key is present (fast literal prefix scan, no backtracking); the cost is only
 * paid when key material actually exists — which is exactly when it must be
 * redacted.
 */
export function redactPemBlocks(input: string | undefined | null): string {
  if (!input) return '';
  return input.replace(PEM_RE, REDACTED).replace(PEM_OPEN_RE, REDACTED);
}

export const REDACTED_PLACEHOLDER = REDACTED;
