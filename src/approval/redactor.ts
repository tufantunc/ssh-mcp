/**
 * Provider-bound approval context redactor.
 *
 * Smart approval can call an operator-configured external LLM, so command and
 * intent text must be scrubbed before either value leaves the process. Rules
 * are deliberately conservative: losing a little context is safer than
 * transmitting a credential. This does not mutate the command that is later
 * executed after approval.
 */

const REDACTED = '<redacted>';
const SECRET_FLAG = String.raw`(?:password|passwd|passphrase|pass|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret|auth[-_]?token|bearer)`;
const SECRET_KEY = String.raw`[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token)[A-Za-z0-9_.-]*`;
const SHELL_SECRET_KEY = String.raw`[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*`;
const DQ_VALUE = String.raw`"(?:[^"\\]|\\.)*"`;
const SQ_VALUE = String.raw`'(?:[^'\\]|\\.)*'`;
const OPEN_DQ_VALUE = String.raw`"(?:[^"\\]|\\.)*$`;
const OPEN_SQ_VALUE = String.raw`'(?:[^'\\]|\\.)*$`;

interface RedactionRule {
  re: RegExp;
  replace: string | ((substring: string, ...groups: string[]) => string);
}

function isSchemeChar(ch: string): boolean {
  return /[A-Za-z0-9+.-]/.test(ch);
}

function isValidScheme(scheme: string): boolean {
  return /^[A-Za-z][A-Za-z0-9+.-]*$/.test(scheme);
}

function isAuthorityBoundary(ch: string): boolean {
  return ch === '/' || ch === '?' || ch === '#' || /\s/.test(ch);
}

function redactUrlUserinfo(input: string): string {
  let cursor = 0;
  let searchFrom = 0;
  let out = '';

  while (true) {
    const separator = input.indexOf('://', searchFrom);
    if (separator === -1) break;

    let schemeStart = separator - 1;
    while (schemeStart >= 0 && isSchemeChar(input[schemeStart])) schemeStart--;
    schemeStart += 1;
    const scheme = input.slice(schemeStart, separator);
    if (!isValidScheme(scheme)) {
      searchFrom = separator + 3;
      continue;
    }

    const authorityStart = separator + 3;
    let at = -1;
    for (let i = authorityStart; i < input.length; i++) {
      const ch = input[i];
      if (ch === '@') {
        at = i;
        break;
      }
      if (isAuthorityBoundary(ch)) break;
    }
    if (at === -1) {
      searchFrom = authorityStart;
      continue;
    }

    const colon = input.indexOf(':', authorityStart);
    if (colon === -1 || colon > at) {
      searchFrom = at + 1;
      continue;
    }

    out += input.slice(cursor, colon + 1) + REDACTED + '@';
    cursor = at + 1;
    searchFrom = at + 1;
  }

  return cursor === 0 ? input : out + input.slice(cursor);
}

const RULES: RedactionRule[] = [
  // Long CLI flags, both --token=value and --token value. Open-quoted rules
  // run first so malformed/truncated commands cannot leak the quoted suffix.
  {
    re: new RegExp(String.raw`(--${SECRET_FLAG}\s*=)\s*(?:${OPEN_DQ_VALUE}|${OPEN_SQ_VALUE})`, 'gi'),
    replace: (_match, key) => `${key}${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`(--${SECRET_FLAG}\s*=)\s*(?:${DQ_VALUE}|${SQ_VALUE}|\S+)`, 'gi'),
    replace: (_match, key) => `${key}${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`(--${SECRET_FLAG})\s+(?:${OPEN_DQ_VALUE}|${OPEN_SQ_VALUE})`, 'gi'),
    replace: (_match, key) => `${key} ${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`(--${SECRET_FLAG})\s+(?:${DQ_VALUE}|${SQ_VALUE}|\S+)`, 'gi'),
    replace: (_match, key) => `${key} ${REDACTED}`,
  },

  // MySQL/MariaDB -p password forms (space-separated, attached, and quoted).
  {
    re: new RegExp(String.raw`(^|\s)(-p)\s+(?:${DQ_VALUE}|${SQ_VALUE}|[^\s]+)`, 'g'),
    replace: (_match, lead, flag) => `${lead}${flag} ${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`(^|\s)-p(?:${OPEN_DQ_VALUE}|${OPEN_SQ_VALUE})`, 'g'),
    replace: (_match, lead) => `${lead}-p${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`(^|\s)-p(${DQ_VALUE}|${SQ_VALUE})`, 'g'),
    replace: (_match, lead, value) => `${lead}-p${value[0]}${REDACTED}${value[0]}`,
  },
  {
    re: /(^|\s)("-p(?:[^"\\]|\\.)*"|'-p(?:[^'\\]|\\.)*')/g,
    replace: (_match, lead, argument) => `${lead}${argument[0]}-p${REDACTED}${argument[0]}`,
  },
  {
    re: /(^|\s)(["']?)-p([^\s"']+)(\2)/g,
    replace: (_match, lead, quote) => `${lead}${quote}-p${REDACTED}${quote}`,
  },

  // HTTP authorization headers and URL userinfo credentials.
  {
    re: /(Authorization\s*:\s*)(Bearer|Basic|Token)\s+([A-Za-z0-9_~\-.=+\/]+)/gi,
    replace: (_match, header, scheme) => `${header}${scheme} ${REDACTED}`,
  },
  // Shell env assignments, JSON/TOML key-value fields, and simple prose.
  {
    re: new RegExp(String.raw`\b(${SHELL_SECRET_KEY}=)\s*(?:${OPEN_DQ_VALUE}|${OPEN_SQ_VALUE})`, 'g'),
    replace: (_match, key) => `${key}${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`\b(${SHELL_SECRET_KEY}=)(?:${DQ_VALUE}|${SQ_VALUE}|\S+)`, 'g'),
    replace: (_match, key) => `${key}${REDACTED}`,
  },
  {
    re: /("[^"\\]*(?:password|passwd|passphrase|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token)[^"\\]*"\s*[:=]\s*)"(?:[^"\\]|\\.)*$/gi,
    replace: (_match, prefix) => `${prefix}"${REDACTED}"`,
  },
  {
    re: /("[^"\\]*(?:password|passwd|passphrase|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token)[^"\\]*"\s*[:=]\s*)"(?:[^"\\]|\\.)*"/gi,
    replace: (_match, prefix) => `${prefix}"${REDACTED}"`,
  },
  {
    re: new RegExp(String.raw`\b(${SECRET_KEY}\s*[:=]\s*)(?:${OPEN_DQ_VALUE}|${OPEN_SQ_VALUE})`, 'gi'),
    replace: (_match, prefix) => `${prefix}${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`\b(${SECRET_KEY}\s*[:=]\s*)(?:${DQ_VALUE}|${SQ_VALUE}|\S+)`, 'gi'),
    replace: (_match, prefix) => `${prefix}${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`\b(password|passwd|passphrase|secret|token)\s+(?:${OPEN_DQ_VALUE}|${OPEN_SQ_VALUE})`, 'gi'),
    replace: (_match, word) => `${word} ${REDACTED}`,
  },
  {
    re: new RegExp(String.raw`\b(password|passwd|passphrase|secret|token)\s+(?:${DQ_VALUE}|${SQ_VALUE}|\S+)`, 'gi'),
    replace: (_match, word) => `${word} ${REDACTED}`,
  },

  // Standalone high-confidence credential shapes and private keys.
  { re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, replace: REDACTED },
  { re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*$/g, replace: REDACTED },
  { re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, replace: REDACTED },
  {
    re: /(aws[_-]?secret[_-]?access[_-]?key\s*[:=]?\s*["']?)([A-Za-z0-9/+]{40})(["']?)/gi,
    replace: (_match, prefix, _value, suffix) => `${prefix}${REDACTED}${suffix}`,
  },
  { re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{8,}\b/g, replace: REDACTED },
  { re: /\b(?:gh[opusr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g, replace: REDACTED },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, replace: REDACTED },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, replace: REDACTED },
  {
    re: /(^|[^A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,255}(?=$|[^A-Za-z0-9_-])/g,
    replace: (_match, lead) => `${lead}${REDACTED}`,
  },
];

export function redactApprovalText(input: string | undefined): string {
  if (!input) return '';
  let output = redactUrlUserinfo(input);
  for (const rule of RULES) {
    output = output.replace(rule.re, rule.replace as any);
  }
  return output;
}
