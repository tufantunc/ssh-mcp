const SENSITIVE_FIELDS = new Set([
  'password', 'privateKey', 'sudoPassword', 'suPassword', 'passphrase',
  'token', 'secret', 'apiKey', 'api_key', 'authorization',
]);

const REGEX_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'aws-access-key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'github-token', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { name: 'gitlab-token', pattern: /glpat-[A-Za-z0-9_-]{20}/g },
  { name: 'jwt', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
  // Body is bounded: an unbounded lazy [\s\S]*? rescans to end-of-input for
  // every BEGIN that has no matching END, so k unmatched markers in a 1MB
  // output cost O(k x 1MB) of synchronous regex time. 64KB comfortably covers
  // any real private key (an 8192-bit RSA key is well under 8KB).
  { name: 'pem-private-key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{0,65536}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: 'bearer-auth', pattern: /[Bb]earer\s+[A-Za-z0-9._~+\/-]+=*/g },
  { name: 'generic-api-key', pattern: /(?:api[_-]?key|api[_-]?secret)["'\s]*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gi },
];

// Field-name-indicated secrets in plaintext assignments (GHSA-95pj-qcm9-m3m9).
// Every layer above keys off the VALUE's shape (token form, entropy, known
// literal), so a short low-entropy value slipped through unless the profile
// happened to list it. These key off the NAME instead: `name=value` in
// env/INI/UCI-set style (quoted or bare) and OpenWrt `option|list name 'value'`
// lines are masked when the field name itself indicates a secret.
const ASSIGNMENT_EQ_PATTERN =
  /(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_.-]{0,63})\s*=\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"'#&\n]+))/g;
const ASSIGNMENT_UCI_PATTERN =
  /\b(?:option|list)\s+['"]?([A-Za-z][A-Za-z0-9_.-]{0,63})['"]?\s+(?:"([^"\n]*)"|'([^'\n]*)'|([^\s'"&\n]+))/gi;

// A name is sensitive when its last `_`/`-` segment is a bare secret word
// (`db_pass`, `wifi_psk`, `client_secret`) or when the whole name is a known
// key compound (`private_key`, `api-key`). Suffix-matching `key` itself is
// deliberately avoided: `persist_key`, `cache_key`, `primary_key` are ordinary
// settings, and their FP risk outweighs the rare real secret they'd catch.
const ASSIGNMENT_SECRET_SEGMENTS = new Set([
  'password', 'passwd', 'pass', 'passphrase', 'secret', 'token', 'psk',
]);
const ASSIGNMENT_SECRET_NAMES = new Set([
  'key', 'apikey', 'accesskey', 'privatekey', 'secretkey', 'clientkey',
  'sharedkey', 'authkey', 'signingkey', 'masterkey', 'encryptionkey',
  'presharedkey', 'wifikey', 'wpakey',
]);

function isSensitiveAssignmentName(name: string): boolean {
  // Dots are namespace separators (uci-show `wireless.radio0.key`), not part
  // of the field name; only the tail names the field.
  const field = name.slice(name.lastIndexOf('.') + 1);
  const segments = field.toLowerCase().split(/[_.-]+/).filter(Boolean);
  if (segments.length === 0) return false;
  if (ASSIGNMENT_SECRET_SEGMENTS.has(segments[segments.length - 1])) return true;
  return ASSIGNMENT_SECRET_NAMES.has(segments.join(''));
}

function maskAssignmentMatch(
  full: string,
  name: string,
  doubleQuoted: string | undefined,
  singleQuoted: string | undefined,
  bare: string | undefined,
): string {
  const quoted = doubleQuoted !== undefined ? doubleQuoted : singleQuoted;
  const raw = quoted !== undefined ? quoted : bare ?? '';
  if (!raw || raw.startsWith('[REDACTED:') || !isSensitiveAssignmentName(name)) {
    return full;
  }
  // A trailing `,`/`;` in a bare value is list syntax, not part of the secret.
  const value = quoted !== undefined ? raw : raw.replace(/[,;]+$/, '');
  if (!value) return full;
  const valueStart = quoted !== undefined ? full.length - raw.length - 1 : full.length - raw.length;
  return full.slice(0, valueStart) + `[REDACTED:assignment:${value.length}]` +
    full.slice(valueStart + value.length);
}

function maskSensitiveAssignments(text: string): string {
  const apply = (...args: unknown[]) => {
    const [full, name, dq, sq, bare] = args as [string, string, string | undefined, string | undefined, string | undefined];
    return maskAssignmentMatch(full, name, dq, sq, bare);
  };
  return text
    .replace(ASSIGNMENT_EQ_PATTERN, apply)
    .replace(ASSIGNMENT_UCI_PATTERN, apply);
}

function shannonEntropy(str: string): number {
  if (!str || str.length < 20) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export interface RedactOptions {
  entropyScan?: boolean;
  entropyThreshold?: number;
  /**
   * Secret values to scrub verbatim — the profile's sudo password, whose only
   * distinctive feature is that we know it. It is neither token-shaped nor
   * reliably high-entropy, so neither the pattern nor the entropy layer can
   * catch it (GHSA-9m75-x2ch-j4jr).
   *
   * Values shorter than 4 characters are ignored: scrubbing, say, a 2-character
   * password would replace that substring everywhere in ordinary output. The
   * exec wrapper that keeps such values out of command output in the first
   * place is the primary layer; this is defense in depth.
   */
  literalSecrets?: string[];
}

export function redactText(text: string, opts: RedactOptions = {}): string {
  let result = text;

  for (const { name, pattern } of REGEX_PATTERNS) {
    result = result.replace(pattern, (match) => {
      return `[REDACTED:${name}:${match.length}]`;
    });
  }

  if (opts.entropyScan) {
    const threshold = opts.entropyThreshold ?? 4.5;
    result = result.replace(/[A-Za-z0-9+/=_-]{20,}/g, (match) => {
      if (shannonEntropy(match) > threshold) {
        return `[REDACTED:entropy:${match.length}]`;
      }
      return match;
    });
  }

  for (const secret of opts.literalSecrets ?? []) {
    if (secret && secret.length >= 4) {
      result = result.split(secret).join(`[REDACTED:secret:${secret.length}]`);
    }
  }

  // Last: masking an assignment's value before the literal layer would hide
  // the only findable copy of a configured secret and spare prose mentions.
  result = maskSensitiveAssignments(result);

  return result;
}

export function redactRecord<T extends Record<string, unknown>>(
  obj: T,
  opts: RedactOptions = {},
): T {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_FIELDS.has(key) || /(?<![^a-z])(token|secret|key|password)$/i.test(key)) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'string') {
      result[key] = redactText(value, opts);
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      result[key] = redactRecord(value as Record<string, unknown>, opts);
    } else {
      result[key] = value;
    }
  }
  return result as T;
}
