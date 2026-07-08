const SENSITIVE_FIELDS = new Set([
  'password', 'privateKey', 'sudoPassword', 'suPassword', 'passphrase',
  'token', 'secret', 'apiKey', 'api_key', 'authorization',
]);

const REGEX_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'aws-access-key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'github-token', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { name: 'gitlab-token', pattern: /glpat-[A-Za-z0-9_-]{20}/g },
  { name: 'jwt', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
  { name: 'pem-private-key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: 'bearer-auth', pattern: /[Bb]earer\s+[A-Za-z0-9._~+\/-]+=*/g },
  { name: 'generic-api-key', pattern: /(?:api[_-]?key|api[_-]?secret)["'\s]*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gi },
];

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
