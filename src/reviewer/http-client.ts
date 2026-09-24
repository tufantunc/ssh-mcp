import { redactText } from '../guard/redactor.js';
import {
  MAX_REVIEW_COMMAND_CHARS,
  MAX_REVIEW_RESPONSE_BYTES,
  reviewResponseSchema,
  type ReviewRequestBody,
} from './contract.js';
import {
  REVIEW_POLICY_VERSION,
  REVIEW_SCHEMA_VERSION,
  type CommandReviewer,
  type ReviewInput,
  type ReviewResult,
} from './types.js';

function unavailable(code: string, startedAt: number): ReviewResult {
  return {
    status: 'unavailable',
    verdict: 'escalate',
    risk: 'unknown',
    summary: 'Contextual reviewer unavailable; manual approval is required.',
    findings: [],
    policyVersion: REVIEW_POLICY_VERSION,
    durationMs: Date.now() - startedAt,
    unavailableCode: code,
  };
}

async function readBounded(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error('response-too-large');
  }
  if (!response.body) return '';

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error('response-too-large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(joined);
}

function endpointFor(baseUrl: string): URL {
  const base = new URL(baseUrl);
  if (!['http:', 'https:'].includes(base.protocol)) {
    throw new Error('Reviewer URL must use http or https');
  }
  if (base.username || base.password) {
    throw new Error('Reviewer URL must not contain credentials');
  }
  if (!base.pathname.endsWith('/')) base.pathname += '/';
  return new URL('v1/review', base);
}

export class HttpCommandReviewer implements CommandReviewer {
  private readonly endpoint: URL;

  constructor(baseUrl: string, private readonly timeoutMs: number) {
    this.endpoint = endpointFor(baseUrl);
  }

  async review(input: ReviewInput): Promise<ReviewResult> {
    const startedAt = Date.now();
    const command = redactText(input.command, { entropyScan: true });
    if (command.length > MAX_REVIEW_COMMAND_CHARS) {
      return unavailable('input-too-large', startedAt);
    }

    const body: ReviewRequestBody = {
      schemaVersion: REVIEW_SCHEMA_VERSION,
      tool: input.tool,
      commandClass: input.commandClass,
      command,
      context: { tier: input.tier, readOnly: input.readOnly },
    };

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!response.ok) return unavailable(`http-${response.status}`, startedAt);

      const raw = await readBounded(response, MAX_REVIEW_RESPONSE_BYTES);
      const parsed = reviewResponseSchema.safeParse(JSON.parse(raw));
      if (!parsed.success) return unavailable('invalid-response', startedAt);

      return {
        status: 'completed',
        verdict: parsed.data.verdict,
        risk: parsed.data.risk,
        summary: redactText(parsed.data.summary, { entropyScan: true }),
        findings: parsed.data.findings.map((finding) => ({
          ...finding,
          category: redactText(finding.category, { entropyScan: true }),
          message: redactText(finding.message, { entropyScan: true }),
        })),
        model: redactText(parsed.data.model, { entropyScan: true }),
        policyVersion: redactText(parsed.data.policyVersion, { entropyScan: true }),
        durationMs: Date.now() - startedAt,
      };
    } catch (err) {
      const code = err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')
        ? 'timeout'
        : err instanceof Error && err.message === 'response-too-large'
          ? 'response-too-large'
          : 'request-failed';
      return unavailable(code, startedAt);
    }
  }
}
