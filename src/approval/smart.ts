/**
 * smart mode: ask a configured LLM endpoint whether a command should be
 * allowed. Default schema follows OpenAI chat-completions; alternative
 * providers can be added behind the `provider` field on SmartLlmConfig.
 *
 * Fail-closed semantics:
 *   - HTTP non-200, timeout, malformed JSON, or missing `allow` field
 *     -> deny when fail_closed=true (default), else allow with warning.
 *
 * The fetch implementation is dependency-injected via SmartApprovalOptions so
 * tests can stub it without monkey-patching the global.
 */

import {
  ApprovalContext,
  ApprovalDecision,
  ApprovalEngine,
  SmartApprovalOptions,
} from './types.js';
import { redactApprovalText } from './redactor.js';

interface LlmJudgement {
  allow: boolean;
  reason: string;
}

export const DEFAULT_SMART_LLM_TIMEOUT_MS = 8000;

/**
 * Normalized snapshot of a live SmartApproval's LLM-relevant settings. Used by
 * the config hot-reload path to compare the incoming TOML `[approval.llm]`
 * against the sub-engine that was built once at boot: the SmartApproval
 * instance is never rebuilt on reload, so a reload that changes any of these
 * fields must be REJECTED (rather than silently keep hitting the stale
 * boot-time endpoint/model/key). `provider` defaults to `'openai'` so the
 * comparison is stable regardless of how the engine was constructed.
 */
export interface SmartLlmSnapshot {
  endpoint: string;
  model: string;
  api_key?: string;
  timeout_ms?: number;
  provider: string;
  fail_closed: boolean;
}

/**
 * Parse the LLM response body and extract a {allow, reason} judgement.
 * Throws when the structure is unusable; the caller maps that to a
 * fail-closed deny (or fail-open allow with warning).
 */
function parseOpenAiResponse(raw: string): LlmJudgement {
  const root = JSON.parse(raw);
  const content: unknown = root?.choices?.[0]?.message?.content;
  if (typeof content !== 'string') {
    throw new Error('LLM response missing choices[0].message.content string');
  }

  // The content itself should be JSON {allow, reason}. We tolerate fenced
  // code blocks (``` ... ```) and stray whitespace by grabbing the first
  // {...} block in the string.
  const match = content.match(/\{[\s\S]*\}/);
  if (!match) {
    throw new Error('LLM content has no JSON object');
  }
  const judgement = JSON.parse(match[0]);
  if (typeof judgement.allow !== 'boolean') {
    throw new Error('LLM JSON missing boolean `allow`');
  }
  const reason = typeof judgement.reason === 'string' ? judgement.reason : '';
  return { allow: judgement.allow, reason };
}

const SYSTEM_PROMPT = [
  'You are a security gatekeeper for an SSH command executor.',
  'Decide whether the proposed command is safe to run on the described host.',
  'Reply with ONLY a single JSON object of the shape {"allow": true|false, "reason": "..."}.',
  'Deny destructive operations (rm -rf, dd, mkfs, shutdown, user/credential changes) unless the host description explicitly authorises them.',
].join(' ');

const SMART_PROMPT_FIELD_MAX_BYTES = 16 * 1024;
const TRUNCATION_MARKER = '\n<truncated>';

function redactAndBoundPromptField(input: string | undefined): string {
  const redacted = redactApprovalText(input);
  const encoded = Buffer.from(redacted, 'utf8');
  if (encoded.byteLength <= SMART_PROMPT_FIELD_MAX_BYTES) return redacted;

  const markerBytes = Buffer.byteLength(TRUNCATION_MARKER, 'utf8');
  let end = SMART_PROMPT_FIELD_MAX_BYTES - markerBytes;
  while (end > 0 && (encoded[end] & 0xc0) === 0x80) end--;
  return encoded.subarray(0, end).toString('utf8') + TRUNCATION_MARKER;
}

function commandWithoutAppendedDescription(ctx: ApprovalContext): string {
  if (!ctx.description) return ctx.command;
  const normalizedDescription = ctx.description
    .replace(/[\r\n]+/g, ' ')
    .replace(/[\t\f\v ]+/g, ' ')
    .trim();
  if (!normalizedDescription) return ctx.command;
  const suffix = ` # ${normalizedDescription}`;
  return ctx.command.endsWith(suffix)
    ? ctx.command.slice(0, -suffix.length)
    : ctx.command;
}

function buildUserPrompt(ctx: ApprovalContext): string {
  const profileId = redactAndBoundPromptField(ctx.profile.id);
  const profileDescription = redactAndBoundPromptField(ctx.profile.description);
  const profileBlock = profileDescription
    ? `Profile: ${profileId}\nDescription: ${profileDescription}`
    : `Profile: ${profileId}`;
  const command = redactAndBoundPromptField(commandWithoutAppendedDescription(ctx));
  const description = redactAndBoundPromptField(ctx.description);
  const descBlock = description ? `\nCommand intent: ${description}` : '';
  return [
    profileBlock,
    `Tool: ${ctx.tool}`,
    `Command:\n${command}${descBlock}`,
    'Respond with the JSON object only.',
  ].join('\n\n');
}

export class SmartApproval implements ApprovalEngine {
  constructor(private readonly opts: SmartApprovalOptions) {
    const provider = opts.llm?.provider ?? 'openai';
    if (provider !== 'openai') {
      throw new Error(`smart approval provider "${provider}" is not supported; use "openai"`);
    }
    if (!opts.llm?.endpoint) {
      throw new Error('smart approval mode requires [approval.llm].endpoint');
    }
    if (!opts.llm?.model) {
      throw new Error('smart approval mode requires [approval.llm].model');
    }
  }

  /**
   * Normalized view of the LLM settings this instance was built with. The
   * config hot-reload path compares this against the reloaded TOML so a change
   * to endpoint/model/api_key/timeout_ms/provider/fail_closed is rejected
   * instead of silently ignored (the instance is never rebuilt on reload).
   */
  describeConfig(): SmartLlmSnapshot {
    return {
      endpoint: this.opts.llm.endpoint,
      model: this.opts.llm.model,
      api_key: this.opts.llm.api_key,
      timeout_ms: this.opts.llm.timeout_ms,
      provider: this.opts.llm.provider ?? 'openai',
      fail_closed: this.opts.fail_closed !== false,
    };
  }

  async decide(ctx: ApprovalContext): Promise<ApprovalDecision> {
    const fail_closed = this.opts.fail_closed !== false; // default true
    const fetchImpl = this.opts.fetchImpl ?? (globalThis.fetch as any);
    if (!fetchImpl) {
      return this.failClosedDecision(
        fail_closed,
        'smart approval: no fetch implementation available',
        'smart-llm:no-fetch',
      );
    }

    const timeoutMs = this.opts.llm.timeout_ms ?? DEFAULT_SMART_LLM_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const body = JSON.stringify({
      model: this.opts.llm.model,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: buildUserPrompt(ctx) },
      ],
      temperature: 0,
      response_format: { type: 'json_object' },
    });

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.opts.llm.api_key) {
      headers['Authorization'] = `Bearer ${this.opts.llm.api_key}`;
    }

    let phase: 'request' | 'body' = 'request';
    let raw: string;
    try {
      const response: { ok: boolean; status: number; text: () => Promise<string> } = await fetchImpl(this.opts.llm.endpoint, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        const reason = `smart approval: LLM returned HTTP ${response.status}`;
        return this.failClosedDecision(fail_closed, reason, `smart-llm:http-${response.status}`);
      }

      phase = 'body';
      raw = await response.text();
    } catch (err: any) {
      const aborted = err?.name === 'AbortError' || /aborted/i.test(String(err?.message ?? ''));
      if (aborted) {
        return this.failClosedDecision(
          fail_closed,
          `smart approval: LLM request timed out after ${timeoutMs}ms`,
          'smart-llm:timeout',
        );
      }
      if (phase === 'request') {
        return this.failClosedDecision(
          fail_closed,
          `smart approval: LLM request failed: ${err?.message ?? err}`,
          'smart-llm:transport-error',
        );
      }
      return this.failClosedDecision(
        fail_closed,
        `smart approval: failed to read LLM body: ${err?.message ?? err}`,
        'smart-llm:read-error',
      );
    } finally {
      clearTimeout(timer);
    }

    let judgement: LlmJudgement;
    try {
      judgement = parseOpenAiResponse(raw);
    } catch (err: any) {
      return this.failClosedDecision(
        fail_closed,
        `smart approval: malformed LLM JSON: ${err?.message ?? err}`,
        'smart-llm:malformed-json',
      );
    }

    return {
      decision: judgement.allow ? 'allow' : 'deny',
      reason: judgement.reason || (judgement.allow ? 'LLM allowed' : 'LLM denied'),
      decided_by: 'smart-llm',
      decided_at: new Date().toISOString(),
      mode: 'smart',
    };
  }

  private failClosedDecision(
    fail_closed: boolean,
    reason: string,
    decided_by: string,
  ): ApprovalDecision {
    if (fail_closed) {
      return {
        decision: 'deny',
        reason,
        decided_by,
        decided_at: new Date().toISOString(),
        mode: 'smart',
      };
    }
    // fail-open: warn loudly so operators see this in stderr, then allow.
    console.warn(`[ssh-mcp][smart-approval] fail-open allow: ${reason}`);
    return {
      decision: 'allow',
      reason: `${reason} (fail_closed=false; allowed with warning)`,
      decided_by,
      decided_at: new Date().toISOString(),
      mode: 'smart',
    };
  }
}
