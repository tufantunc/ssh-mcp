import type { AuditTail } from '../types.js';

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;

export async function handleExecutions(
  audit: AuditTail | undefined,
  query: URLSearchParams,
): Promise<{ status: number; body: unknown }> {
  if (!audit) {
    return { status: 200, body: { executions: [], note: 'audit log not wired' } };
  }
  const profile = query.get('profile') || undefined;
  const limitRaw = query.get('limit');
  let limit = DEFAULT_LIMIT;
  if (limitRaw !== null) {
    const parsed = parseInt(limitRaw, 10);
    if (!isNaN(parsed) && parsed > 0) {
      limit = Math.min(parsed, MAX_LIMIT);
    }
  }
  try {
    const records = await audit.tail({ profile, limit });
    return { status: 200, body: { executions: records } };
  } catch (err: any) {
    return { status: 500, body: { error: err?.message || String(err) } };
  }
}
