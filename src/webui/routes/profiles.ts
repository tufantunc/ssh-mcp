import type { RegistrySnapshot } from '../types.js';

export function handleProfiles(
  registry: RegistrySnapshot,
  getApprovalMode?: (name: string) => string,
): { status: number; body: unknown } {
  const rows = registry.list().map(row => ({
    id: row.name,
    name: row.name,
    description: row.description ?? '',
    host: row.host,
    port: row.port,
    user: row.username,
    auth: row.authMode,
    transport: row.transport,
    connected: row.connected,
    default: row.isDefault,
    approval_mode_effective: getApprovalMode ? getApprovalMode(row.name) : 'unknown',
  }));
  return { status: 200, body: { profiles: rows } };
}
