import type { RegistrySnapshot } from '../types.js';

export function handleProfiles(
  registry: RegistrySnapshot,
  getApprovalMode?: (name: string) => string,
  sourceEditEnabled = false,
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
  // `source_edit_enabled` tells the UI whether to render the live
  // description editor (PR-8). It is true iff a SourceController is wired;
  // in-memory only (Decision D3), so editing never persists to the TOML.
  return { status: 200, body: { profiles: rows, source_edit_enabled: sourceEditEnabled } };
}
