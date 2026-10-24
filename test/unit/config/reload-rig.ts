import { ConfigReloader } from '../../../src/config/reload.js';
import type { ConfigSource } from '../../../src/config/loaded.js';
import type { AclOptions } from '../../../src/config/windows-acl.js';
import { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';
import { PolicyEngine, resolvePolicyRules } from '../../../src/policy/engine.js';
import { AuditStore } from '../../../src/audit/store.js';
import type { AppConfig } from '../../../src/types.js';

/**
 * A real ConfigReloader over real deps, wired as main() wires them: the reload suites,
 * the reload-config tool tests and the live integration suite each built this by hand.
 *
 * Kept out of helpers.ts on purpose: that module is fs-only and imported by suites that
 * mock `os` and the ACL check, and this one pulls in the whole reload path. A suite
 * that mocks a module the reload path uses imports this module after its mocks (after
 * `vi.resetModules()`), so the reloader is built from the mocked graph.
 */

/** When the rig's server started: fixed, so a reload's new loadedAt is told apart from it. */
export const STARTED_AT = '2026-10-23T00:00:00.000Z';

export interface ReloaderOptions {
  config: AppConfig;
  /** The config file the reloader reads. */
  path: string;
  auditPath: string;
  /** Default `file`. */
  source?: ConfigSource;
  /** Of the startup bytes; default null, as for a source with no file. */
  sha256?: string | null;
  /** Default `{}`: the posture with no ACL flags. */
  aclOptions?: AclOptions;
  /** The object the transfer tools read; default `{}`. */
  localPath?: { transferRoot?: string };
}

export interface ReloaderRig {
  registry: ConnectionRegistry;
  policy: PolicyEngine;
  audit: AuditStore;
  localPath: { transferRoot?: string };
  reloader: ConfigReloader;
}

export function buildReloader(o: ReloaderOptions): ReloaderRig {
  const { config } = o;
  const registry = new ConnectionRegistry(config, 'insecure');
  const policy = new PolicyEngine(resolvePolicyRules(config.profiles, config.policy));
  const audit = new AuditStore(o.auditPath);
  const localPath = o.localPath ?? {};
  const reloader = new ConfigReloader({
    aclOptions: o.aclOptions ?? {},
    registry,
    policy,
    audit,
    localPath,
    startup: { config, source: o.source ?? 'file', path: o.path, sha256: o.sha256 ?? null, loadedAt: STARTED_AT },
  });
  return { registry, policy, audit, localPath, reloader };
}
