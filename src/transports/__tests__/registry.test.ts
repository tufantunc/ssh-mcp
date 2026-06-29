/**
 * TransportRegistry.profile() — per-source approval/description read path.
 *
 * The WIP (wip/per-source-approval) shipped the data path but lacked a test
 * proving that a per-source `description` + `approval` override actually
 * propagate the full distance: TOML loader -> ServerConfig -> registry.profile()
 * -> ApprovalEngine resolution. This suite closes that gap.
 *
 * No transport is ever created here (register() only records config; profile()
 * reads the config map), so no sandbox sshd is required.
 */
import { describe, it, expect, vi } from 'vitest';

import { TransportRegistry } from '../registry.js';
import { parseTomlConfig } from '../../config/toml-loader.js';
import { buildApprovalEngineFromConfig } from '../../approval/engine.js';
import type { ApprovalContext } from '../../approval/types.js';

/**
 * Two sources: a plain default (`lab`, no override -> global yolo) and a
 * locked-down DC (`dc03`) carrying a policy description + a smart override.
 * `lab` is listed first so it becomes the registry default.
 */
const TWO_SOURCE_TOML = `
[[sources]]
id = "lab"
host = "lab.example"
user = "root"
auth = "kerberos"

[[sources]]
id = "dc03"
host = "dc03.css.com.tw"
user = "css\\\\c19087"
auth = "kerberos"
description = '''allow only NTDS\\My thumbprint 8A00772D4491E2E71218405BDDE5A5FE3E9C7DBE certificate-object writes; deny PFX, private key reads, restart, reboot'''
approval = { mode = "smart" }
`;

function registryFrom(toml: string): { registry: TransportRegistry; cfg: ReturnType<typeof parseTomlConfig> } {
  const cfg = parseTomlConfig(toml);
  const registry = new TransportRegistry();
  // Mirror src/index.ts bootstrapRegistry(): register in source order.
  for (const src of cfg.sources) registry.register(src);
  if (cfg.defaultName) registry.setDefault(cfg.defaultName);
  return { registry, cfg };
}

describe('TransportRegistry.profile() — read path', () => {
  it('surfaces per-source description + approval override from the loaded config', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);

    const dc03 = registry.profile('dc03');
    expect(dc03.id).toBe('dc03');
    expect(dc03.description).toContain('NTDS\\My');
    expect(dc03.description).toContain('8A00772D4491E2E71218405BDDE5A5FE3E9C7DBE');
    expect(dc03.approval?.mode).toBe('smart');
  });

  it('returns an override-free profile for sources without description/approval', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);

    const lab = registry.profile('lab');
    expect(lab.id).toBe('lab');
    expect(lab.description).toBeUndefined();
    expect(lab.approval).toBeUndefined();
  });

  it('falls back to the registry default when no name is given (after an explicit default is set)', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);

    // With multiple sources the omit-name shortcut is enabled only by a
    // deliberate setDefault() (PR #3 R1 fix: never silently pick a host).
    registry.setDefault('lab');
    const def = registry.profile();
    expect(def.id).toBe('lab');
    expect(def.approval).toBeUndefined();
  });

  it('throws on an unknown connection name (same contract as get())', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);
    expect(() => registry.profile('does-not-exist')).toThrow(/Unknown connection name/);
  });
});

describe('per-source approval propagates loader -> registry -> engine', () => {
  it('drives engine resolution by source: dc03 -> smart (sees description), lab -> default yolo', async () => {
    const { registry, cfg } = registryFrom(TWO_SOURCE_TOML);

    // Loader extracted the per-source override into perSourceApproval.
    expect(cfg.perSourceApproval).toEqual({ dc03: 'smart' });

    // Capture the smart LLM request body so we can assert the per-source
    // description rode all the way into the prompt.
    const bodies: string[] = [];
    const fetchStub = vi.fn(async (_url: string, init: { body: string }) => {
      bodies.push(init.body);
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            choices: [{ message: { content: '{"allow": true, "reason": "policy permits certutil"}' } }],
          }),
      };
    });

    const dispatcher = buildApprovalEngineFromConfig(
      {
        defaultMode: 'yolo',
        llm: { endpoint: 'http://stub/llm', model: 'stub-model', api_key: 'fake' },
        perSourceModes: Object.values(cfg.perSourceApproval),
      },
      { manualOpts: { webuiEnabled: false }, smartFetchImpl: fetchStub as any },
    );

    // dc03 profile -> smart sub-engine (override beats global yolo default).
    const dc03Ctx: ApprovalContext = {
      profile: registry.profile('dc03'),
      tool: 'exec',
      command: 'certutil -addstore My cert.cer',
    };
    const dc03Decision = await dispatcher.decide(dc03Ctx);
    expect(dc03Decision.mode).toBe('smart');
    expect(dc03Decision.decided_by).toBe('smart-llm');
    expect(dc03Decision.decision).toBe('allow');
    expect(fetchStub).toHaveBeenCalledTimes(1);
    // The per-source description reached the LLM prompt body.
    expect(bodies[0]).toContain('8A00772D4491E2E71218405BDDE5A5FE3E9C7DBE');

    // lab profile (no override) -> global yolo default; no LLM call.
    const labCtx: ApprovalContext = {
      profile: registry.profile('lab'),
      tool: 'exec',
      command: 'uptime',
    };
    const labDecision = await dispatcher.decide(labCtx);
    expect(labDecision.mode).toBe('yolo');
    expect(labDecision.decided_by).toBe('yolo');
    expect(fetchStub).toHaveBeenCalledTimes(1); // unchanged — yolo never calls the LLM
  });
});
