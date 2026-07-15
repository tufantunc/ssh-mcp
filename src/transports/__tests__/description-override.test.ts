/**
 * TransportRegistry live description override — PR-8 data path (Decision D3).
 *
 * Proves the in-memory per-source description override:
 *   - profile() / list() surface the override on top of the TOML description
 *   - clearing (null) reverts to the TOML-seeded value
 *   - the approval engine RE-READS the effective description on its NEXT
 *     decision (an override edited mid-session rides into the smart-mode prompt)
 *   - NOTHING is written to disk: no fs surface, the parsed config object is
 *     never mutated, and a fresh registry from the same TOML has no override
 *
 * No transport is created (register() only records config; profile() reads the
 * config map + override map), so no sandbox sshd is required.
 */
import { describe, it, expect, vi } from 'vitest';

import { TransportRegistry } from '../registry.js';
import { parseTomlConfig } from '../../config/toml-loader.js';
import { buildApprovalEngineFromConfig } from '../../approval/engine.js';
import type { ApprovalContext } from '../../approval/types.js';

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
description = "boot policy: deny PFX and private key reads"
approval = { mode = "smart" }
`;

function registryFrom(toml: string): { registry: TransportRegistry; cfg: ReturnType<typeof parseTomlConfig> } {
  const cfg = parseTomlConfig(toml);
  const registry = new TransportRegistry();
  for (const src of cfg.sources) registry.register(src);
  if (cfg.defaultName) registry.setDefault(cfg.defaultName);
  return { registry, cfg };
}

describe('TransportRegistry live description override — read path', () => {
  it('profile() returns the live override on top of the TOML description', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);

    expect(registry.profile('dc03').description).toBe('boot policy: deny PFX and private key reads');

    const ret = registry.setDescription('dc03', 'LIVE: also deny certutil -delstore');
    expect(ret).toBe('LIVE: also deny certutil -delstore');
    expect(registry.profile('dc03').description).toBe('LIVE: also deny certutil -delstore');
    expect(registry.getDescriptionOverride('dc03')).toBe('LIVE: also deny certutil -delstore');
  });

  it('list() reflects the override too (WebUI status surface)', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);
    registry.setDescription('dc03', 'LIVE override');
    const row = registry.list().find(r => r.name === 'dc03')!;
    expect(row.description).toBe('LIVE override');
  });

  it('an override can blank a description (empty string is a real value)', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);
    registry.setDescription('dc03', '');
    expect(registry.profile('dc03').description).toBe('');
    expect(registry.getDescriptionOverride('dc03')).toBe('');
  });

  it('clearing (null) reverts to the TOML-seeded description', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);
    registry.setDescription('dc03', 'LIVE override');
    expect(registry.profile('dc03').description).toBe('LIVE override');

    const reverted = registry.setDescription('dc03', null);
    expect(reverted).toBe('boot policy: deny PFX and private key reads');
    expect(registry.profile('dc03').description).toBe('boot policy: deny PFX and private key reads');
    expect(registry.getDescriptionOverride('dc03')).toBeUndefined();
  });

  it('a source with no TOML description starts undefined and an override fills it', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);
    expect(registry.profile('lab').description).toBeUndefined();
    registry.setDescription('lab', 'newly described at runtime');
    expect(registry.profile('lab').description).toBe('newly described at runtime');
    // Clearing removes it again.
    registry.setDescription('lab', null);
    expect(registry.profile('lab').description).toBeUndefined();
  });

  it('falls back to the default source when name is omitted (after an explicit default is set)', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);
    // With multiple sources the omit-name shortcut is enabled only by a
    // deliberate setDefault() (PR #3 R1 fix: never silently pick a host).
    registry.setDefault('lab');
    expect(registry.getEffectiveDescription()).toBe('');
    registry.setDescription('lab', 'default-host note');
    expect(registry.getEffectiveDescription()).toBe('default-host note');
  });

  it('throws on an unknown connection name (same contract as get()/profile())', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);
    expect(() => registry.setDescription('does-not-exist', 'x')).toThrow(/Unknown connection name/);
    expect(() => registry.getEffectiveDescription('nope')).toThrow(/Unknown connection name/);
  });
});

describe('approval engine RE-READS the effective description live (override > TOML)', () => {
  it('a description edited mid-session rides into the NEXT smart-mode decision', async () => {
    const { registry, cfg } = registryFrom(TWO_SOURCE_TOML);
    expect(cfg.perSourceApproval).toEqual({ dc03: 'smart' });

    const bodies: string[] = [];
    const fetchStub = vi.fn(async (_url: string, init: { body: string }) => {
      bodies.push(init.body);
      return new Response(
        JSON.stringify({ choices: [{ message: { content: '{"allow": true, "reason": "ok"}' } }] }),
        { status: 200 },
      );
    });

    const dispatcher = buildApprovalEngineFromConfig(
      {
        defaultMode: 'yolo',
        llm: { endpoint: 'http://stub/llm', model: 'stub-model', api_key: 'fake' },
        perSourceModes: Object.values(cfg.perSourceApproval),
      },
      { manualOpts: { webuiEnabled: false }, smartFetchImpl: fetchStub as any },
    );

    // First decision: the BOOT description rides into the prompt. The engine
    // reads registry.profile() fresh, exactly like src/index.ts's exec handler.
    await dispatcher.decide({ profile: registry.profile('dc03'), tool: 'exec', command: 'certutil -addstore My c.cer' } as ApprovalContext);
    expect(bodies[0]).toContain('boot policy: deny PFX and private key reads');
    expect(bodies[0]).not.toContain('LIVE EDIT');

    // Operator live-edits the description (in-memory only).
    registry.setDescription('dc03', 'LIVE EDIT: now also deny reg.exe writes');

    // Second decision: the NEW description rides into the prompt — proving the
    // engine re-reads rather than caching the boot value.
    await dispatcher.decide({ profile: registry.profile('dc03'), tool: 'exec', command: 'reg add HKLM\\X' } as ApprovalContext);
    expect(bodies[1]).toContain('LIVE EDIT: now also deny reg.exe writes');
    expect(bodies[1]).not.toContain('boot policy: deny PFX');
    expect(fetchStub).toHaveBeenCalledTimes(2);
  });
});

describe('description override is IN-MEMORY ONLY (Decision D3 — no silent persistence)', () => {
  it('never mutates the parsed config object and never touches the fs', () => {
    const { registry, cfg } = registryFrom(TWO_SOURCE_TOML);
    const dc03Cfg = cfg.sources.find(s => s.name === 'dc03')!;
    const original = dc03Cfg.description;

    registry.setDescription('dc03', 'LIVE override that must not persist');

    // The TOML-parsed ServerConfig is untouched — only the override Map changed.
    expect(dc03Cfg.description).toBe(original);
  });

  it('a fresh registry built from the SAME toml has NO override (proves nothing was written back)', () => {
    const first = registryFrom(TWO_SOURCE_TOML);
    first.registry.setDescription('dc03', 'session-1 live edit');
    expect(first.registry.profile('dc03').description).toBe('session-1 live edit');

    // Simulate a process restart: re-parse the identical TOML source.
    const second = registryFrom(TWO_SOURCE_TOML);
    expect(second.registry.getDescriptionOverride('dc03')).toBeUndefined();
    expect(second.registry.profile('dc03').description).toBe('boot policy: deny PFX and private key reads');
  });

  it('the registry exposes no disk/fs/persist surface for descriptions', () => {
    const { registry } = registryFrom(TWO_SOURCE_TOML);
    const keys = [
      ...Object.getOwnPropertyNames(registry),
      ...Object.getOwnPropertyNames(Object.getPrototypeOf(registry)),
    ];
    const forbidden = /persist|writeFile|toml|disk|flush|save/i;
    expect(keys.some(k => forbidden.test(k))).toBe(false);
  });
});
