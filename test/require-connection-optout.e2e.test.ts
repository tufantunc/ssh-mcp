import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { ISshTransport } from '../src/transports/types';

// End-to-end coverage of the require_connection opt-out, exercised through the
// REAL resolver (TOML → ResolvedConfig) and the REAL boot-time policy helper
// (ResolvedConfig → TransportRegistry). This is the full integration path the
// pr/connection-name-toml-optout feature adds: a [server].require_connection
// value in a TOML must actually toggle the multi-source omit-name guard at
// runtime. Pre-fix that knob was inert (no registry reader); these tests fail
// closed if the wiring regresses.

const { createTransportMock } = vi.hoisted(() => ({ createTransportMock: vi.fn() }));
vi.mock('../src/transports/factory.js', () => ({ createTransport: createTransportMock }));

import { resolveConfig } from '../src/config/resolver';
import { TransportRegistry } from '../src/transports/registry';
import { applyRegistryConnectionPolicy } from '../src/index';

function stub(): ISshTransport {
  return {
    name: 'ssh2',
    init: vi.fn().mockResolvedValue(undefined),
    exec: vi.fn(),
    execElevated: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  } as unknown as ISshTransport;
}

const multiToml = `
[[sources]]
id = "a"
host = "a.example"
user = "u"
auth = "password"
password = "pw"

[[sources]]
id = "b"
host = "b.example"
user = "u"
auth = "password"
password = "pw"
`;

/**
 * Drive the production composition: parse the TOML via resolveConfig(), register
 * its sources, then apply the boot-time connection policy. Returns the wired
 * registry so the test can assert routing/guard behavior on get().
 */
function bootFromToml(tmp: string, body: string): TransportRegistry {
  const file = path.join(tmp, 'config.toml');
  fs.writeFileSync(file, body);
  const cfg = resolveConfig({ cliSources: [], cliConfigPath: file, env: {} });
  const r = new TransportRegistry();
  for (const s of cfg.sources) r.register(s);
  applyRegistryConnectionPolicy(r, cfg);
  return r;
}

describe('require_connection opt-out — TOML → resolver → registry (end-to-end)', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-rc-e2e-'));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  // A5 (end-to-end): require_connection absent → guard ON → multi-source omit throws.
  it('A5: multi-source TOML, require_connection absent, omitted name THROWS (safe default)', async () => {
    const r = bootFromToml(tmp, multiToml);
    await expect(r.get()).rejects.toThrow(
      /connectionName is required when multiple servers are configured: a, b/,
    );
  });

  // A5: require_connection = true explicit → still throws.
  it('A5: multi-source TOML, [server].require_connection = true, omitted name THROWS', async () => {
    const r = bootFromToml(tmp, `
[server]
require_connection = true
${multiToml}`);
    await expect(r.get()).rejects.toThrow(/connectionName is required/);
  });

  // A4 (end-to-end): require_connection = false → guard OFF → routes to first.
  it('A4: multi-source TOML, [server].require_connection = false, omitted name routes to first (no throw)', async () => {
    const s = stub();
    createTransportMock.mockReturnValue(s);
    const r = bootFromToml(tmp, `
[server]
require_connection = false
${multiToml}`);
    await expect(r.get()).resolves.toBe(s);
  });

  // The opt-out must not weaken explicit-name routing.
  it('A4: opt-out still routes an explicit connectionName correctly', async () => {
    const s = stub();
    createTransportMock.mockReturnValue(s);
    const r = bootFromToml(tmp, `
[server]
require_connection = false
${multiToml}`);
    await expect(r.get('b')).resolves.toBe(s);
  });

  // An explicit default in the TOML still works regardless of the opt-out.
  it('A2: explicit `default = true` source resolves on omitted name even with the guard armed', async () => {
    const s = stub();
    createTransportMock.mockReturnValue(s);
    const r = bootFromToml(tmp, `
[[sources]]
id = "a"
host = "a.example"
user = "u"
auth = "password"
password = "pw"

[[sources]]
id = "b"
host = "b.example"
user = "u"
auth = "password"
password = "pw"
default = true
`);
    await expect(r.get()).resolves.toBe(s);
    expect(r.getDefaultName()).toBe('b');
  });
});
