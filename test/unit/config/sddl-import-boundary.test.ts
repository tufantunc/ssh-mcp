import { describe, it, expect } from 'vitest';
import { readFile } from 'fs/promises';
import { createRequire } from 'module';

/**
 * The guarantee the sddl.ts split exists to create, asserted rather than trusted.
 *
 * `parseDacl` is the security decision for the whole Windows config path, and the reason
 * its 2000-run property tests can guard that decision on the Linux job is that the parser
 * touches nothing platform-specific. Before the split, that was true only by discipline: an
 * edit reaching for `run(ICACLS, …)` inside `parseDacl` would compile, read as a one-liner,
 * and quietly turn every parser test into a Windows-only test — while the suite stayed
 * green, because the property and unit files would simply stop exercising it off Windows.
 *
 * A separate file does not prevent that on its own. This does.
 */

const SDDL = new URL('../../../src/config/sddl.ts', import.meta.url);

/** Node builtins whose presence would make the parser platform-bound. */
const FORBIDDEN = ['child_process', 'fs', 'fs/promises', 'os', 'util', 'path'];

describe('the SDDL parser stays platform-independent', () => {
  it('imports nothing at all', async () => {
    const source = await readFile(SDDL, 'utf8');
    const imports = [...source.matchAll(/^\s*(?:import|export)\s.*?from\s*'([^']+)'/gm)].map((m) => m[1]);
    // Not "imports no builtins" but "imports nothing": the file is pure grammar, and the
    // moment it needs anything the question of what it may need is worth a human answering.
    expect(imports, 'sddl.ts gained an import; see this file’s header before adding one').toEqual([]);
  });

  it.each(FORBIDDEN)('does not reach for %s by any spelling', async (mod) => {
    // Belt to the braces above: `require`, a dynamic `import()`, or a side-effect-only
    // `import 'fs'` would all slip past a `from`-anchored scan.
    const source = await readFile(SDDL, 'utf8');
    const pattern = new RegExp(`(?:require\\(|import\\(|import\\s+)['"]${mod.replace('/', '\\/')}['"]`);
    expect(pattern.test(source), `sddl.ts reaches for ${mod}`).toBe(false);
  });

  it('really does load without a platform module in its graph', async () => {
    // The static checks describe the text; this one describes the module. If sddl.ts ever
    // pulls in a platform module transitively — through a helper that looks innocent — the
    // text scans above would pass and this would not.
    const require = createRequire(import.meta.url);
    const before = new Set(Object.keys(require.cache));
    await import('../../../src/config/sddl.js');
    const added = Object.keys(require.cache).filter((k) => !before.has(k));
    expect(added.filter((k) => /node_modules|child_process|[\\/]os\.js/.test(k))).toEqual([]);
  });
});
