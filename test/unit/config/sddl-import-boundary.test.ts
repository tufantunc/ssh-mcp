import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFile } from 'fs/promises';
import ts from 'typescript';
import { parseDacl, aclIdentity } from '../../../src/config/sddl.js';

/**
 * The boundary that lets the parser's property tests judge an authorization decision on
 * every job rather than only the Windows one.
 *
 * The claim this file used to make was wrong, and the correction is the point. It said an
 * edit reaching for `icacls` inside `parseDacl` would leave the suite green. It would not:
 * the parser tests carry no platform guard, so such an edit fails ~69 of them loudly on
 * Linux — measured. What is actually dangerous is the *next* step. Faced with 69 red parser
 * tests on a change that "obviously only affects Windows", the cheapest repair is
 * `describe.runIf(win32)`, and at that moment the 2000-run property suite stops exercising
 * the decision off Windows and CI goes green for real. A boundary asserted here fails in a
 * place whose only sane repair is to undo the import.
 *
 * Two things this file learned the hard way, both from mutations that survived its first
 * version:
 *
 * 1. Do not pattern-match source text. The first version scanned with a single-quote,
 *    single-line regex, so `from "child_process"` was invisible — and so was the repo's own
 *    multi-line import style, the shape `windows-acl.ts` uses to import from this very
 *    module. It also "checked" the module graph through `require.cache`, which an ESM
 *    `import()` never populates: that assertion could not fail for any content at all.
 *    The specifier list now comes from TypeScript's own preprocessor, and the scanner is
 *    itself tested against a corpus of spellings below.
 * 2. An empty import list is not platform independence. `process.platform` needs no import.
 *    A mutation reading it inside `parseDacl` flipped a NULL DACL — the most open ACL a
 *    file can carry — from `no-dacl` to `restricted` on Windows only, and every test here
 *    passed. Hence both the identifier ban and the behavioural check at the end.
 */

const SDDL_PATH = new URL('../../../src/config/sddl.ts', import.meta.url);
const readSddl = () => readFile(SDDL_PATH, 'utf8');

/**
 * Every module specifier a source file names, however it names it.
 *
 * `preProcessFile` is the compiler's own scanner: quote-agnostic, comment-aware, and it
 * reports static imports, `export … from`, side-effect imports, `require()` and dynamic
 * `import()` in one pass. Replacing three hand-rolled regexes with it is the whole fix.
 */
function specifiersOf(source: string): string[] {
  const info = ts.preProcessFile(source, /* readImportFiles */ true, /* detectJavaScriptImports */ true);
  return [...info.importedFiles, ...info.referencedFiles, ...info.libReferenceDirectives]
    .map((f) => f.fileName);
}

describe('the SDDL parser imports nothing', () => {
  it('names no module at all', async () => {
    expect(
      specifiersOf(await readSddl()),
      'sddl.ts gained an import; read this file’s header before adding one',
    ).toEqual([]);
  });

  /**
   * The scanner's own test. Every one of these was a spelling that defeated the previous
   * version, so the corpus is a regression list rather than a thought experiment: if the
   * detection ever weakens, this fails before the real file is even consulted.
   */
  it.each([
    ["single-quoted named", `import { execFile } from 'child_process';`],
    ["double-quoted named", `import { execFile } from "child_process";`],
    ["multi-line, the repo's own style", `import {\n  execFile,\n  execFileSync,\n} from 'child_process';`],
    ['side-effect only', `import 'os';`],
    ['node: prefixed', `import { existsSync } from 'node:fs';`],
    ['require', `const cp = require('child_process');`],
    ['dynamic import', `const cp = await import('child_process');`],
    ['export … from', `export { execFile } from 'child_process';`],
    ['createRequire, the escape hatch', `import { createRequire } from 'module';`],
    ['relative, back across the cut', `import { classifyReadFailure } from './windows-acl.js';`],
  ])('detects an import written as %s', (_name, line) => {
    expect(specifiersOf(`${line}\nexport const x = 1;\n`)).not.toEqual([]);
  });

  it('rejects the platform reads that need no import', async () => {
    // `process` is a global. An empty import list says nothing about it, and the mutation
    // that proved the point read `process.platform` to change a verdict on Windows only.
    // An identifier is safe to match with a regex — unlike a quoted specifier, it has one
    // spelling.
    const source = await readSddl();
    const reach = source.match(/\bprocess\s*\.\s*(?:platform|env|arch|version)\b/g);
    expect(reach, 'sddl.ts reached for a platform global').toBeNull();
  });
});

describe('the parser gives the same answer on every platform', () => {
  afterEach(() => vi.unstubAllGlobals());

  /**
   * The property the file header claims, asserted directly rather than through the proxy of
   * an import list. These four descriptors are the verdicts that matter most: the most open
   * ACL there is, a write grant, a read-only grant, and an owner-only one.
   */
  const OWNER = 'S-1-5-21-11-22-33-1001';
  const CASES: Array<[string, string]> = [
    ['a NULL DACL', 'D:NO_ACCESS_CONTROL'],
    ['a modify grant to Authenticated Users', 'D:(A;;0x1301bf;;;AU)'],
    ['a read-only grant to BUILTIN\\Users', 'D:(A;;0x1200a9;;;BU)'],
    ['an owner-only descriptor', `D:(A;;FA;;;${OWNER})(A;;FA;;;SY)`],
  ];

  it.each(CASES)('reads %s identically on win32 and linux', (_name, descriptor) => {
    const identity = aclIdentity(OWNER);
    vi.stubGlobal('process', { ...process, platform: 'win32' });
    const onWindows = JSON.stringify(parseDacl(descriptor, identity));
    vi.stubGlobal('process', { ...process, platform: 'linux' });
    const onLinux = JSON.stringify(parseDacl(descriptor, identity));
    expect(onWindows, 'the parser branched on the platform').toBe(onLinux);
  });
});
