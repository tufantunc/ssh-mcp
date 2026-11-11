#!/usr/bin/env node
/**
 * Turns the V8 coverage the e2e suite's server processes wrote into an lcov file.
 *
 * The e2e suite drives `build/index.js` as a spawned process, so vitest's in-process
 * coverage never sees `main()`: every line of it read as uncovered, and every change
 * there failed Codecov's patch check whatever the e2e suite proved. Run with
 * NODE_V8_COVERAGE set, each child writes its own coverage on exit, and this script
 * maps it back to `src/` through the build's source maps.
 *
 * Converted with the same pair vitest uses, `ast-v8-to-istanbul` over `parseAstAsync`,
 * on purpose. c8 was tried first: it counts every line of a covered file, comments and
 * blank lines included (174 lines of index.ts against vitest's 65), and Codecov merges
 * uploads line by line — so its comment lines would have arrived as new misses. With the
 * same converter both reports name the same lines, and the merge is a union of hits.
 *
 * A child that is SIGKILLed writes nothing; the kill-ladder tests are lost to this
 * report, which is a gap in the measurement, not a claim that their code is untested.
 *
 *   node scripts/e2e-coverage.mjs <NODE_V8_COVERAGE dir> <output lcov path>
 */
import { readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import convert from 'ast-v8-to-istanbul';
import { parseAstAsync } from 'vitest/node';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BUILD = join(ROOT, 'build') + sep;
// vitest.config.ts's `coverage.exclude`, which says why; both reports must name the same files.
const EXCLUDE = new Set(['src/types.ts', 'src/version.ts']);

const [rawDir, outPath] = process.argv.slice(2);
if (!rawDir || !outPath) {
  console.error('usage: node scripts/e2e-coverage.mjs <v8 coverage dir> <output lcov>');
  process.exit(2);
}

/** Per source file: hits summed across processes, keyed by location so the sum is exact. */
const files = new Map();
const key = (loc) => `${loc.start.line}:${loc.start.column}-${loc.end.line}:${loc.end.column}`;

function accumulate(fileCoverage) {
  let acc = files.get(fileCoverage.path);
  if (!acc) {
    acc = { statements: new Map(), functions: new Map(), branches: new Map() };
    files.set(fileCoverage.path, acc);
  }
  for (const [id, loc] of Object.entries(fileCoverage.statementMap)) {
    const k = key(loc);
    const prev = acc.statements.get(k);
    acc.statements.set(k, { line: loc.start.line, hits: (prev?.hits ?? 0) + fileCoverage.s[id] });
  }
  for (const [id, fn] of Object.entries(fileCoverage.fnMap)) {
    const k = key(fn.loc);
    const prev = acc.functions.get(k);
    acc.functions.set(k, { line: fn.loc.start.line, name: fn.name, hits: (prev?.hits ?? 0) + fileCoverage.f[id] });
  }
  for (const [id, branch] of Object.entries(fileCoverage.branchMap)) {
    const k = key(branch.loc);
    const prev = acc.branches.get(k);
    const hits = fileCoverage.b[id].map((h, i) => h + (prev?.hits[i] ?? 0));
    acc.branches.set(k, { line: branch.line ?? branch.loc.start.line, hits });
  }
}

const sources = new Map();
async function source(path) {
  if (!sources.has(path)) {
    sources.set(path, (async () => {
      const code = await readFile(path, 'utf8');
      const map = JSON.parse(await readFile(`${path}.map`, 'utf8'));
      return { code, map };
    })());
  }
  return sources.get(path);
}

const dumps = (await readdir(rawDir)).filter((f) => f.endsWith('.json'));
let scripts = 0;
for (const dump of dumps) {
  const { result } = JSON.parse(await readFile(join(rawDir, dump), 'utf8'));
  for (const script of result) {
    if (!script.url.startsWith('file://')) continue;
    const path = fileURLToPath(script.url);
    if (!path.startsWith(BUILD) || !path.endsWith('.js')) continue;
    const { code, map } = await source(path);
    const converted = await convert({
      code,
      sourceMap: map,
      ast: parseAstAsync(code),
      coverage: { functions: script.functions, url: script.url },
    });
    for (const fileCoverage of Object.values(converted)) accumulate(fileCoverage);
    scripts++;
  }
}

const lines = [];
for (const [path, acc] of [...files].sort(([a], [b]) => a.localeCompare(b))) {
  const name = relative(ROOT, path).split(sep).join('/');
  if (EXCLUDE.has(name)) continue;
  lines.push('TN:', `SF:${name}`);
  const fns = [...acc.functions.values()];
  for (const fn of fns) lines.push(`FN:${fn.line},${fn.name}`);
  for (const fn of fns) lines.push(`FNDA:${fn.hits},${fn.name}`);
  lines.push(`FNF:${fns.length}`, `FNH:${fns.filter((f) => f.hits > 0).length}`);
  // A line's count is its busiest statement's, as istanbul's own line coverage does.
  const byLine = new Map();
  for (const { line, hits } of acc.statements.values()) {
    byLine.set(line, Math.max(byLine.get(line) ?? 0, hits));
  }
  const sortedLines = [...byLine].sort(([a], [b]) => a - b);
  for (const [line, hits] of sortedLines) lines.push(`DA:${line},${hits}`);
  lines.push(`LF:${sortedLines.length}`, `LH:${sortedLines.filter(([, h]) => h > 0).length}`);
  let brf = 0;
  let brh = 0;
  [...acc.branches.values()].forEach((branch, block) => {
    branch.hits.forEach((hits, i) => {
      lines.push(`BRDA:${branch.line},${block},${i},${hits}`);
      brf++;
      if (hits > 0) brh++;
    });
  });
  lines.push(`BRF:${brf}`, `BRH:${brh}`, 'end_of_record');
}

await mkdir(dirname(resolve(outPath)), { recursive: true });
await writeFile(outPath, lines.join('\n') + '\n');
console.log(`e2e coverage: ${scripts} scripts from ${dumps.length} processes -> ${outPath}`);
