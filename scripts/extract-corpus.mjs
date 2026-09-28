#!/usr/bin/env node
// Builds the differential corpus: every quoted literal in the policy suites
// (each is a valid classification probe, whatever it was written for), plus
// deterministic backslash rewrites of each, so the run covers inputs the
// suites never wrote on purpose. Output is sorted and de-duplicated so the
// same corpus can be classified by two revisions of the tree.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dir = new URL('../test/unit/policy/', import.meta.url);
const entries = new Set();

for (const file of readdirSync(dir)) {
  if (!file.endsWith('.test.ts')) continue;
  const text = readFileSync(join(dir.pathname, file), 'utf8');
  for (const m of text.matchAll(/'((?:[^'\\\n]|\\.)*)'/g)) entries.add(m[1]);
  for (const m of text.matchAll(/"((?:[^"\\\n]|\\.)*)"/g)) entries.add(m[1]);
}

const probes = new Set();
for (const literal of entries) {
  probes.add(literal);
  if (literal.length === 0 || literal.length > 100) continue;
  if (/['"\\\n]/.test(literal)) continue;   // variants stay single-token-simple
  probes.add(literal.replaceAll('/', '\\'));
  const firstSpace = literal.indexOf(' ');
  const first = firstSpace === -1 ? literal : literal.slice(0, firstSpace);
  const rest = firstSpace === -1 ? '' : literal.slice(firstSpace);
  if (!first.includes('/')) {
    const exe = first.includes('.') ? first : `${first}.exe`;
    probes.add(`C:\\Windows\\System32\\${exe}${rest}`);
    probes.add(`"${first}"${rest}`);
    if (first.length > 1) probes.add(`${first.slice(0, 1)}\\${first.slice(1)}${rest}`);
  }
}

const corpus = [...probes].sort();
writeFileSync(new URL('../test/differential/corpus.json', import.meta.url), `${JSON.stringify(corpus, null, 1)}\n`);
console.log(`corpus: ${corpus.length} probes from ${entries.size} literals`);
