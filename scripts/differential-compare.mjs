#!/usr/bin/env node
// Compares two differential runs. The invariant this harness measures over its
// corpus: a command's
// class either stays or rises — nothing drops (a stricter reading may cost an
// approval; it may never cost a refusal).
import { readFileSync } from 'node:fs';

const RANK = { 'read-only': 0, safe: 1, destructive: 2, privileged: 3 };
const [baseFile, headFile] = process.argv.slice(2);
if (!baseFile || !headFile) {
  console.error('usage: differential-compare.mjs <base.json> <head.json>');
  process.exit(2);
}
const base = JSON.parse(readFileSync(baseFile, 'utf8'));
const head = JSON.parse(readFileSync(headFile, 'utf8'));

let same = 0;
const rises = [];
const drops = [];
for (const command of Object.keys(base)) {
  const before = base[command];
  const after = head[command];
  if (after === undefined) { drops.push([command, before, '(absent)']); continue; }
  if (RANK[after] === RANK[before]) { same++; continue; }
  (RANK[after] > RANK[before] ? rises : drops).push([command, before, after]);
}

for (const [command, before, after] of rises) console.log(`RISE  ${before} -> ${after}  ${command}`);
for (const [command, before, after] of drops) console.log(`DROP  ${before} -> ${after}  ${command}`);
console.log(`\n${same} unchanged, ${rises.length} risen, ${drops.length} dropped`);
process.exit(drops.length === 0 ? 0 : 1);
