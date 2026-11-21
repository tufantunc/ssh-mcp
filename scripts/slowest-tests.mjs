#!/usr/bin/env node
// Prints where a test run's time went, from vitest's JSON report: the slowest files and
// the slowest tests, each with its result. For the CI log, where a test that hits its
// time limit is otherwise the only one whose duration is ever printed.
//
//   node scripts/slowest-tests.mjs <report.json> [count]
import { readFileSync } from 'node:fs';
import { relative } from 'node:path';

const [reportPath, countArg] = process.argv.slice(2);
if (reportPath === undefined) {
  console.error('usage: node scripts/slowest-tests.mjs <report.json> [count]');
  process.exit(2);
}
const count = Number(countArg ?? 25);

let report;
try {
  report = JSON.parse(readFileSync(reportPath, 'utf8'));
} catch (error) {
  // A run that died before it wrote its report has nothing to show; that is not this
  // step's failure to report.
  console.log(`no test report at ${reportPath}: ${error.message}`);
  process.exit(0);
}

const seconds = (ms) => `${(ms / 1000).toFixed(1).padStart(7)} s`;
const files = [];
const tests = [];
for (const file of report.testResults ?? []) {
  const name = relative(process.cwd(), file.name);
  let spent = 0;
  for (const test of file.assertionResults ?? []) {
    const duration = test.duration ?? 0;
    spent += duration;
    tests.push({ duration, status: test.status, name: `${name} > ${test.fullName}` });
  }
  // The file's own span includes its imports and hooks; where the report lacks it, the
  // sum of its tests stands in.
  const span = file.endTime > file.startTime ? file.endTime - file.startTime : spent;
  files.push({ duration: span, status: file.status, name, tests: (file.assertionResults ?? []).length });
}

const total = files.reduce((sum, file) => sum + file.duration, 0);
console.log(`${files.length} test files, ${tests.length} tests, ${seconds(total).trim()} in test files`);
console.log(`\nSlowest ${Math.min(count, files.length)} files`);
for (const file of files.sort((a, b) => b.duration - a.duration).slice(0, count)) {
  console.log(`${seconds(file.duration)}  ${file.status.padEnd(7)} ${file.name} (${file.tests} tests)`);
}
console.log(`\nSlowest ${Math.min(count, tests.length)} tests`);
for (const test of tests.sort((a, b) => b.duration - a.duration).slice(0, count)) {
  console.log(`${seconds(test.duration)}  ${test.status.padEnd(7)} ${test.name}`);
}
