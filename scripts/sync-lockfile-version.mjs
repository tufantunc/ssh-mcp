#!/usr/bin/env node
/**
 * Copies package.json's version into package-lock.json's own two version fields:
 * the top-level `version` and `packages[""].version`.
 *
 * `changeset version` bumps package.json and never touches the lockfile, so these
 * fell one release behind on every release — on main at 2.19.0 the lockfile still
 * said 2.16.0. Nothing reads them at runtime (src/version.ts reads package.json),
 * but `npm ci` and `npm version` both treat a mismatch as drift, and a stale value
 * is noise in every Dependabot PR that rewrites the file.
 *
 * Deliberately not `npm install --package-lock-only`: that re-resolves the tree and
 * rewrites entries the installed npm version formats differently — measured with
 * npm 11.9.0, it stripped every `libc` field, which is what picks the musl or glibc
 * build of a native optional dependency. This script edits the two fields and
 * nothing else.
 *
 * Wired to the `version` npm script after sync-server-json.mjs, so the rewrite
 * lands in the "Version Packages" pull request. `--check` reports staleness instead
 * of fixing it.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const checkOnly = process.argv.slice(2).includes('--check');

const root = new URL('..', import.meta.url);
const lockFile = new URL('package-lock.json', root);

const pkg = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
const lock = JSON.parse(readFileSync(lockFile, 'utf8'));

// A lockfile copied in from another project would otherwise be stamped with this
// package's version and look current.
if (lock.name !== pkg.name) {
  console.error(
    `sync-lockfile-version: package-lock.json belongs to ${lock.name ?? 'an unnamed package'}, ` +
    `not ${pkg.name}.`,
  );
  process.exit(1);
}

const rootEntry = lock.packages?.[''];
const stale = lock.version !== pkg.version || (rootEntry && rootEntry.version !== pkg.version);

if (!stale) {
  console.log(`sync-lockfile-version: package-lock.json already at ${pkg.version}`);
  process.exit(0);
}

if (checkOnly) {
  console.error(
    `sync-lockfile-version: package-lock.json is stale — ${lock.version}, but package.json ` +
    `is at ${pkg.version}. Run \`node scripts/sync-lockfile-version.mjs\` and commit the result.`,
  );
  process.exit(1);
}

lock.version = pkg.version;
if (rootEntry) rootEntry.version = pkg.version;
writeFileSync(lockFile, `${JSON.stringify(lock, null, 2)}\n`);
console.log(`sync-lockfile-version: package-lock.json -> ${pkg.version}`);
