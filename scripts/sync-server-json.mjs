#!/usr/bin/env node
/**
 * Copies package.json's version into server.json, the MCP registry entry.
 *
 * The version lives there twice, and both have to agree with the version that
 * reaches npm:
 *
 *   version            the registry listing's own version. The registry refuses
 *                      to publish a version of a server it already has, so a
 *                      stale value here fails the publish outright.
 *   packages[].version the npm version the listing points at. The registry
 *                      resolves it against `registry.npmjs.org/<identifier>/<version>`
 *                      and reads `mcpName` out of that exact manifest — so a
 *                      stale value either 404s or, worse, lists a version other
 *                      than the one that just shipped.
 *
 * Wired to the `version` npm script, which is what changesets/action runs when
 * it opens or updates the "Version Packages" pull request. It commits whatever
 * the version command left in the working tree, so the rewrite lands in that PR
 * alongside the package.json bump and the CHANGELOG entry — and main is already
 * correct by the time the release job publishes from it.
 *
 * Nothing else in the repo carries the version: src/version.ts reads it from
 * package.json at runtime.
 *
 * `--check` reports staleness instead of fixing it, for the release job to run
 * before it publishes a listing. `git diff --exit-code server.json` was the
 * first shape of that check and is a trap: git diff says nothing about an
 * untracked file, so the check passes on exactly the machine where server.json
 * is missing from the index.
 *
 * What this script does *not* do is validate server.json against its schema.
 * An earlier version reimplemented the 100-character `title`/`description` caps
 * as a literal, on the belief that mcp-publisher only reports them at publish
 * time. It does not: `mcp-publisher validate` checks the whole schema without
 * publishing, against an endpoint that needs no credentials, and the release
 * workflow runs it. Two of the schema's rules copied into a constant here would
 * have gone stale the first time the pinned schema URL moved, while still
 * missing the name pattern, the required fields and the rest. The caps that
 * matter for the values a human edits are asserted on the real files in
 * test/unit/sync-server-json.test.ts, which fails on the pull request that
 * writes them rather than on the release two merges later.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const checkOnly = process.argv.slice(2).includes('--check');

const root = new URL('..', import.meta.url);
const registryFile = new URL('server.json', root);

const pkg = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
const registry = JSON.parse(readFileSync(registryFile, 'utf8'));

/**
 * A mismatch here is the registry's "ownership validation failed. Expected
 * mcpName '<a>', got '<b>'" — discovered after npm has already published, at
 * the one step of the release that cannot be undone by re-running it. It costs
 * a comparison to find it while the version bump is still a pull request.
 */
if (pkg.mcpName !== registry.name) {
  console.error(
    `sync-server-json: package.json mcpName (${pkg.mcpName ?? 'unset'}) does not match ` +
    `server.json name (${registry.name}). The registry validates one against the other.`,
  );
  process.exit(1);
}

const npmPackage = registry.packages?.find((p) => p.registryType === 'npm');
// Refuse rather than guess: silently skipping would hand the release job a
// server.json pointing at whatever version was there before.
if (!npmPackage) {
  console.error('sync-server-json: server.json has no npm package entry to update');
  process.exit(1);
}

/**
 * The identifier is the other half of the same ownership check.
 *
 * `mcpName` above proves we own the package the listing claims; this is the
 * package it actually resolves — the registry fetches
 * `registry.npmjs.org/<identifier>/<version>` and reads `mcpName` out of *that*
 * manifest. A rename or typo here fails the same way and just as late, so it
 * gets the same guard rather than being the one copied field with nothing
 * behind it.
 */
if (npmPackage.identifier !== pkg.name) {
  console.error(
    `sync-server-json: server.json packages[].identifier (${npmPackage.identifier}) does not ` +
    `match the npm package name (${pkg.name}).`,
  );
  process.exit(1);
}

const stale =
  registry.version !== pkg.version || npmPackage.version !== pkg.version;

if (!stale) {
  console.log(`sync-server-json: server.json already at ${pkg.version}`);
  process.exit(0);
}

if (checkOnly) {
  console.error(
    `sync-server-json: server.json is stale — listing ${registry.version} / npm ` +
    `${npmPackage.version}, but package.json is at ${pkg.version}. ` +
    'Run `node scripts/sync-server-json.mjs` and commit the result.',
  );
  process.exit(1);
}

registry.version = pkg.version;
npmPackage.version = pkg.version;
writeFileSync(registryFile, `${JSON.stringify(registry, null, 2)}\n`);
console.log(`sync-server-json: server.json -> ${pkg.version}`);
