/**
 * Regenerates `test/fixtures/policy/realistic-commands.json`: the class and never-allowed
 * label of every command in the corpus, as the classifier in this checkout gives them.
 *
 * The fixture is a reference, so run this on the commit you want to compare against, not
 * on the change under test. It was last taken at 6763d3c, before the classifier read the
 * shell's grammar; `test/unit/policy/grammar-differential.test.ts` lists what that change
 * moved. To add commands, append `{ "command": "…" }` rows to the fixture and run this on
 * the reference commit.
 *
 *   SSH_MCP_DISABLE_MAIN=1 npx tsx scripts/snapshot-command-classes.mts
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { classifyCommand, findForbiddenMatch } from '../src/policy/classifier.js';

const path = new URL('../test/fixtures/policy/realistic-commands.json', import.meta.url);
const rows = JSON.parse(readFileSync(path, 'utf8')) as Array<{ command: string }>;
const snapshot = rows.map(({ command }) => ({
  command,
  class: classifyCommand(command).class,
  forbidden: findForbiddenMatch(command) !== null,
}));
writeFileSync(path, `${JSON.stringify(snapshot, null, 1)}\n`);
console.log(`${snapshot.length} commands`);
