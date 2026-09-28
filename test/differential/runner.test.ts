import { readFileSync, writeFileSync } from 'node:fs';
import { describe, it } from 'vitest';
import { classifyCommand } from '../../src/policy/classifier.js';

// Not part of any test run: the differential driver points
// SSH_MCP_DIFFERENTIAL_OUT at a file and this classifies the corpus into it,
// so the same corpus can be classified by two revisions of the tree and
// compared (scripts/differential-run.sh).
const suite = describe.skipIf(!process.env.SSH_MCP_DIFFERENTIAL_OUT);

suite('differential corpus', () => {
  it('classifies every probe', () => {
    const corpus: string[] = JSON.parse(
      readFileSync(new URL('./corpus.json', import.meta.url), 'utf8'),
    );
    const out: Record<string, string> = Object.create(null);
    for (const command of corpus) out[command] = classifyCommand(command).class;
    if (Object.keys(out).length !== corpus.length) {
      throw new Error(`differential runner lost entries: ${corpus.length} probes, ${Object.keys(out).length} recorded`);
    }
    writeFileSync(process.env.SSH_MCP_DIFFERENTIAL_OUT!, JSON.stringify(out, null, 1));
  });
});
