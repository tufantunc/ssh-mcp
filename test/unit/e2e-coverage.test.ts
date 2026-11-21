import { describe, it, expect } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { join } from 'path';

const run = promisify(execFile);

const SCRIPT = fileURLToPath(new URL('../../scripts/e2e-coverage.mjs', import.meta.url));

/**
 * scripts/e2e-coverage.mjs, which CI runs after the suite over the V8 coverage that
 * every process of the run wrote on exit.
 *
 * A process writes its dump in two steps, creating the file and then filling it. One
 * that is killed in between leaves the file empty, and one killed while filling it
 * leaves half a document: measured, a SIGKILL 9.2 to 9.5 ms after a SIGTERM left an
 * empty file in 5 of 400 tries. The suite kills processes on purpose, so such a file
 * is a process this report cannot see, like one that wrote nothing, and not a reason
 * for the run to fail: it failed main's CI twice with every test green.
 */
async function convert(dumps: Record<string, string>) {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-mcp-e2e-cov-'));
  try {
    for (const [name, text] of Object.entries(dumps)) await writeFile(join(dir, name), text);
    const out = join(dir, 'out', 'lcov.info');
    try {
      const ok = await run('node', [SCRIPT, dir, out]);
      return { code: 0, stdout: ok.stdout, stderr: ok.stderr, lcov: await readFile(out, 'utf8') };
    } catch (err: any) {
      return { code: err.code as number, stdout: (err.stdout ?? '') as string, stderr: (err.stderr ?? '') as string, lcov: null };
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('scripts/e2e-coverage.mjs', () => {
  const whole = JSON.stringify({ result: [] });

  it('converts a directory of whole dumps', async () => {
    const result = await convert({ 'coverage-1.json': whole, 'coverage-2.json': whole });
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('from 2 processes');
    expect(result.stdout).not.toContain('skipped');
  });

  it('passes over a dump its process was killed before filling, and says so', async () => {
    const result = await convert({ 'coverage-1.json': whole, 'coverage-2.json': '' });
    expect(result.code).toBe(0);
    expect(result.lcov).not.toBeNull();
    expect(result.stdout).toContain('from 1 processes');
    expect(result.stdout).toContain('skipped 1');
    expect(result.stdout).toContain('coverage-2.json');
  });

  it('passes over a dump its process was killed while filling', async () => {
    const result = await convert({ 'coverage-1.json': whole, 'coverage-2.json': '{"result":[{"scriptId":"1","url":"file:///x' });
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('skipped 1');
  });

  it('still fails on a dump that is whole and is not coverage', async () => {
    const result = await convert({ 'coverage-1.json': JSON.stringify({ unrelated: true }) });
    expect(result.code).not.toBe(0);
  });
});
