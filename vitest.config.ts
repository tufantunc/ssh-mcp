import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: ['**/node_modules/**', '**/dist/**', 'test/legacy/**'],
    // Integration test files each open real SSH connections to the Docker test
    // servers. Running the files in parallel multiplies concurrent handshakes,
    // and connections start getting dropped before the handshake completes —
    // which surfaces as failures and, worse, as *skips*, since a test file whose
    // probe is dropped skips itself and a degraded run still looks green.
    //
    // The suite is fast either way (a few seconds), so serialising files buys
    // determinism cheaply.
    fileParallelism: false,

    coverage: {
      provider: 'v8',
      // text for the terminal, lcov for everything that consumes a report:
      // SonarQube imports coverage rather than measuring it, and Codecov reads
      // the same file. Without lcov both show 0%, which reads as "untested"
      // rather than "no report was produced".
      reporter: ['text', 'lcov'],
      reportsDirectory: 'coverage',
      include: ['src/**/*.ts'],
      // Only modules that carry no logic: types.ts is interfaces, which erase
      // to nothing, and version.ts is a single constant. index.ts stays in
      // despite scoring low — the e2e suite drives it as a spawned process, so
      // in-process instrumentation cannot follow it, and excluding it would
      // hide genuinely untested wiring behind a nicer number.
      exclude: ['src/types.ts', 'src/version.ts'],
    },
  },
});
