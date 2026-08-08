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
  },
});
