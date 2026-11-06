// Preloaded with --require: makes ssh2's optional native crypto binding unloadable, so
// ssh2 takes its JavaScript cipher path — the one the published Docker image runs, since
// `npm ci --ignore-scripts` never builds the binding.
const Module = require('module');
const load = Module._load;
Module._load = function (request, ...rest) {
  if (request.endsWith('sshcrypto.node')) throw new Error('native binding hidden for this test');
  return load.call(this, request, ...rest);
};
