// Spawned by via-chacha.test.ts. Connects bastion -> forwardOut -> target with bare ssh2,
// offering `argv[2]` on the outer hop and `argv[3]` on the inner one ('frozen' or
// 'forwarded'), and prints one JSON line: whether `echo ok` came back, and whether ssh2
// had its native binding. A hop that hangs is reported as such rather than awaited.
import { createRequire } from 'module';
import { FROZEN_ALGORITHMS, FORWARDED_ALGORITHMS } from '../../../src/ssh/algorithms.ts';

const require = createRequire(import.meta.url);
const { Client } = require('ssh2');
const { bindingAvailable } = require('ssh2/lib/protocol/crypto.js');
const sets = { frozen: FROZEN_ALGORITHMS, forwarded: FORWARDED_ALGORITHMS };
const [outerSet, innerSet, host, port, target, targetPort, hangMs] = process.argv.slice(2);

const report = (result) => {
  process.stdout.write(JSON.stringify({ result, bindingAvailable }) + '\n');
  process.exit(0);
};
setTimeout(() => report('hang'), Number(hangMs)).unref();

const outer = new Client();
outer.on('error', (e) => report(`outer error: ${e.message}`));
outer.on('ready', () => {
  outer.forwardOut('127.0.0.1', 0, target, Number(targetPort), (err, stream) => {
    if (err) return report(`forwardOut error: ${err.message}`);
    const inner = new Client();
    inner.on('error', (e) => report(`inner error: ${e.message}`));
    inner.on('ready', () => {
      inner.exec('echo ok', (e, s) => {
        if (e) return report(`exec error: ${e.message}`);
        let out = '';
        s.on('data', (d) => { out += d; });
        s.on('close', () => report(out.trim() === 'ok' ? 'ok' : `unexpected output: ${out}`));
      });
    });
    inner.connect({ sock: stream, username: 'operator', password: 'oppass', algorithms: sets[innerSet] });
  });
});
outer.connect({ host, port: Number(port), username: 'bastion', password: 'bastionpass', algorithms: sets[outerSet] });
