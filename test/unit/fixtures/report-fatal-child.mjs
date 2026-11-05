// Spawned by cli-fatal-reporting.test.ts: report an OperatorError of argv[2]
// characters through reportFatal's default sink, then exit at once, the way main() does.
import { reportFatal, OperatorError } from '../../../src/errors.ts';

process.exit(reportFatal(new OperatorError('x'.repeat(Number(process.argv[2])))));
