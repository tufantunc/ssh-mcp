import { createRequire } from 'module';

const require = createRequire(import.meta.url);

/**
 * Single source of truth for the version reported over MCP (`initialize`) and
 * on `GET /status`. Read from package.json at runtime so a changesets release
 * bump can't leave hardcoded literals behind, disagreeing with the installed
 * package. Resolves to the repo root from both `src/` and `build/`.
 */
export const SERVER_VERSION: string = (require('../package.json') as { version: string }).version;
