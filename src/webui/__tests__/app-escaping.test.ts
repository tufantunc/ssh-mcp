/**
 * Client-side XSS regression guard for the read-only WebUI (`static/app.js`).
 *
 * The execution / approval / profile renderers interpolate server-provided
 * fields into `innerHTML`. Several of those fields are attacker-influenceable:
 * an MCP client supplies an arbitrary `connectionName`, which flows through
 * `resolvedProfileName()` into the audit record's `profile` and is then
 * broadcast over SSE into the DOM. If rendered raw, injected markup runs in
 * the same origin that holds the bearer token in `localStorage`.
 *
 * `app.js` is plain browser JS (no build step, served statically) and the repo
 * has no DOM test environment, so we evaluate it inside a `vm` sandbox backed
 * by a minimal fake DOM and a URL-keyed `fetch` stub, then assert the rendered
 * HTML escaped the payload (`&lt;img` present, executable `<img ... onerror`
 * absent).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const __dirname = dirname(fileURLToPath(import.meta.url));
const APP_JS = readFileSync(join(__dirname, '..', 'static', 'app.js'), 'utf8');

const XSS = '<img src=x onerror=alert(document.cookie)>';

interface FakeEl {
  innerHTML: string;
  textContent: string;
  value: string;
  dataset: Record<string, string>;
  classList: { add(): void; remove(): void };
  firstChild: FakeEl | null;
  children: FakeEl[];
  appendChild(c: FakeEl): void;
  insertBefore(c: FakeEl, _ref: FakeEl | null): void;
  removeChild(c: FakeEl): void;
  addEventListener(): void;
}

interface FakeEventSourceHandle {
  emit(event: string, data: unknown): void;
}

function makeEl(): FakeEl {
  const el: FakeEl = {
    innerHTML: '',
    textContent: '',
    value: '',
    dataset: {},
    classList: { add() {}, remove() {} },
    firstChild: null,
    children: [],
    appendChild(c: FakeEl) {
      this.children.push(c);
      this.firstChild = this.children[0] ?? null;
    },
    insertBefore(c: FakeEl) {
      this.children.unshift(c);
      this.firstChild = this.children[0] ?? null;
    },
    removeChild(c: FakeEl) {
      this.children = this.children.filter(child => child !== c);
      this.firstChild = this.children[0] ?? null;
    },
    addEventListener() {},
  };
  return el;
}

/** Run app.js in a sandbox with malicious /api/profiles + /api/executions data. */
async function renderWith(payload: {
  profiles?: unknown[];
  executions?: unknown[];
  approvals?: unknown[];
}): Promise<{ created: FakeEl[]; byId: Map<string, FakeEl>; eventSources: FakeEventSourceHandle[] }> {
  const created: FakeEl[] = [];
  const byId = new Map<string, FakeEl>();
  const eventSources: FakeEventSourceHandle[] = [];
  const getById = (sel: string) => {
    let el = byId.get(sel);
    if (!el) {
      el = makeEl();
      byId.set(sel, el);
    }
    return el;
  };

  const fakeDocument = {
    querySelector: (sel: string) => getById(sel),
    createElement: () => {
      const el = makeEl();
      created.push(el);
      return el;
    },
  };

  const jsonResp = (body: unknown) => ({
    status: 200,
    ok: true,
    json: async () => body,
  });

  const fetchStub = async (url: string) => {
    if (url.startsWith('/api/profiles')) return jsonResp({ profiles: payload.profiles ?? [] });
    if (url.startsWith('/api/executions')) return jsonResp({ executions: payload.executions ?? [] });
    if (url.startsWith('/api/approvals')) return jsonResp({ approvals: payload.approvals ?? [] });
    return { status: 404, ok: false, json: async () => ({}) };
  };

  class FakeEventSource {
    onopen: (() => void) | null = null;
    onerror: (() => void) | null = null;
    private readonly listeners = new Map<string, ((ev: { data: string }) => void)[]>();
    constructor() { eventSources.push(this); }
    addEventListener(event: string, fn: (ev: { data: string }) => void) {
      const list = this.listeners.get(event) ?? [];
      list.push(fn);
      this.listeners.set(event, list);
    }
    emit(event: string, data: unknown) {
      for (const fn of this.listeners.get(event) ?? []) {
        fn({ data: JSON.stringify(data) });
      }
    }
    close() {}
  }

  const store = new Map<string, string>();
  const sandbox: Record<string, unknown> = {
    document: fakeDocument,
    localStorage: {
      getItem: (k: string) => (store.has(k) ? store.get(k) : null),
      setItem: (k: string, v: string) => void store.set(k, v),
    },
    location: { hash: '', pathname: '/', search: '' },
    history: { replaceState() {} },
    fetch: fetchStub,
    EventSource: FakeEventSource,
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: (fn: () => void) => { fn(); return 0; },
    Date,
    JSON,
    encodeURIComponent,
    decodeURIComponent,
    parseInt,
    console,
  };

  vm.runInNewContext(APP_JS, sandbox, { timeout: 2000 });
  // Flush the bootstrap fetch microtask chains.
  for (let i = 0; i < 10; i++) await Promise.resolve();
  await new Promise(r => setTimeout(r, 0));
  for (let i = 0; i < 10; i++) await Promise.resolve();

  return { created, byId, eventSources };
}

describe('WebUI app.js XSS escaping', () => {
  it('escapes a malicious profile name in the profiles table', async () => {
    const { created } = await renderWith({
      profiles: [
        {
          name: XSS,
          host: 'h',
          port: 22,
          user: 'u',
          auth: 'key',
          transport: 'ssh2',
          approval_mode_effective: 'yolo',
          connected: false,
          default: false,
        },
      ],
    });
    const html = created.map(e => e.innerHTML).join('\n');
    expect(html).toContain('&lt;img');
    expect(html).not.toContain('<img src=x onerror');
  });

  it('escapes attacker-controlled profile/tool in the executions feed', async () => {
    const { created } = await renderWith({
      executions: [
        {
          ts: new Date().toISOString(),
          profile: XSS,
          tool: '<script>alert(1)</script>',
          command: 'uptime',
          approval: { decision: 'allow' },
        },
      ],
    });
    const html = created.map(e => e.innerHTML).join('\n');
    expect(html).toContain('&lt;img');
    expect(html).toContain('&lt;script&gt;');
    expect(html).not.toContain('<img src=x onerror');
    expect(html).not.toContain('<script>alert(1)</script>');
  });

  it('does not let a malicious approval.decision break out of the class attribute', async () => {
    const { created } = await renderWith({
      executions: [
        {
          ts: new Date().toISOString(),
          profile: 'p',
          tool: 'exec',
          command: 'uptime',
          // hostile decision attempting to inject an attribute/handler
          approval: { decision: 'allow"><img src=x onerror=alert(1)>' },
        },
      ],
    });
    const html = created.map(e => e.innerHTML).join('\n');
    expect(html).not.toContain('<img src=x onerror');
    // escapeAttr keeps only the allowlisted [A-Za-z0-9_-] characters.
    expect(html).toContain('class="pill allowimgsrcxonerroralert1"');
  });

  it('renders the initial execution rows newest-first to match live SSE prepends (Codex 3556038523)', async () => {
    // /api/executions returns the tail oldest-first; the initial render must
    // reverse it so the feed starts newest-at-top, consistent with
    // prependExecution's live inserts.
    const mk = (i: number) => ({
      ts: new Date(2026, 0, 1, 0, 0, i).toISOString(),
      profile: 'p',
      tool: 'exec',
      command: `uptime ${i}`,
      approval: { decision: 'allow' },
    });
    const { byId, eventSources } = await renderWith({
      executions: [mk(0), mk(1), mk(2)],
    });
    const list = byId.get('#exec-list')!;
    expect(list.children).toHaveLength(3);
    expect(list.children[0].innerHTML).toContain('uptime 2');
    expect(list.children[2].innerHTML).toContain('uptime 0');
    expect(byId.get('#exec-count')!.textContent).toBe('3');

    // A live SSE event lands on top and the ordering stays newest-first.
    eventSources[0].emit('execution', mk(3));
    expect(list.children[0].innerHTML).toContain('uptime 3');
    expect(list.children[1].innerHTML).toContain('uptime 2');
  });

  it('caps the live SSE execution list', async () => {
    const { byId, eventSources } = await renderWith({ executions: [] });
    const source = eventSources[0];
    expect(source).toBeTruthy();

    for (let i = 0; i < 55; i++) {
      source.emit('execution', {
        ts: new Date().toISOString(),
        profile: 'p',
        tool: 'exec',
        command: `uptime ${i}`,
        approval: { decision: 'allow' },
      });
    }

    const list = byId.get('#exec-list')!;
    expect(list.children).toHaveLength(50);
    expect(byId.get('#exec-count')!.textContent).toBe('50');
    expect(list.children[0].innerHTML).toContain('uptime 54');
    expect(list.children[list.children.length - 1].innerHTML).toContain('uptime 5');
  });
});
