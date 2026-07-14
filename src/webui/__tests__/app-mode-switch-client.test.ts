/**
 * Client-side tests for the WebUI runtime mode-switch controls in
 * `static/app.js`. Complements the route-level tests in `mode-switch.test.ts`
 * (which exercise the HTTP surface) by asserting the *dashboard* actually
 * drives the API the backend exposes:
 *
 *   FINDING 1 — the per-profile <select> offers an "inherit" option that PUTs
 *               {mode:null} so an operator can clear a live override from the
 *               UI (not just pin a concrete mode forever).
 *   FINDING 2 — the dashboard renders a global-default control bound to
 *               PUT /api/approval-mode, and reflects an incoming scope:'global'
 *               mode-changed SSE event back into that control.
 *
 * `app.js` is plain browser JS (no build step) and the repo has no DOM test
 * environment, so we evaluate it inside a `vm` sandbox backed by a minimal
 * fake DOM, mirroring the harness in `app-escaping.test.ts`. The fake DOM here
 * additionally records change-event listeners (so a selection can be
 * simulated) and the SSE `mode-changed` listener (so an event can be injected).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const __dirname = dirname(fileURLToPath(import.meta.url));
const APP_JS = readFileSync(join(__dirname, '..', 'static', 'app.js'), 'utf8');

interface FakeEl {
  tagName: string;
  innerHTML: string;
  textContent: string;
  value: string;
  id: string;
  className: string;
  selected: boolean;
  disabled: boolean;
  dataset: Record<string, string>;
  classList: { add(): void; remove(): void };
  firstChild: FakeEl | null;
  children: FakeEl[];
  _listeners: Record<string, Array<() => void>>;
  appendChild(c: FakeEl): void;
  insertBefore(c: FakeEl, ref: FakeEl | null): void;
  querySelector(): FakeEl | null;
  querySelectorAll(): FakeEl[];
  addEventListener(type: string, fn: () => void): void;
  focus(): void;
  /** Test helper: synchronously fire a registered listener. */
  fire(type: string): void;
}

function makeEl(tag = 'div'): FakeEl {
  const children: FakeEl[] = [];
  let innerHTML = '';
  const el = {
    tagName: tag,
    get innerHTML() { return innerHTML; },
    set innerHTML(v: string) {
      innerHTML = v;
      // Mirror the real DOM: assigning innerHTML replaces all child nodes
      // (clearing to '' removes them). Our renderers rely on this to reset.
      children.length = 0;
      (this as FakeEl).firstChild = null;
    },
    textContent: '',
    value: '',
    id: '',
    className: '',
    selected: false,
    disabled: false,
    dataset: {} as Record<string, string>,
    classList: { add() {}, remove() {} },
    firstChild: null as FakeEl | null,
    children,
    _listeners: {} as Record<string, Array<() => void>>,
    appendChild(c: FakeEl) {
      children.push(c);
      (this as FakeEl).firstChild = children[0] ?? null;
    },
    insertBefore(c: FakeEl) {
      children.unshift(c);
      (this as FakeEl).firstChild = children[0] ?? null;
    },
    querySelector() { return makeEl(); },
    querySelectorAll() { return []; },
    addEventListener(type: string, fn: () => void) {
      ((this as FakeEl)._listeners[type] ??= []).push(fn);
    },
    focus() {},
    fire(type: string) {
      for (const fn of (this as FakeEl)._listeners[type] ?? []) fn();
    },
  } as unknown as FakeEl;
  return el;
}

interface FetchCall { url: string; method: string; body: unknown }

/**
 * Boot app.js in a sandbox. `modes` payload backs /api/approval-modes; every
 * PUT/POST is recorded into `calls`. Returns the byId map (header elements,
 * including #global-mode-control), the list of dynamically created elements
 * (profile-row selects live here), the captured fetch calls, and a hook to
 * inject an SSE `mode-changed` event.
 */
async function boot(opts: {
  modes?: { modes: string[]; global: string };
  profiles?: unknown[];
  sourceEditEnabled?: boolean;
  descriptionSaveStatus?: number;
}): Promise<{
  byId: Map<string, FakeEl>;
  created: FakeEl[];
  calls: FetchCall[];
  emitMode: (data: unknown) => void;
  emitConfigReloaded: (data: unknown) => void;
  intervalCallbacks: Array<() => unknown>;
  getProfileFetchCount: () => number;
  deferNextProfileResponse: () => () => void;
}> {
  const created: FakeEl[] = [];
  const byId = new Map<string, FakeEl>();
  const calls: FetchCall[] = [];
  const intervalCallbacks: Array<() => unknown> = [];
  let profileFetchCount = 0;
  let nextProfileGate: Promise<void> | null = null;
  let releaseNextProfile: (() => void) | null = null;
  let modeChangedListener: ((ev: { data: string }) => void) | null = null;
  let configReloadedListener: ((ev: { data: string }) => void) | null = null;

  const getById = (sel: string) => {
    let el = byId.get(sel);
    if (!el) { el = makeEl(); byId.set(sel, el); }
    return el;
  };

  const fakeDocument = {
    querySelector: (sel: string) => getById(sel),
    createElement: (tag: string) => {
      const el = makeEl(tag);
      created.push(el);
      return el;
    },
  };

  const jsonResp = (body: unknown) => ({ status: 200, ok: true, json: async () => body });

  const fetchStub = async (url: string, init?: RequestInit) => {
    const method = (init?.method ?? 'GET').toUpperCase();
    if (method === 'PUT' || method === 'POST') {
      let body: unknown = undefined;
      try { body = init?.body ? JSON.parse(String(init.body)) : undefined; } catch { /* ignore */ }
      calls.push({ url, method, body });
      if (url.includes('/description')) {
        const status = opts.descriptionSaveStatus ?? 200;
        return { status, ok: status >= 200 && status < 300, json: async () => ({}) };
      }
      return jsonResp({ ok: true });
    }
    if (url.startsWith('/api/approval-modes')) {
      if (!opts.modes) return { status: 503, ok: false, json: async () => ({}) };
      return jsonResp(opts.modes);
    }
    if (url.startsWith('/api/profiles')) {
      profileFetchCount += 1;
      if (nextProfileGate) {
        const gate = nextProfileGate;
        nextProfileGate = null;
        await gate;
      }
      return jsonResp({
        profiles: opts.profiles ?? [],
        source_edit_enabled: opts.sourceEditEnabled ?? false,
      });
    }
    if (url.startsWith('/api/executions')) return jsonResp({ executions: [] });
    if (url.startsWith('/api/approvals')) return jsonResp({ approvals: [] });
    return { status: 404, ok: false, json: async () => ({}) };
  };

  class FakeEventSource {
    onopen: (() => void) | null = null;
    onerror: (() => void) | null = null;
    addEventListener(type: string, fn: (ev: { data: string }) => void) {
      if (type === 'mode-changed') modeChangedListener = fn;
      if (type === 'config-reloaded') configReloadedListener = fn;
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
    setInterval: (fn: () => unknown) => { intervalCallbacks.push(fn); return intervalCallbacks.length; },
    clearInterval: () => {},
    setTimeout: (fn: () => void) => { fn(); return 0; },
    Date,
    JSON,
    encodeURIComponent,
    decodeURIComponent,
    parseInt,
    Array,
    Object,
    console,
  };

  vm.runInNewContext(APP_JS, sandbox, { timeout: 2000 });
  for (let i = 0; i < 10; i++) await Promise.resolve();
  await new Promise(r => setTimeout(r, 0));
  for (let i = 0; i < 10; i++) await Promise.resolve();

  return {
    byId,
    created,
    calls,
    emitMode: (data: unknown) => modeChangedListener?.({ data: JSON.stringify(data) }),
    emitConfigReloaded: (data: unknown) => configReloadedListener?.({ data: JSON.stringify(data) }),
    intervalCallbacks,
    getProfileFetchCount: () => profileFetchCount,
    deferNextProfileResponse: () => {
      nextProfileGate = new Promise<void>(resolve => { releaseNextProfile = resolve; });
      return () => {
        releaseNextProfile?.();
        releaseNextProfile = null;
      };
    },
  };
}

const PROFILE = {
  name: 'prod', description: 'p', host: 'h', port: 22, user: 'u',
  auth: 'kerberos', transport: 'openssh', approval_mode_effective: 'manual',
  id: 'prod', connected: true, default: true,
};

describe('WebUI app.js per-profile mode control (FINDING 1: inherit/clear)', () => {
  it('renders a leading empty-value "inherit" option on the profile select', async () => {
    const { created } = await boot({
      modes: { modes: ['yolo', 'manual'], global: 'yolo' },
      profiles: [PROFILE],
    });
    const selects = created.filter(e => e.tagName === 'select' && e.dataset.profile === 'prod');
    expect(selects.length).toBe(1);
    const sel = selects[0];
    const inherit = sel.children[0];
    expect(inherit.value).toBe('');
    expect(inherit.textContent).toBe('inherit');
    // concrete modes still present after the inherit option
    expect(sel.children.map(o => o.value)).toEqual(['', 'yolo', 'manual']);
  });

  it('selecting "inherit" PUTs {mode:null} to clear the override', async () => {
    const { created, calls } = await boot({
      modes: { modes: ['yolo', 'manual'], global: 'yolo' },
      profiles: [PROFILE],
    });
    const sel = created.find(e => e.tagName === 'select' && e.dataset.profile === 'prod')!;
    sel.value = ''; // operator picks "inherit"
    sel.fire('change');
    for (let i = 0; i < 10; i++) await Promise.resolve();

    const put = calls.find(c => c.method === 'PUT' && c.url.includes('/api/profiles/prod/approval-mode'));
    expect(put).toBeDefined();
    expect(put!.body).toEqual({ mode: null });
  });

  it('selecting a concrete mode still PUTs that mode string', async () => {
    const { created, calls } = await boot({
      modes: { modes: ['yolo', 'manual'], global: 'yolo' },
      profiles: [PROFILE],
    });
    const sel = created.find(e => e.tagName === 'select' && e.dataset.profile === 'prod')!;
    sel.value = 'manual';
    sel.fire('change');
    for (let i = 0; i < 10; i++) await Promise.resolve();

    const put = calls.find(c => c.method === 'PUT' && c.url.includes('/api/profiles/prod/approval-mode'));
    expect(put!.body).toEqual({ mode: 'manual' });
  });

  it('surfaces an unswitchable effective mode as a disabled placeholder, not "inherit"', async () => {
    // modeController is armed (availableModes non-empty) but the server reports
    // an effective mode outside that set ('unknown'). The select must not
    // silently fall back to the leading "inherit" option and misrepresent state.
    const { created } = await boot({
      modes: { modes: ['yolo', 'manual'], global: 'yolo' },
      profiles: [{ ...PROFILE, approval_mode_effective: 'unknown' }],
    });
    const sel = created.find(e => e.tagName === 'select' && e.dataset.profile === 'prod')!;
    const selected = sel.children.find(o => o.selected)!;
    expect(selected).toBeDefined();
    expect(selected.value).toBe('');
    expect(selected.disabled).toBe(true);
    expect(selected.textContent).toBe('unknown (current)');
    // the real "inherit" option is not the selected one
    const inheritOpts = sel.children.filter(o => o.textContent === 'inherit');
    expect(inheritOpts.every(o => !o.selected)).toBe(true);
  });
});

describe('WebUI app.js global mode control (FINDING 2: global switch + SSE)', () => {
  it('renders a global-default <select> seeded from data.global', async () => {
    const { byId } = await boot({ modes: { modes: ['yolo', 'manual'], global: 'manual' } });
    const host = byId.get('#global-mode-control')!;
    const sel = host.children.find(c => c.tagName === 'select');
    expect(sel).toBeDefined();
    expect(sel!.children.map(o => o.value)).toEqual(['yolo', 'manual']);
    const selected = sel!.children.find(o => o.selected);
    expect(selected!.value).toBe('manual');
  });

  it('switching the global control PUTs /api/approval-mode with the chosen mode', async () => {
    const { byId, calls } = await boot({ modes: { modes: ['yolo', 'manual'], global: 'yolo' } });
    const host = byId.get('#global-mode-control')!;
    const sel = host.children.find(c => c.tagName === 'select')!;
    sel.value = 'manual';
    sel.fire('change');
    for (let i = 0; i < 10; i++) await Promise.resolve();

    const put = calls.find(c => c.method === 'PUT' && c.url === '/api/approval-mode');
    expect(put).toBeDefined();
    expect(put!.body).toEqual({ mode: 'manual' });
  });

  it('reflects an incoming scope:global mode-changed SSE into the global control', async () => {
    const { byId, emitMode } = await boot({ modes: { modes: ['yolo', 'manual'], global: 'yolo' } });
    emitMode({ scope: 'global', mode: 'manual', effective: 'manual', at: new Date().toISOString() });
    for (let i = 0; i < 10; i++) await Promise.resolve();

    const host = byId.get('#global-mode-control')!;
    const sel = host.children.find(c => c.tagName === 'select')!;
    const selected = sel.children.find(o => o.selected);
    expect(selected!.value).toBe('manual');
  });

  it('omits the global control when mode switching is disabled (503)', async () => {
    const { byId } = await boot({}); // no modes payload -> /api/approval-modes 503
    const host = byId.get('#global-mode-control')!;
    expect(host.children.length).toBe(0);
  });
});

describe('WebUI app.js description editor polling', () => {
  it('does not refresh profiles while an unsaved description draft is open', async () => {
    const app = await boot({ profiles: [PROFILE], sourceEditEnabled: true });
    const edit = app.created.find(e => e.tagName === 'button' && e.className === 'desc-edit')!;
    expect(edit).toBeDefined();

    edit.fire('click');
    const draft = app.created.find(e => e.tagName === 'textarea' && e.className === 'desc-input')!;
    expect(draft).toBeDefined();
    draft.value = 'unsaved operator draft';

    const beforePoll = app.getProfileFetchCount();
    expect(app.intervalCallbacks).toHaveLength(1);
    await app.intervalCallbacks[0]();
    for (let i = 0; i < 10; i++) await Promise.resolve();

    expect(app.getProfileFetchCount()).toBe(beforePoll);
    expect(draft.value).toBe('unsaved operator draft');
  });

  it('forces a profile refresh when config-reloaded arrives during description editing', async () => {
    const app = await boot({
      modes: { modes: ['yolo', 'manual'], global: 'yolo' },
      profiles: [PROFILE],
      sourceEditEnabled: true,
    });
    const edit = app.created.find(e => e.tagName === 'button' && e.className === 'desc-edit')!;
    edit.fire('click');
    const draft = app.created.find(e => e.tagName === 'textarea' && e.className === 'desc-input')!;
    draft.value = 'stale after the TOML source set changes';

    const beforeReload = app.getProfileFetchCount();
    app.emitConfigReloaded({ sources: ['prod'], defaultName: 'prod', at: new Date().toISOString() });
    for (let i = 0; i < 20; i++) await Promise.resolve();

    expect(app.getProfileFetchCount()).toBe(beforeReload + 1);
  });

  it('clears the editor state when config-reloaded lands mid-edit so the dashboard stays editable', async () => {
    // Codex finding 3575258569: the forced refresh replaced the editor's DOM
    // but left descriptionEditorOpen === true, so background polling stayed
    // suppressed forever and every later edit click was ignored.
    const app = await boot({
      modes: { modes: ['yolo', 'manual'], global: 'yolo' },
      profiles: [PROFILE],
      sourceEditEnabled: true,
    });
    const edit = app.created.find(e => e.tagName === 'button' && e.className === 'desc-edit')!;
    edit.fire('click');
    const draft = app.created.find(e => e.tagName === 'textarea' && e.className === 'desc-input')!;
    draft.value = 'draft that the reload replaces';

    app.emitConfigReloaded({ sources: ['prod'], defaultName: 'prod', at: new Date().toISOString() });
    for (let i = 0; i < 20; i++) await Promise.resolve();

    // Background polling must run again (a stale open-editor flag suppresses it).
    const afterReload = app.getProfileFetchCount();
    await app.intervalCallbacks[0]();
    for (let i = 0; i < 10; i++) await Promise.resolve();
    expect(app.getProfileFetchCount()).toBe(afterReload + 1);

    // And a NEW editor can be opened on the re-rendered table: the fresh edit
    // button creates a fresh textarea (openDescriptionEditor is not ignored).
    const textareasBefore = app.created.filter(
      e => e.tagName === 'textarea' && e.className === 'desc-input').length;
    const editButtons = app.created.filter(
      e => e.tagName === 'button' && e.className === 'desc-edit');
    editButtons[editButtons.length - 1].fire('click');
    for (let i = 0; i < 10; i++) await Promise.resolve();
    const textareasAfter = app.created.filter(
      e => e.tagName === 'textarea' && e.className === 'desc-input').length;
    expect(textareasAfter).toBe(textareasBefore + 1);
  });

  it('keeps the editor and draft open when the description save is rejected', async () => {
    const app = await boot({
      profiles: [PROFILE],
      sourceEditEnabled: true,
      descriptionSaveStatus: 422,
    });
    const edit = app.created.find(e => e.tagName === 'button' && e.className === 'desc-edit')!;
    edit.fire('click');
    const draft = app.created.find(e => e.tagName === 'textarea' && e.className === 'desc-input')!;
    const save = app.created.find(e => e.tagName === 'button' && e.className === 'desc-save')!;
    draft.value = 'draft that must survive a rejected save';

    save.fire('click');
    for (let i = 0; i < 10; i++) await Promise.resolve();

    const beforePoll = app.getProfileFetchCount();
    await app.intervalCallbacks[0]();
    for (let i = 0; i < 10; i++) await Promise.resolve();
    expect(app.getProfileFetchCount()).toBe(beforePoll);
    expect(draft.value).toBe('draft that must survive a rejected save');
    expect(save.disabled).toBe(false);
  });

  it('does not render a profile response that finishes after the editor opens', async () => {
    const app = await boot({ profiles: [PROFILE], sourceEditEnabled: true });
    const releaseProfileResponse = app.deferNextProfileResponse();
    const inFlightPoll = app.intervalCallbacks[0]();
    await Promise.resolve();

    const edit = app.created.find(e => e.tagName === 'button' && e.className === 'desc-edit')!;
    edit.fire('click');
    const draft = app.created.find(e => e.tagName === 'textarea' && e.className === 'desc-input')!;
    draft.value = 'draft opened while fetch was in flight';
    const editorsBeforeResponse = app.created.filter(
      e => e.tagName === 'button' && e.className === 'desc-edit',
    ).length;

    releaseProfileResponse();
    await inFlightPoll;
    for (let i = 0; i < 10; i++) await Promise.resolve();

    expect(app.created.filter(
      e => e.tagName === 'button' && e.className === 'desc-edit',
    )).toHaveLength(editorsBeforeResponse);
    expect(draft.value).toBe('draft opened while fetch was in flight');
  });
});
