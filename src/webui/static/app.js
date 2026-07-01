// ssh-mcp WebUI client. Vanilla JS, no build step.
//
// Auth: token is read from (1) location.hash (#token=...), (2) localStorage,
// or (3) the input box. All API calls send Authorization: Bearer <token>.

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);

  function getToken() {
    if (location.hash && location.hash.startsWith('#token=')) {
      const t = decodeURIComponent(location.hash.slice('#token='.length));
      try { localStorage.setItem('ssh-mcp-token', t); } catch (_) {}
      // Strip from URL bar so it isn't leaked via history.
      history.replaceState(null, '', location.pathname + location.search);
      return t;
    }
    try { return localStorage.getItem('ssh-mcp-token') || ''; } catch (_) { return ''; }
  }

  let token = getToken();
  if (token) $('#token').value = token;

  $('#save-token').addEventListener('click', () => {
    token = $('#token').value.trim();
    try { localStorage.setItem('ssh-mcp-token', token); } catch (_) {}
    bootstrap();
  });

  function authHeaders() {
    return token ? { Authorization: 'Bearer ' + token } : {};
  }

  function fmtTime(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleTimeString(); } catch (_) { return iso; }
  }

  function setConnStatus(state) {
    const el = $('#conn-status');
    el.classList.remove('ok', 'err');
    if (state === 'connected') { el.classList.add('ok'); el.textContent = 'connected'; }
    else if (state === 'error') { el.classList.add('err'); el.textContent = 'auth error'; }
    else { el.textContent = state; }
  }

  async function fetchProfiles() {
    try {
      const r = await fetch('/api/profiles', { headers: authHeaders() });
      if (r.status === 401) { setConnStatus('error'); return; }
      const data = await r.json();
      renderProfiles(data.profiles || []);
    } catch (e) { /* ignore polling glitches */ }
  }

  async function fetchApprovals() {
    try {
      const r = await fetch('/api/approvals', { headers: authHeaders() });
      if (!r.ok) return;
      const data = await r.json();
      renderApprovals(data.approvals || []);
    } catch (_) {}
  }

  async function fetchExecutions() {
    try {
      const r = await fetch('/api/executions?limit=50', { headers: authHeaders() });
      if (!r.ok) return;
      const data = await r.json();
      renderExecutions(data.executions || []);
    } catch (_) {}
  }

  function renderProfiles(rows) {
    const tbody = $('#profiles-body');
    tbody.innerHTML = '';
    if (!rows.length) { tbody.innerHTML = '<tr><td colspan="8" class="muted">no profiles registered</td></tr>'; return; }
    for (const p of rows) {
      const tr = document.createElement('tr');
      tr.dataset.id = p.id;
      tr.innerHTML = `<td>${escapeHtml(p.name)}${p.default ? ' <span class="muted">(default)</span>' : ''}</td>
                      <td>${escapeHtml(p.description || '')}</td>
                      <td>${escapeHtml(p.host)}:${escapeHtml(p.port)}</td>
                      <td>${escapeHtml(p.user)}</td>
                      <td>${escapeHtml(p.auth)}</td>
                      <td>${escapeHtml(p.transport)}</td>
                      <td class="mode-cell"></td>
                      <td>${p.connected ? '<span class="pill allow">connected</span>' : '<span class="pill">idle</span>'}</td>`;
      tr.querySelector('.mode-cell').appendChild(buildModeControl(p.id, p.approval_mode_effective));
      tbody.appendChild(tr);
    }
  }

  // Build the per-profile approval-mode control: a <select> of available modes
  // when the server exposes a mode controller, else a read-only pill (the
  // read-only WebUI / no-engine case).
  function buildModeControl(profileId, effective) {
    if (!availableModes.length) {
      const span = document.createElement('span');
      span.className = 'pill';
      span.textContent = effective || 'unknown';
      return span;
    }
    const sel = document.createElement('select');
    sel.className = 'mode-select';
    sel.dataset.profile = profileId;
    // Leading "inherit" option clears any live per-profile override (PUT
    // {mode:null}), letting the profile revert to its static/global mode.
    // Without it an operator who overrides a profile could never undo it from
    // the UI — the live override would stay pinned until restart.
    const inherit = document.createElement('option');
    inherit.value = '';
    inherit.textContent = 'inherit';
    sel.appendChild(inherit);
    for (const m of availableModes) {
      const opt = document.createElement('option');
      opt.value = m;
      opt.textContent = m;
      if (m === effective) opt.selected = true;
      sel.appendChild(opt);
    }
    // If the server reports an effective mode we can't switch to (missing, or
    // not in availableModes — e.g. modeController wired without getApprovalMode,
    // so /api/profiles returns 'unknown'), the <select> would otherwise default
    // to the first option ("inherit") and misrepresent the live state. Surface
    // the real value as a disabled, pre-selected placeholder instead of lying.
    if (effective && !availableModes.includes(effective)) {
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = effective + ' (current)';
      placeholder.disabled = true;
      placeholder.selected = true;
      sel.insertBefore(placeholder, sel.firstChild);
    }
    sel.addEventListener('change', () => switchMode(profileId, sel.value, sel));
    return sel;
  }

  // List of modes the server allows switching to (populated from
  // /api/approval-modes). Empty => mode switching disabled (read-only).
  let availableModes = [];
  // Live global default mode (the fallback applied to any profile without an
  // override). Populated from /api/approval-modes `global` and kept in sync
  // with scope:'global' mode-changed SSE events.
  let globalMode = null;

  async function fetchModes() {
    try {
      const r = await fetch('/api/approval-modes', { headers: authHeaders() });
      if (!r.ok) { availableModes = []; globalMode = null; renderGlobalControl(); return; }
      const data = await r.json();
      availableModes = Array.isArray(data.modes) ? data.modes : [];
      globalMode = typeof data.global === 'string' ? data.global : null;
    } catch (_) { availableModes = []; globalMode = null; }
    renderGlobalControl();
  }

  // Render the global-default approval-mode control in the header: a <select>
  // bound to PUT /api/approval-mode when the server exposes a mode controller,
  // else nothing (read-only / no-engine case).
  function renderGlobalControl() {
    const host = $('#global-mode-control');
    if (!host) return;
    host.innerHTML = '';
    if (!availableModes.length || globalMode == null) return;
    const label = document.createElement('span');
    label.className = 'muted';
    label.textContent = 'global:';
    host.appendChild(label);
    const sel = document.createElement('select');
    sel.className = 'mode-select';
    sel.id = 'global-mode-select';
    for (const m of availableModes) {
      const opt = document.createElement('option');
      opt.value = m;
      opt.textContent = m;
      if (m === globalMode) opt.selected = true;
      sel.appendChild(opt);
    }
    sel.addEventListener('change', () => switchGlobalMode(sel.value, sel));
    host.appendChild(sel);
  }

  async function switchGlobalMode(mode, sel) {
    if (sel) sel.disabled = true;
    try {
      const r = await fetch('/api/approval-mode', {
        method: 'PUT',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
        body: JSON.stringify({ mode }),
      });
      if (r.ok) {
        globalMode = mode;
      } else {
        // Revert the dropdown to the server's truth on failure.
        fetchModes();
      }
    } catch (_) {
      fetchModes();
    } finally {
      if (sel) sel.disabled = false;
    }
  }

  async function switchMode(profileId, mode, sel) {
    if (sel) sel.disabled = true;
    // The "inherit" option carries an empty value; serialize it as {mode:null}
    // so the server clears the override instead of pinning a literal '' mode.
    const payload = mode === '' ? null : mode;
    try {
      const r = await fetch('/api/profiles/' + encodeURIComponent(profileId) + '/approval-mode', {
        method: 'PUT',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
        body: JSON.stringify({ mode: payload }),
      });
      if (!r.ok) {
        // Revert the dropdown to the server's truth on failure.
        fetchProfiles();
      }
    } catch (_) {
      fetchProfiles();
    } finally {
      if (sel) sel.disabled = false;
    }
  }

  function renderApprovals(rows) {
    const list = $('#approvals-list');
    $('#approvals-count').textContent = String(rows.length);
    list.innerHTML = '';
    for (const a of rows) {
      const li = document.createElement('li');
      li.dataset.id = a.id;
      li.innerHTML = `
        <div class="row1">
          <span class="profile">${escapeHtml(a.profile)}</span>
          <span class="muted">${escapeHtml(a.tool)}</span>
          <span class="ts">${escapeHtml(fmtTime(a.enqueuedAt))}</span>
        </div>
        <code>${escapeHtml(a.command)}</code>
        ${a.description ? `<div class="muted">${escapeHtml(a.description)}</div>` : ''}
        <div class="actions">
          <input type="text" placeholder="optional note">
          <button class="allow" data-act="allow">allow</button>
          <button class="deny" data-act="deny">deny</button>
        </div>`;
      const noteInput = li.querySelector('input');
      li.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', () => decide(a.id, btn.dataset.act, noteInput.value, li));
      });
      list.appendChild(li);
    }
  }

  function renderExecutions(rows) {
    const list = $('#exec-list');
    $('#exec-count').textContent = String(rows.length);
    list.innerHTML = '';
    for (const r of rows) {
      const li = document.createElement('li');
      const dec = r.approval && r.approval.decision;
      li.innerHTML = `
        <div class="row1">
          <span class="profile">${escapeHtml(r.profile)}</span>
          <span class="muted">${escapeHtml(r.tool)}</span>
          ${dec ? `<span class="pill ${escapeAttr(dec)}">${escapeHtml(dec)}</span>` : ''}
          <span class="ts">${escapeHtml(fmtTime(r.ts))}</span>
        </div>
        <code>${escapeHtml(r.command)}</code>`;
      list.appendChild(li);
    }
  }

  function prependExecution(rec) {
    const list = $('#exec-list');
    const li = document.createElement('li');
    const dec = rec.approval && rec.approval.decision;
    li.innerHTML = `
      <div class="row1">
        <span class="profile">${escapeHtml(rec.profile)}</span>
        <span class="muted">${escapeHtml(rec.tool)}</span>
        ${dec ? `<span class="pill ${escapeAttr(dec)}">${escapeHtml(dec)}</span>` : ''}
        <span class="ts">${escapeHtml(fmtTime(rec.ts))}</span>
      </div>
      <code>${escapeHtml(rec.command)}</code>`;
    list.insertBefore(li, list.firstChild);
    const count = parseInt($('#exec-count').textContent || '0', 10) + 1;
    $('#exec-count').textContent = String(count);
  }

  async function decide(id, action, note, li) {
    try {
      const r = await fetch('/api/approvals/' + encodeURIComponent(id) + '/' + action, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
        body: JSON.stringify({ note: note || '' }),
      });
      if (r.ok) { li.remove(); fetchApprovals(); }
    } catch (_) {}
  }


  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, ch => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[ch]);
  }

  // Stricter escaping for values interpolated into an unquoted HTML attribute
  // context (e.g. a CSS class). Drops everything outside a conservative
  // allowlist so an attacker-influenced value can never break out of the
  // attribute, even though current callers only pass the allow/deny enum.
  function escapeAttr(s) {
    return String(s == null ? '' : s).replace(/[^a-zA-Z0-9_-]/g, '');
  }

  let sse;
  function openSse() {
    if (sse) try { sse.close(); } catch (_) {}
    const url = token ? '/events?token=' + encodeURIComponent(token) : '/events';
    sse = new EventSource(url);
    sse.onopen = () => setConnStatus('connected');
    sse.onerror = () => setConnStatus('error');
    sse.addEventListener('pending-approval', (ev) => {
      try {
        const m = JSON.parse(ev.data);
        if (m.action === 'enqueue' || m.action === 'resolve') fetchApprovals();
      } catch (_) {}
    });
    sse.addEventListener('execution', (ev) => {
      try { prependExecution(JSON.parse(ev.data)); } catch (_) {}
    });
    sse.addEventListener('mode-changed', (ev) => {
      // A live mode switch landed (possibly from another client). Reflect a
      // global-scope switch into the header control immediately, then re-fetch
      // the profile snapshot so every open dashboard converges on server truth.
      try {
        const m = JSON.parse(ev.data);
        if (m && m.scope === 'global' && typeof m.mode === 'string') {
          globalMode = m.mode;
          renderGlobalControl();
        }
      } catch (_) {}
      fetchProfiles();
    });
  }

  function bootstrap() {
    setConnStatus('connecting');
    // Fetch the available-modes list BEFORE profiles so the first render can
    // draw the mode <select> controls.
    fetchModes().then(() => fetchProfiles());
    fetchApprovals();
    fetchExecutions();
    openSse();
  }

  // Poll profiles every 10s (cheap snapshot).
  setInterval(fetchProfiles, 10000);
  bootstrap();
})();
