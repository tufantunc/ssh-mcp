// ssh-mcp WebUI client. Vanilla JS, no build step.
//
// Auth: token is read from (1) location.hash (#token=...), (2) localStorage,
// or (3) the input box. All API calls send Authorization: Bearer <token>.

(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const MAX_EXECUTION_ROWS = 50;

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
      const r = await fetch('/api/executions?limit=' + MAX_EXECUTION_ROWS, { headers: authHeaders() });
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
      tr.innerHTML = `<td>${escapeHtml(p.name)}${p.default ? ' <span class="muted">(default)</span>' : ''}</td>
                      <td>${escapeHtml(p.description || '')}</td>
                      <td>${escapeHtml(p.host)}:${escapeHtml(p.port)}</td>
                      <td>${escapeHtml(p.user)}</td>
                      <td>${escapeHtml(p.auth)}</td>
                      <td>${escapeHtml(p.transport)}</td>
                      <td><span class="pill">${escapeHtml(p.approval_mode_effective)}</span></td>
                      <td>${p.connected ? '<span class="pill allow">connected</span>' : '<span class="pill">idle</span>'}</td>`;
      tbody.appendChild(tr);
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
    // /api/executions returns the tail oldest-first, while live SSE events are
    // inserted at the top by prependExecution. Keep the newest rows and render
    // them newest-first so the initial feed matches the live ordering and
    // "Recent executions" stays consistent (Codex 3556038523).
    const visibleRows = rows.slice(-MAX_EXECUTION_ROWS).reverse();
    $('#exec-count').textContent = String(visibleRows.length);
    list.innerHTML = '';
    for (const r of visibleRows) {
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

  function trimExecutionList(list) {
    while (list.children.length > MAX_EXECUTION_ROWS) {
      list.removeChild(list.children[list.children.length - 1]);
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
    trimExecutionList(list);
    const count = Math.min(parseInt($('#exec-count').textContent || '0', 10) + 1, MAX_EXECUTION_ROWS);
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
  }

  function bootstrap() {
    setConnStatus('connecting');
    fetchProfiles();
    fetchApprovals();
    fetchExecutions();
    openSse();
  }

  // Poll profiles every 10s (cheap snapshot).
  setInterval(fetchProfiles, 10000);
  bootstrap();
})();
