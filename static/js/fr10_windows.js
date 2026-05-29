/**
 * static/js/fr10_windows.js
 * ==========================
 * FR10-03  Windows Update status + patch levels panel
 * FR10-04  Windows Action Center notification controls
 * FR10-05  Start Menu shortcut management
 *
 * PLACE THIS FILE AT:
 *   <your_project>/static/js/fr10_windows.js
 *
 * HOW TO USE:
 * Add ONE line in index.html after the existing <script src="...dashboard.js"> tag:
 *   <script src="/static/js/fr10_windows.js"></script>
 *
 * Add ONE div inside the dashboard page section (id="page-dashboard"),
 * just before the closing </div> that wraps the Charts section:
 *   <!-- FR10 Windows Integration Panel -->
 *   <div id="fr10-windows-panel"></div>
 *
 * The script self-renders all three panels into that container.
 */

(function () {
  'use strict';

  // ── API endpoints ───────────────────────────────────────────────────────────
  var API = {
    updateStatus:   '/api/windows/update-status',
    notify:         '/api/windows/notify',
    shortcutStatus: '/api/windows/shortcut-status',
    createShortcut: '/api/windows/create-shortcut',
    removeShortcut: '/api/windows/remove-shortcut',
  };

  // ── Utility ─────────────────────────────────────────────────────────────────
  async function apiFetch(url, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    var r = await fetch(url, opts);
    return r.json();
  }

  function _esc(str) {
    return String(str || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function _setEl(id, html) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  function _showResult(elId, msg, type) {
    var el = document.getElementById(elId);
    if (!el) return;
    el.style.display = '';
    el.textContent   = msg;
    el.className     = 'fr10-result-msg fr10-result-' + type;
  }

  function patchBadgeColor(level) {
    if (!level) return '#6a90b8';
    if (level === 'Fully Patched')   return '#10b981';
    if (level === 'Reboot Required') return '#f59e0b';
    if (level.includes('Pending'))   return '#ef4444';
    return '#6a90b8';
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Styles
  // ══════════════════════════════════════════════════════════════════════════
  function injectStyles() {
    if (document.getElementById('fr10-styles')) return;
    var s = document.createElement('style');
    s.id = 'fr10-styles';
    s.textContent = [
      /* wrapper */
      '#fr10-windows-panel{display:flex;flex-direction:column;gap:14px;padding:0 0 24px 0}',

      /* section card */
      '.fr10-section{background:var(--panel,#0f1a2e);border:1px solid var(--border,#1c2d4a);border-radius:8px;overflow:hidden}',

      /* header */
      '.fr10-section-header{display:flex;align-items:center;gap:8px;padding:10px 16px;background:var(--panel2,#132036);border-bottom:1px solid var(--border,#1c2d4a);font-size:12px;font-weight:700;color:var(--text-bright,#e4f0ff);letter-spacing:.4px;text-transform:uppercase}',
      '.fr10-section-icon{font-size:15px}',
      '.fr10-section-title{flex:1}',

      /* badges */
      '.fr10-badge{font-size:10px;font-weight:700;padding:3px 9px;border-radius:20px;background:#253e65;color:#fff;letter-spacing:.3px;transition:background .3s;white-space:nowrap}',

      /* refresh button */
      '.fr10-btn-sm{font-size:10px;padding:3px 9px;background:transparent;border:1px solid var(--border2,#253e65);color:var(--text-mid,#6a90b8);border-radius:4px;cursor:pointer;transition:color .2s,border-color .2s}',
      '.fr10-btn-sm:hover{color:var(--text-bright,#e4f0ff);border-color:var(--border3,#2e5080)}',

      /* section bodies */
      '.fr10-wu-body,.fr10-notify-body,.fr10-shortcut-body{padding:14px 16px}',

      /* WU meta row */
      '.fr10-wu-meta{display:flex;flex-wrap:wrap;gap:6px 20px;margin-bottom:12px}',
      '.fr10-wu-kv{display:flex;flex-direction:column;font-size:11px}',
      '.fr10-wu-kv span{color:var(--text-dim,#3d5570);text-transform:uppercase;font-size:10px;letter-spacing:.5px}',
      '.fr10-wu-kv b{color:var(--text-bright,#e4f0ff);font-family:var(--mono,monospace);font-size:12px}',
      '.fr10-reboot-warn{background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);color:#fbbf24;font-size:11px;padding:6px 10px;border-radius:5px;margin-bottom:10px}',
      '.fr10-ok-msg{font-size:12px;color:#10b981;padding:6px 0}',

      /* tables */
      '.fr10-table-header{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim,#3d5570);margin-bottom:6px}',
      '.fr10-table-scroll{overflow-x:auto;max-height:200px;overflow-y:auto}',
      '.fr10-table{width:100%;border-collapse:collapse;font-size:11px}',
      '.fr10-table th{text-align:left;padding:5px 8px;background:var(--panel2,#132036);color:var(--text-dim,#3d5570);font-size:10px;text-transform:uppercase;letter-spacing:.4px;position:sticky;top:0;z-index:1}',
      '.fr10-table td{padding:5px 8px;border-bottom:1px solid var(--border,#1c2d4a);vertical-align:top}',
      '.fr10-table tr:hover td{background:var(--panel2,#132036)}',
      '.fr10-td-title{max-width:320px;word-break:break-word;color:var(--text,#b8d0ee)}',
      '.fr10-kb{font-family:var(--mono,monospace);font-size:10px;color:#38bdf8;background:rgba(56,189,248,.08);padding:1px 5px;border-radius:3px}',
      '.fr10-date{font-family:var(--mono,monospace);font-size:10px;color:var(--text-mid,#6a90b8)}',
      '.fr10-mandatory{font-size:10px;color:#f59e0b;background:rgba(245,158,11,.1);padding:1px 5px;border-radius:3px}',

      /* severity pills */
      '.fr10-sev{font-size:10px;padding:1px 6px;border-radius:3px;font-weight:700}',
      '.fr10-sev-critical{background:rgba(239,68,68,.12);color:#f87171}',
      '.fr10-sev-important{background:rgba(245,158,11,.12);color:#fbbf24}',
      '.fr10-sev-moderate{background:rgba(56,189,248,.12);color:#38bdf8}',
      '.fr10-sev-low{background:rgba(100,116,139,.12);color:#94a3b8}',
      '.fr10-sev-unknown{color:var(--text-dim,#3d5570)}',

      /* form fields */
      '.fr10-field-row{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}',
      '.fr10-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim,#3d5570);width:60px;flex-shrink:0}',
      '.fr10-input{flex:1;min-width:140px;background:var(--bg3,#0d1528);border:1px solid var(--border2,#253e65);color:var(--text,#b8d0ee);border-radius:5px;padding:5px 9px;font-size:12px;font-family:inherit}',
      '.fr10-input:focus{outline:none;border-color:var(--border3,#2e5080)}',
      '.fr10-select{max-width:140px;flex:0 0 auto}',

      /* buttons */
      '.fr10-btn-row{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}',
      '.fr10-btn{padding:7px 16px;background:var(--panel2,#132036);border:1px solid var(--border2,#253e65);color:var(--text-bright,#e4f0ff);border-radius:5px;cursor:pointer;font-size:12px;font-weight:600;transition:background .2s,border-color .2s}',
      '.fr10-btn:hover{background:var(--panel3,#172640);border-color:var(--border3,#2e5080)}',
      '.fr10-btn-secondary{color:var(--text-mid,#6a90b8)}',
      '.fr10-btn-danger{border-color:rgba(239,68,68,.3);color:#f87171}',
      '.fr10-btn-danger:hover{background:rgba(239,68,68,.08)}',

      /* result messages */
      '.fr10-result-msg{margin-top:8px;font-size:11px;padding:6px 10px;border-radius:5px}',
      '.fr10-result-ok{background:rgba(16,185,129,.10);color:#10b981;border:1px solid rgba(16,185,129,.2)}',
      '.fr10-result-error{background:rgba(239,68,68,.10);color:#f87171;border:1px solid rgba(239,68,68,.2)}',
      '.fr10-result-info{background:rgba(56,189,248,.08);color:#38bdf8;border:1px solid rgba(56,189,248,.15)}',

      /* notes */
      '.fr10-note{margin-top:10px;font-size:10px;color:var(--text-dim,#3d5570);line-height:1.7}',
      '.fr10-note code,.fr10-shortcut-info code{background:var(--bg3,#0d1528);padding:1px 5px;border-radius:3px;color:#38bdf8;font-size:10px}',

      /* shortcut info */
      '.fr10-shortcut-info{font-size:12px;color:var(--text-mid,#6a90b8);margin-bottom:10px;line-height:1.6}',

      /* loading / error inline */
      '.fr10-loading{color:var(--text-dim,#3d5570);font-size:12px;padding:6px 0}',
      '.fr10-error{color:#f87171;font-size:12px;padding:6px 0}',
    ].join('');
    document.head.appendChild(s);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR10-03 — Patch Level Panel
  // ══════════════════════════════════════════════════════════════════════════

  function buildPatchPanel(container) {
    var div = document.createElement('div');
    div.className = 'fr10-section';
    div.innerHTML =
      '<div class="fr10-section-header">' +
        '<span class="fr10-section-icon">🔄</span>' +
        '<span class="fr10-section-title">Windows Update &amp; Patch Level</span>' +
        '<span class="fr10-badge" id="fr10-patch-badge">Loading…</span>' +
        '<button class="fr10-btn-sm" id="fr10-refresh-wu">↻ Refresh</button>' +
      '</div>' +
      '<div id="fr10-wu-body" class="fr10-wu-body">' +
        '<div class="fr10-loading">Querying Windows Update Agent…</div>' +
      '</div>';
    container.appendChild(div);
    document.getElementById('fr10-refresh-wu').addEventListener('click', loadUpdateStatus);
    loadUpdateStatus();
  }

  async function loadUpdateStatus() {
    var body  = document.getElementById('fr10-wu-body');
    var badge = document.getElementById('fr10-patch-badge');
    if (!body) return;
    body.innerHTML = '<div class="fr10-loading">Querying Windows Update Agent…</div>';
    try {
      var d = await apiFetch(API.updateStatus);
      renderUpdateStatus(d, body, badge);
    } catch (e) {
      body.innerHTML = '<div class="fr10-error">Failed to fetch: ' + _esc(e.message) + '</div>';
    }
  }

  function renderUpdateStatus(d, body, badge) {
    badge.textContent        = d.patch_level || 'Unknown';
    badge.style.background   = patchBadgeColor(d.patch_level);
    badge.style.color        = '#fff';

    if (!d.ok) {
      body.innerHTML = '<div class="fr10-error">⚠ ' + _esc(d.error || 'Unavailable') + '</div>';
      return;
    }

    var rebootHtml = d.reboot_required
      ? '<div class="fr10-reboot-warn">⚠ Reboot required to complete updates</div>' : '';

    var pendingRows = (d.pending || []).map(function(u) {
      return '<tr>' +
        '<td class="fr10-td-title">' + _esc(u.title) + '</td>' +
        '<td><span class="fr10-kb">' + _esc(u.kb || '—') + '</span></td>' +
        '<td><span class="fr10-sev fr10-sev-' + _esc((u.severity||'unknown').toLowerCase()) + '">' + _esc(u.severity || '—') + '</span></td>' +
        '<td>' + (u.is_mandatory ? '<span class="fr10-mandatory">Mandatory</span>' : '') + '</td>' +
        '</tr>';
    }).join('');

    var installedRows = (d.installed || []).slice(0, 10).map(function(u) {
      return '<tr>' +
        '<td class="fr10-td-title">' + _esc(u.title) + '</td>' +
        '<td><span class="fr10-kb">' + _esc(u.kb || '—') + '</span></td>' +
        '<td class="fr10-date">' + _esc(u.date || '—') + '</td>' +
        '</tr>';
    }).join('');

    body.innerHTML =
      '<div class="fr10-wu-meta">' +
        '<div class="fr10-wu-kv"><span>OS Version</span><b>' + _esc(d.os_version || '—') + '</b></div>' +
        '<div class="fr10-wu-kv"><span>Last Installed</span><b>' + _esc(d.last_install_date || 'Never') + '</b></div>' +
        '<div class="fr10-wu-kv"><span>Pending Updates</span><b style="color:' + (d.pending_count > 0 ? '#ef4444' : '#10b981') + '">' + (d.pending_count || 0) + '</b></div>' +
        '<div class="fr10-wu-kv"><span>Installed (recent)</span><b>' + (d.installed_count || 0) + '</b></div>' +
        '<div class="fr10-wu-kv"><span>Reboot Required</span><b style="color:' + (d.reboot_required ? '#f59e0b' : '#10b981') + '">' + (d.reboot_required ? 'Yes' : 'No') + '</b></div>' +
      '</div>' +
      rebootHtml +
      (d.pending_count > 0
        ? '<div class="fr10-table-header">⏳ Pending Updates (' + d.pending_count + ')</div>' +
          '<div class="fr10-table-scroll"><table class="fr10-table">' +
          '<thead><tr><th>Title</th><th>KB</th><th>Severity</th><th></th></tr></thead>' +
          '<tbody>' + pendingRows + '</tbody></table></div>'
        : '<div class="fr10-ok-msg">✅ No pending updates</div>') +
      (d.installed_count > 0
        ? '<div class="fr10-table-header" style="margin-top:12px">✅ Recently Installed Updates</div>' +
          '<div class="fr10-table-scroll"><table class="fr10-table">' +
          '<thead><tr><th>Title</th><th>KB</th><th>Date Installed</th></tr></thead>' +
          '<tbody>' + installedRows + '</tbody></table></div>'
        : '');
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR10-04 — Action Center Notification Controls
  // ══════════════════════════════════════════════════════════════════════════

  function buildNotifyPanel(container) {
    var div = document.createElement('div');
    div.className = 'fr10-section';
    div.innerHTML =
      '<div class="fr10-section-header">' +
        '<span class="fr10-section-icon">🔔</span>' +
        '<span class="fr10-section-title">Windows Action Center Notifications</span>' +
        '<span class="fr10-badge" id="fr10-notify-status">Idle</span>' +
      '</div>' +
      '<div class="fr10-notify-body">' +
        '<div class="fr10-field-row">' +
          '<label class="fr10-label">Title</label>' +
          '<input id="fr10-ntitle" class="fr10-input" placeholder="Notification title" value="Secure Eye Trust+" />' +
        '</div>' +
        '<div class="fr10-field-row">' +
          '<label class="fr10-label">Message</label>' +
          '<input id="fr10-nmessage" class="fr10-input" placeholder="Notification body text" value="Security monitoring is active." />' +
        '</div>' +
        '<div class="fr10-field-row">' +
          '<label class="fr10-label">Severity</label>' +
          '<select id="fr10-nseverity" class="fr10-input fr10-select">' +
            '<option value="info">ℹ Info</option>' +
            '<option value="warning">⚠ Warning</option>' +
            '<option value="critical">🚨 Critical</option>' +
          '</select>' +
          '<label class="fr10-label" style="margin-left:8px;width:auto">Duration</label>' +
          '<select id="fr10-nduration" class="fr10-input fr10-select">' +
            '<option value="short">Short</option>' +
            '<option value="long">Long</option>' +
          '</select>' +
        '</div>' +
        '<div class="fr10-btn-row">' +
          '<button class="fr10-btn" id="fr10-send-notify">🔔 Send to Action Center</button>' +
          '<button class="fr10-btn fr10-btn-secondary" id="fr10-test-notify">🧪 Test Notification</button>' +
        '</div>' +
        '<div id="fr10-notify-result" class="fr10-result-msg" style="display:none"></div>' +
        '<div class="fr10-note">' +
          'Requires <code>winotify</code>, <code>win10toast</code>, or <code>plyer</code>.<br>' +
          'Install: <code>pip install winotify</code>' +
        '</div>' +
      '</div>';
    container.appendChild(div);
    document.getElementById('fr10-send-notify').addEventListener('click', sendCustomNotification);
    document.getElementById('fr10-test-notify').addEventListener('click', sendTestNotification);
  }

  async function sendCustomNotification() {
    await _doNotify({
      title:    document.getElementById('fr10-ntitle').value.trim() || 'Secure Eye Trust+',
      message:  document.getElementById('fr10-nmessage').value.trim() || 'Alert.',
      severity: document.getElementById('fr10-nseverity').value,
      duration: document.getElementById('fr10-nduration').value,
    });
  }

  async function sendTestNotification() {
    await _doNotify({
      title:    'Secure Eye Trust+ — Test',
      message:  'Action Center integration is working correctly.',
      severity: 'info',
      duration: 'short',
    });
  }

  async function _doNotify(payload) {
    var statusEl = document.getElementById('fr10-notify-status');
    statusEl.textContent = 'Sending…';
    statusEl.style.background = '#f59e0b';
    _setEl('fr10-notify-result', '');
    document.getElementById('fr10-notify-result').style.display = 'none';
    try {
      var d = await apiFetch(API.notify, { method: 'POST', body: JSON.stringify(payload) });
      if (d.ok) {
        statusEl.textContent = 'Sent via ' + d.method;
        statusEl.style.background = '#10b981';
        _showResult('fr10-notify-result', '✅ Notification delivered via ' + d.method, 'ok');
      } else {
        statusEl.textContent = 'Failed';
        statusEl.style.background = '#ef4444';
        _showResult('fr10-notify-result', '❌ ' + (d.error || 'Unknown error'), 'error');
      }
    } catch (e) {
      statusEl.textContent = 'Error';
      statusEl.style.background = '#ef4444';
      _showResult('fr10-notify-result', '❌ ' + e.message, 'error');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR10-05 — Start Menu Shortcut Management
  // ══════════════════════════════════════════════════════════════════════════

  function buildShortcutPanel(container) {
    var div = document.createElement('div');
    div.className = 'fr10-section';
    div.innerHTML =
      '<div class="fr10-section-header">' +
        '<span class="fr10-section-icon">🪟</span>' +
        '<span class="fr10-section-title">Windows Start Menu Integration</span>' +
        '<span class="fr10-badge" id="fr10-shortcut-badge">Checking…</span>' +
      '</div>' +
      '<div class="fr10-shortcut-body">' +
        '<div id="fr10-shortcut-info" class="fr10-shortcut-info">Checking shortcut status…</div>' +
        '<div class="fr10-btn-row">' +
          '<button class="fr10-btn" id="fr10-btn-create">📌 Pin to Start Menu</button>' +
          '<button class="fr10-btn fr10-btn-danger" id="fr10-btn-remove" style="display:none">🗑 Remove from Start Menu</button>' +
        '</div>' +
        '<div id="fr10-shortcut-result" class="fr10-result-msg" style="display:none"></div>' +
        '<div class="fr10-note">' +
          'Creates a shortcut in:<br>' +
          '<code>%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Secure Eye Trust+</code><br>' +
          'Requires <code>pywin32</code> — install: <code>pip install pywin32</code>' +
        '</div>' +
      '</div>';
    container.appendChild(div);
    document.getElementById('fr10-btn-create').addEventListener('click', createShortcut);
    document.getElementById('fr10-btn-remove').addEventListener('click', removeShortcut);
    checkShortcutStatus();
  }

  async function checkShortcutStatus() {
    var badge  = document.getElementById('fr10-shortcut-badge');
    var infoEl = document.getElementById('fr10-shortcut-info');
    var btnC   = document.getElementById('fr10-btn-create');
    var btnR   = document.getElementById('fr10-btn-remove');
    if (!badge) return;
    try {
      var d = await apiFetch(API.shortcutStatus);
      if (d.exists) {
        badge.textContent = '✅ Installed';
        badge.style.background = '#10b981';
        infoEl.innerHTML = 'Shortcut exists at:<br><code>' + _esc(d.path) + '</code>';
        if (btnC) btnC.style.display = 'none';
        if (btnR) btnR.style.display = '';
      } else {
        badge.textContent = '➕ Not installed';
        badge.style.background = '#253e65';
        infoEl.textContent = 'No Start Menu shortcut found for Secure Eye Trust+.';
        if (btnC) btnC.style.display = '';
        if (btnR) btnR.style.display = 'none';
      }
    } catch (e) {
      badge.textContent = 'Error';
      badge.style.background = '#ef4444';
      if (infoEl) infoEl.textContent = 'Could not check: ' + e.message;
    }
  }

  async function createShortcut() {
    _showResult('fr10-shortcut-result', '⏳ Creating Start Menu shortcut…', 'info');
    try {
      var d = await apiFetch(API.createShortcut, { method: 'POST' });
      if (d.ok) {
        _showResult('fr10-shortcut-result', '✅ Shortcut created at: ' + d.path, 'ok');
        checkShortcutStatus();
      } else {
        _showResult('fr10-shortcut-result', '❌ ' + (d.error || 'Failed'), 'error');
      }
    } catch (e) {
      _showResult('fr10-shortcut-result', '❌ ' + e.message, 'error');
    }
  }

  async function removeShortcut() {
    if (!confirm('Remove Secure Eye Trust+ from the Start Menu?')) return;
    try {
      var d = await apiFetch(API.removeShortcut, { method: 'DELETE' });
      if (d.ok) {
        _showResult('fr10-shortcut-result', '✅ Shortcut removed.', 'ok');
        checkShortcutStatus();
      } else {
        _showResult('fr10-shortcut-result', '❌ ' + (d.error || 'Failed'), 'error');
      }
    } catch (e) {
      _showResult('fr10-shortcut-result', '❌ ' + e.message, 'error');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Init — called on DOMContentLoaded
  // ══════════════════════════════════════════════════════════════════════════
  function init() {
    var container = document.getElementById('fr10-windows-panel');
    if (!container) return;
    injectStyles();
    buildPatchPanel(container);
    buildNotifyPanel(container);
    buildShortcutPanel(container);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  window.FR10 = {
    refreshUpdates:  loadUpdateStatus,
    checkShortcut:   checkShortcutStatus,
    notify: function(title, message, severity) {
      return apiFetch(API.notify, {
        method: 'POST',
        body: JSON.stringify({ title: title, message: message, severity: severity || 'info', duration: 'short' }),
      });
    },
  };

})();
