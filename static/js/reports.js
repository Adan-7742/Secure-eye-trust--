/**
 * reports.js — Secure Eye Trust+
 * Report generation, preview and export.
 * All data pulled from /api/reports/* — real live system data.
 */

let _reportsList   = [];  // in-memory list synced from server
let _latestReportId = null;
const REPORT_ICONS = {
  security:    '🛡', performance: '📈', compliance: '✅',
  daily:       '🕐', network:     '🌐', executive:  '📊', technical:   '🔬',
};
const REPORT_COLORS = {
  security: '#ef4444', performance: '#10b981', compliance: '#06b6d4',
  daily:    '#f59e0b', network:     '#8b5cf6', executive:  '#1a8cff', technical: '#f97316',
};

/* ── Generate ───────────────────────────────────────────────── */
async function generateReport(type) {
  type = type || 'security';
  const wrap = document.getElementById('rpt-table-wrap');
  if (wrap) {
    wrap.innerHTML = [
      '<div class="rpt-generating">',
      '<div class="spinner"></div>',
      `Generating <strong style="color:var(--text-bright)">${type}</strong> report from live data…`,
      '</div>'
    ].join('');
  }

  try {
    const res  = await fetch('/api/reports/generate', {
      method:  'POST',
      headers: {'Content-Type':'application/json'},
      body:    JSON.stringify({ type, include_details: true }),
    });
    const data = await res.json();
    if (!data.ok) { toast('❌ Report failed'); return; }

    _reportsList.unshift(data.report);
    _latestReportId = data.report.id;
    _renderReportTable();
    _updateReportBadge();
    toast('✅ ' + data.report.name + ' ready');
  } catch(e) {
    toast('❌ Generate failed: ' + e.message);
    if (wrap) wrap.innerHTML = '<div style="padding:20px;color:var(--red)">Failed to generate report.</div>';
  }
}

/* ── Render table ────────────────────────────────────────────── */
function _renderReportTable() {
  const wrap  = document.getElementById('rpt-table-wrap');
  const label = document.getElementById('rpt-count-label');
  if (!wrap) return;
  if (label) label.textContent = _reportsList.length + ' report' + (_reportsList.length !== 1 ? 's' : '');

  if (!_reportsList.length) {
    wrap.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-dim)"><div style="font-size:40px;margin-bottom:10px">📄</div><div style="font-size:14px;font-weight:700;color:var(--text-bright);margin-bottom:6px">No reports generated yet</div><div style="font-size:12px">Click "Generate Report" or use the quick cards above</div></div>';
    return;
  }

  const riskColors = { Low:'#4ade80', Medium:'#fcd34d', High:'#fb923c', Critical:'#f87171' };

  let html = '<div class="rpt-row rpt-row-header"><span>Report</span><span>Date &amp; Time</span><span>Type</span><span>Risk</span><span>Actions</span></div>';
  _reportsList.forEach(function(r) {
    const isAnalysis = r.type === 'analysis' || (r.id && r.id.startsWith('pa_'));
    const icon  = isAnalysis ? '🧠' : (REPORT_ICONS[r.type]  || '📄');
    const color = isAnalysis ? '#a78bfa' : (REPORT_COLORS[r.type] || 'var(--sky)');
    const rk    = riskColors[r.risk_label] || '#94a3b8';
    const trigger = r.trigger === 'auto_12h' ? ' <span style="font-size:10px;background:rgba(167,139,250,.15);color:#a78bfa;border:1px solid rgba(167,139,250,.3);padding:1px 7px;border-radius:10px;vertical-align:middle">🤖 Auto</span>' : '';
    const dateStr = (r.generated_at || r.date || '').substring(0, 16);

    // Actions
    let actionsHtml;
    if (isAnalysis) {
      actionsHtml = [
        `<button class="rpt-action-btn primary" onclick="previewAnalysisReport('${r.id}')">👁 View</button>`,
        `<button class="rpt-action-btn download" onclick="pickAndDownloadAnalysis('${r.id}')">⬇ Download</button>`,
        `<button class="rpt-action-btn danger" onclick="deleteReport('${r.id}')">🗑</button>`,
      ].join('');
    } else {
      actionsHtml = [
        `<button class="rpt-action-btn primary" onclick="previewReport('${r.id}')">👁 View</button>`,
        `<button class="rpt-action-btn download" onclick="exportReport('${r.id}','pdf')">⬇ Download</button>`,
        `<button class="rpt-action-btn danger" onclick="deleteReport('${r.id}')">🗑</button>`,
      ].join('');
    }

    html += [
      '<div class="rpt-row">',
      // Name
      '<div class="rpt-row-name">' +
        '<div class="rpt-row-icon" style="background:' + color + '18;color:' + color + '">' + icon + '</div>' +
        '<div>' +
          '<div>' + r.name + trigger + '</div>' +
          '<div style="font-size:10px;color:var(--text-dim);font-family:var(--mono)">' + r.id + '</div>' +
        '</div>' +
      '</div>',
      // Date
      '<div style="font-size:12px;color:var(--text-dim);font-family:var(--mono)">' + dateStr + '</div>',
      // Type
      '<div><span class="rpt-type-chip" style="background:' + color + '18;color:' + color + '">' + (isAnalysis ? 'ANALYSIS' : r.type.toUpperCase()) + '</span></div>',
      // Risk
      '<div><span class="rpt-risk-chip" style="background:' + rk + '18;color:' + rk + ';border:1px solid ' + rk + '33">' + r.risk_label + ' · ' + r.risk_score + '</span></div>',
      // Actions
      '<div class="rpt-actions">' + actionsHtml + '</div>',
      '</div>',
    ].join('');
  });
  wrap.innerHTML = html;
}

function _updateReportBadge() {
  const b = document.getElementById('badge-reports');
  if (b) b.textContent = _reportsList.length;
}

/* ── Preview in overlay iframe ───────────────────────────────── */
function previewReport(rid) {
  // open export endpoint in overlay iframe
  _openPreviewOverlay(`/api/reports/export`, rid, 'html');
}

function _openPreviewOverlay(url, rid, fmt) {
  let overlay = document.getElementById('rpt-preview-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'rpt-preview-overlay';
    overlay.className = 'rpt-preview-overlay';
    overlay.innerHTML = [
      '<div class="rpt-preview-modal">',
      '  <div class="rpt-preview-head">',
      '    <div class="rpt-preview-title" id="rpt-preview-title">Report Preview</div>',
      '    <div style="display:flex;gap:8px;align-items:center">',
      '      <button class="rpt-action-btn" id="rpt-preview-dl-btn">⬇ Download</button>',
      '      <button class="rpt-preview-close" onclick="_closePreview()">✕</button>',
      '    </div>',
      '  </div>',
      '  <div class="rpt-preview-body">',
      '    <iframe class="rpt-preview-iframe" id="rpt-preview-iframe"></iframe>',
      '  </div>',
      '</div>',
    ].join('');
    document.body.appendChild(overlay);
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) _closePreview();
    });
  }

  const rpt  = _reportsList.find(r => r.id === rid);
  const title= document.getElementById('rpt-preview-title');
  const dl   = document.getElementById('rpt-preview-dl-btn');
  if (title && rpt) title.textContent = rpt.name;

  // DL button
  if (dl) dl.onclick = function() { exportReport(rid, 'html'); };

  // Load iframe via blob (POST request)
  fetch(url, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ id: rid, format: fmt }),
  })
  .then(r => r.text())
  .then(html => {
    const iframe = document.getElementById('rpt-preview-iframe');
    if (iframe) {
      const blob = new Blob([html], {type:'text/html'});
      iframe.src = URL.createObjectURL(blob);
    }
    overlay.classList.add('open');
  })
  .catch(e => toast('❌ Preview failed: ' + e.message));
}

function previewAnalysisReport(rid) {
  // Open the AI-styled Perform Analysis report inside the in-app preview overlay.
  let overlay = document.getElementById('rpt-preview-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'rpt-preview-overlay';
    overlay.className = 'rpt-preview-overlay';
    overlay.innerHTML = [
      '<div class="rpt-preview-modal">',
      '  <div class="rpt-preview-head">',
      '    <div class="rpt-preview-title" id="rpt-preview-title">Report Preview</div>',
      '    <div style="display:flex;gap:8px;align-items:center">',
      '      <button class="rpt-action-btn" id="rpt-preview-dl-btn">⬇ Download</button>',
      '      <button class="rpt-preview-close" onclick="_closePreview()">✕</button>',
      '    </div>',
      '  </div>',
      '  <div class="rpt-preview-body">',
      '    <iframe class="rpt-preview-iframe" id="rpt-preview-iframe"></iframe>',
      '  </div>',
      '</div>',
    ].join('');
    document.body.appendChild(overlay);
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) _closePreview();
    });
  }

  const rpt  = _reportsList.find(r => r.id === rid);
  const title= document.getElementById('rpt-preview-title');
  const dl   = document.getElementById('rpt-preview-dl-btn');
  if (title && rpt) title.textContent = rpt.name;
  if (dl) dl.onclick = function() { pickAndDownloadAnalysis(rid); };

  const iframe = document.getElementById('rpt-preview-iframe');
  if (iframe) {
    iframe.src = '/api/ai-report?report_id=' + encodeURIComponent(rid) + '&t=' + Date.now();
  }
  overlay.classList.add('open');
}

window._closePreview = function() {
  const o = document.getElementById('rpt-preview-overlay');
  if (o) o.classList.remove('open');
};

/* ── Export ──────────────────────────────────────────────────── */
async function exportReport(rid, fmt) {
  try {
    const res  = await fetch('/api/reports/export', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ id: rid, format: fmt }),
    });
    if (!res.ok) { toast('❌ Export failed'); return; }

    if (fmt === 'html') {
      const html = await res.text();
      const win  = window.open('', '_blank');
      win.document.open(); win.document.write(html); win.document.close();
      return;
    }
    // Download file
    const blob = await res.blob();
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    const rpt  = _reportsList.find(r => r.id === rid);
    const ext  = fmt === 'pdf' ? '.pdf' : fmt === 'csv' ? '.csv' : fmt === 'html' ? '.html' : '.json';
    a.download  = (rpt ? rpt.id : 'report') + ext;
    document.body.appendChild(a); a.click();
    a.remove(); URL.revokeObjectURL(a.href);
  } catch(e) { toast('❌ Export error: ' + e.message); }
}

/* ── Export latest ───────────────────────────────────────────── */
async function exportLatest(fmt) {
  if (!_latestReportId) {
    toast('Generate a report first');
    return;
  }
  exportReport(_latestReportId, fmt);
}

/* ── Delete ──────────────────────────────────────────────────── */
function deleteReport(rid) {
  const report = _reportsList.find(r => r.id === rid) || {};
  const isAnalysis = report.type === 'analysis' || (report.id && report.id.startsWith('pa_'));
  _showPasswordModal({
    title: 'Delete Report',
    message: 'Permanently delete this report? Enter the dashboard password to confirm.',
    btnLabel: '🗑 Delete Report',
    btnColor: '#ef4444',
    failKey: 'report-delete-' + rid,
    captureReason: 'Failed report delete',
    onConfirm: async function(password) {
      if (isAnalysis) {
        const r = await fetch('/api/perform-analysis/delete/' + rid, {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const d = await r.json();
        if (!d.ok) {
          throw new Error(d.error || 'Delete failed');
        }
      } else {
        // Regular (non-analysis) reports stored in-memory — delete via API for parity
        const r = await fetch('/api/reports/delete/' + rid, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const d = await r.json();
        if (!d.ok) throw new Error(d.error || 'Delete failed');
      }
      _reportsList = _reportsList.filter(r => r.id !== rid);
      if (_latestReportId === rid) _latestReportId = _reportsList[0]?.id || null;
      _renderReportTable();
      _updateReportBadge();
      toast('🗑 Report deleted');
    }
  });
}

/* ── Show modal (type picker) ────────────────────────────────── */
function showReportModal() {
  const types = [
    {key:'security',    label:'Security Audit',    icon:'🛡',  desc:'Threats, failed logons, security event IDs'},
    {key:'performance', label:'Performance',        icon:'📈',  desc:'CPU, RAM, disk utilization report'},
    {key:'compliance',  label:'Compliance Check',   icon:'✅',  desc:'NIST / CIS benchmark style report'},
    {key:'daily',       label:'Daily Summary',      icon:'🕐',  desc:'24-hour activity across all log categories'},
    {key:'network',     label:'Network Report',     icon:'🌐',  desc:'Active connections and network stats'},
    {key:'executive',   label:'Executive Summary',  icon:'📊',  desc:'High-level overview for management'},
    {key:'technical',   label:'Technical Deep Dive',icon:'🔬',  desc:'Full technical detail for IT staff'},
  ];

  let existing = document.getElementById('rpt-type-modal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'rpt-type-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:800;display:flex;align-items:center;justify-content:center;animation:overlay-in .18s ease';
  modal.innerHTML = [
    '<div style="width:min(560px,94vw);background:var(--bg2);border:1px solid var(--border2);border-radius:20px;overflow:hidden;box-shadow:0 30px 80px rgba(0,0,0,.7);animation:modal-up .2s ease">',
    '  <div style="padding:18px 22px;background:var(--panel2);border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">',
    '    <span style="font-size:16px;font-weight:800;color:var(--text-bright)">📄 Choose Report Type</span>',
    '    <button onclick="this.closest(\'#rpt-type-modal\')?.remove()||document.getElementById(\'rpt-type-modal\').remove()" style="background:none;border:1px solid var(--border2);color:var(--text-dim);border-radius:50%;width:28px;height:28px;cursor:pointer;font-size:14px">✕</button>',
    '  </div>',
    '  <div style="padding:16px;display:grid;grid-template-columns:1fr 1fr;gap:10px;max-height:70vh;overflow-y:auto">',
    types.map(t => [
      `<div onclick="document.getElementById('rpt-type-modal').remove();generateReport('${t.key}')"`,
      `style="padding:14px;border-radius:12px;border:1px solid var(--border);background:var(--panel);cursor:pointer;transition:all .15s"`,
      `onmouseover="this.style.borderColor='var(--border2)';this.style.transform='translateY(-2px)'"`,
      `onmouseout="this.style.borderColor='var(--border)';this.style.transform='none'"`,
      `>`,
      `  <div style="font-size:22px;margin-bottom:7px">${t.icon}</div>`,
      `  <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:4px">${t.label}</div>`,
      `  <div style="font-size:11px;color:var(--text-dim)">${t.desc}</div>`,
      `</div>`,
    ].join('')).join(''),
    '  </div>',
    '</div>',
  ].join('');

  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
}

/* ── Load from server (includes persisted analysis reports) ─── */
async function loadReportsFromServer() {
  try {
    const res  = await fetch('/api/reports/list');
    const data = await res.json();
    if (data.reports) {
      // Merge server list with any locally generated ones
      const serverIds = new Set(data.reports.map(r => r.id));
      const localOnly = _reportsList.filter(r => !serverIds.has(r.id));
      _reportsList = [...data.reports, ...localOnly];
      _reportsList.sort((a,b) => (b.generated_at||'').localeCompare(a.generated_at||''));
    }
  } catch(e) {
    console.warn('Could not load reports from server:', e.message);
  }
  _renderReportTable();
  _updateReportBadge();
}


/* ── Export analysis report (uses perform-analysis endpoint) ── */
async function exportAnalysisReport(reportId, fmt) {
  const url = '/api/perform-analysis/export/' + reportId + '/' + fmt + '?t=' + Date.now();
  const btn = event && event.target;
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      toast('❌ Export failed: ' + (err.error || r.status));
      return;
    }
    const blob = await r.blob();
    const ext  = fmt === 'pdf' ? '.pdf' : fmt === 'html' ? '.html' : fmt === 'csv' ? '.csv' : '.json';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'analysis_' + reportId + ext;
    document.body.appendChild(a); a.click();
    setTimeout(function() { a.remove(); URL.revokeObjectURL(a.href); }, 2000);
    toast('✅ ' + fmt.toUpperCase() + ' report downloaded');
  } catch(e) {
    toast('❌ ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = fmt.toUpperCase(); }
  }
}

/* ── Badge update ─────────────────────────────────────────────── */
function _updateReportBadge() {
  const badge = document.getElementById('badge-reports');
  if (badge) badge.textContent = _reportsList.length || '';
}

/* ── Pick format modal + download ────────────────────────────── */
function pickAndDownloadAnalysis(reportId) {
  // Remove any existing modal
  var existing = document.getElementById('dl-modal');
  if (existing) existing.remove();

  var modal = document.createElement('div');
  modal.id = 'dl-modal';
  modal.style.cssText = [
    'position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999',
    'display:flex;align-items:center;justify-content:center',
    'animation:fadeIn .15s ease'
  ].join(';');

  modal.innerHTML = [
    '<div style="background:#0f1a2e;border:1px solid rgba(255,255,255,.12);border-radius:16px;padding:28px;min-width:340px;box-shadow:0 24px 60px rgba(0,0,0,.6)">',
      '<div style="font-size:16px;font-weight:800;color:#e2e8f0;margin-bottom:6px">Download Report</div>',
      '<div style="font-size:12px;color:#64748b;margin-bottom:22px">Choose format for: <span style="color:#4da6ff;font-family:monospace">' + reportId + '</span></div>',
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px">',
        _dlBtn('pdf',  '⬇ PDF',  'background:linear-gradient(135deg,#ef4444,#b91c1c);color:#fff;border:none',  reportId),
        _dlBtn('html', '⬇ HTML', 'background:rgba(26,140,255,.15);color:#4da6ff;border:1px solid rgba(26,140,255,.3)', reportId),
        _dlBtn('csv',  '⬇ CSV',  'background:rgba(74,222,128,.12);color:#4ade80;border:1px solid rgba(74,222,128,.3)', reportId),
        _dlBtn('json', '⬇ JSON', 'background:rgba(255,255,255,.06);color:#94a3b8;border:1px solid rgba(255,255,255,.1)', reportId),
      '</div>',
      '<button onclick="document.getElementById(\'dl-modal\').remove()" ',
        'style="width:100%;background:transparent;border:1px solid rgba(255,255,255,.1);color:#64748b;padding:9px;border-radius:8px;cursor:pointer;font-size:13px">',
        'Cancel',
      '</button>',
    '</div>'
  ].join('');

  // Close on backdrop click
  modal.addEventListener('click', function(e) {
    if (e.target === modal) modal.remove();
  });
  document.body.appendChild(modal);
}

function _dlBtn(fmt, label, style, reportId) {
  return '<button onclick="exportAnalysisReport(\'' + reportId + '\',\'' + fmt + '\');document.getElementById(\'dl-modal\').remove()" ' +
    'style="' + style + ';padding:12px;border-radius:10px;cursor:pointer;font-size:13px;font-weight:700;transition:all .15s">' +
    label + '</button>';
}

const _deleteActionAttempts = {};

function _showPasswordModal({ title, message, btnLabel, btnColor, failKey, captureReason, onConfirm }) {
  const existing = document.getElementById('report-del-modal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'report-del-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center;';

  modal.innerHTML = `
    <div style="background:#0f1a2e;border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:28px 26px;width:min(420px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.6);">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;">
        <div style="width:38px;height:38px;background:rgba(239,68,68,.12);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0">🔐</div>
        <div style="font-size:16px;font-weight:800;color:#e8f4ff">${title}</div>
      </div>
      <div style="font-size:13px;color:#8faac8;line-height:1.6;margin-bottom:20px;">${message}</div>
      <div style="margin-bottom:18px;">
        <label style="display:block;font-size:11px;font-weight:700;color:#4a6a8a;text-transform:uppercase;letter-spacing:.1em;margin-bottom:7px;">Enter Password to Confirm</label>
        <div style="position:relative;">
          <input id="rpm-pass" type="password" placeholder="Dashboard password" autocomplete="current-password"
            style="width:100%;padding:12px 44px 12px 14px;border-radius:10px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);color:#e8f4ff;font-size:13px;outline:none;font-family:inherit;">
          <button id="rpm-toggle" type="button" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;color:#4a6a8a;cursor:pointer;font-size:14px;padding:4px;">👁</button>
        </div>
        <div id="rpm-err" style="display:none;margin-top:10px;padding:10px 12px;border-radius:8px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);color:#fca5a5;font-size:12px;"></div>
      </div>
      <div style="display:flex;gap:10px;">
        <button type="button" id="rpm-cancel" style="flex:1;padding:12px;border-radius:10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#8faac8;cursor:pointer;font-size:13px;font-weight:600;font-family:inherit;">Cancel</button>
        <button type="button" id="rpm-confirm" style="flex:2;padding:12px;border-radius:10px;background:${btnColor};border:none;color:#fff;cursor:pointer;font-size:13px;font-weight:700;font-family:inherit;">${btnLabel}</button>
      </div>
    </div>`;

  modal.addEventListener('click', function(e) {
    if (e.target === modal) modal.remove();
  });

  document.body.appendChild(modal);
  const passInput = document.getElementById('rpm-pass');
  const errEl = document.getElementById('rpm-err');
  const confirmBtn = document.getElementById('rpm-confirm');
  const toggleBtn = document.getElementById('rpm-toggle');
  const cancelBtn = document.getElementById('rpm-cancel');

  if (passInput) {
    passInput.focus();
    passInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') confirmBtn.click();
    });
  }
  if (toggleBtn) {
    toggleBtn.addEventListener('click', function() {
      passInput.type = passInput.type === 'password' ? 'text' : 'password';
      toggleBtn.textContent = passInput.type === 'password' ? '👁' : '🙈';
    });
  }
  if (cancelBtn) {
    cancelBtn.addEventListener('click', () => modal.remove());
  }

  confirmBtn.addEventListener('click', async function() {
    const password = passInput.value.trim();
    if (!password) {
      errEl.textContent = 'Please enter the dashboard password.';
      errEl.style.display = 'block';
      return;
    }
    confirmBtn.disabled = true;
    confirmBtn.textContent = '⟳ Verifying…';
    errEl.style.display = 'none';
    try {
      await onConfirm(password);
      if (failKey) _deleteActionAttempts[failKey] = 0;
      modal.remove();
    } catch (err) {
      const msg = err?.message || 'Wrong password';
      errEl.textContent = '❌ ' + msg;
      errEl.style.display = 'block';
      confirmBtn.disabled = false;
      confirmBtn.textContent = btnLabel;
      if (failKey && /password/i.test(msg)) {
        _deleteActionAttempts[failKey] = (_deleteActionAttempts[failKey] || 0) + 1;
        if (_deleteActionAttempts[failKey] >= 2) {
          toast('⚠ 2 failed password attempts — recording intruder capture');
          _captureIntruderPhoto(captureReason || title);
        }
      }
      passInput.value = '';
      passInput.focus();
    }
  });
}

async function _captureIntruderPhoto(reason = 'Unauthorized delete') {
  let photo = '';
  if (navigator.mediaDevices?.getUserMedia) {
    const video = document.createElement('video');
    const canvas = document.createElement('canvas');
    canvas.width = 320;
    canvas.height = 240;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240 }, audio: false });
      video.srcObject = stream;
      await video.play();
      await new Promise((resolve) => setTimeout(resolve, 500));
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, 320, 240);
      photo = canvas.toDataURL('image/jpeg', 0.7);
      stream.getTracks().forEach((track) => track.stop());
    } catch (e) {
      console.warn('Intruder camera capture failed:', e.message);
    }
  }
  try {
    await fetch('/api/auth/intruder-photo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: reason, photo, attempt_no: 2 })
    });
  } catch (e) {
    console.warn('Intruder save failed:', e.message);
  }
}

/* ── Delete analysis report from DB ─────────────────────────── */
async function deleteAnalysisReport(reportId, btnEl) {
  _showPasswordModal({
    title: 'Delete Report',
    message: 'Permanently delete this analysis report? Enter the dashboard password to confirm.',
    btnLabel: '🗑 Delete Report',
    btnColor: '#ef4444',
    failKey: 'report-delete-' + reportId,
    captureReason: 'Failed report delete',
    onConfirm: async function(password) {
      if (btnEl) { btnEl.disabled = true; btnEl.textContent = '…'; }
      const r = await fetch('/api/perform-analysis/delete/' + reportId, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });
      const d = await r.json();
      if (!d.ok) {
        throw new Error(d.error || 'Delete failed');
      }
      _reportsList = _reportsList.filter(function(r) { return r.id !== reportId; });
      _renderReportTable();
      _updateReportBadge();
      toast('🗑 Report deleted');
    }
  });
}
