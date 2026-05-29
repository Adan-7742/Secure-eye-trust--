/**
 * static/js/logs.js  — ENHANCED v2
 * ==================================
 * ✅ Every ERROR/CRITICAL row has a 🤖 AI Explain button
 * ✅ Click any row to open full AI Detail + Auto-Fix modal
 * ✅ Auto-Resolve button: one-click copy of PowerShell/CMD fix
 * ✅ "Copy Fix" and "Run in Terminal" buttons in modal
 * ✅ Error rows highlighted with severity colour
 * ✅ Real-time new-error notification fired when ERROR loaded
 */

'use strict';

let currentCat   = 'application';
let currentPage  = 1;
let currentDate  = '';
let currentLevel = '';

// ─────────────────────────────────────────────────────────────────────────────
//  SHOW LOGS PAGE
// ─────────────────────────────────────────────────────────────────────────────

async function showLogsPage(category, el) {
  currentCat   = category;
  currentPage  = 1;
  currentDate  = '';
  currentLevel = '';

  showPage('logs', el);

  const labels = {
    application:    'Application',
    system:         'System',
    security:       'Security',
    windows_update: 'Win Update'
  };
  setText('logs-page-title', `📋 ${labels[category] || category} Logs`);

  const dayData  = await api(`/api/days/${category}`);
  const daySelect = document.getElementById('day-filter');
  if (daySelect) {
    daySelect.innerHTML = '<option value="">All Days</option>';
    (dayData.days || []).forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.date;
      opt.textContent = `${d.date}  (${fmt(d.total)}${d.errors > 0 ? ' ⚠' + d.errors + ' err' : ''})`;
      daySelect.appendChild(opt);
    });
  }

  loadLogs();
}

// ─────────────────────────────────────────────────────────────────────────────
//  LOAD + RENDER LOGS TABLE
// ─────────────────────────────────────────────────────────────────────────────

async function loadLogs() {
  const tbody = document.getElementById('logs-tbody');
  const info  = document.getElementById('logs-info');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="7" style="padding:20px;color:var(--text-dim)">
    <div class="loading"><div class="spinner"></div> Loading…</div>
  </td></tr>`;

  const params = new URLSearchParams({ page: currentPage, per_page: 100 });
  if (currentDate)  params.set('date',  currentDate);
  if (currentLevel) params.set('level', currentLevel);

  const data = await api(`/api/logs/${currentCat}?${params}`);
  const { logs, total, page, pages } = data;

  tbody.innerHTML = '';
  if (!logs.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="padding:20px;color:var(--text-dim);text-align:center">
      No logs found</td></tr>`;
  } else {
    window._logRows = {};

    logs.forEach((row, idx) => {
      const logData = {
        timestamp: row.timestamp,
        level:     row.level,
        source:    row.source,
        event_id:  row.event_id,
        message:   row.message,
        category:  currentCat
      };
      window._logRows[idx] = logData;

      const lvl       = (row.level || '').toUpperCase();
      const isError   = ['ERROR','CRITICAL','FAILURE'].includes(lvl);
      const isWarning = lvl === 'WARNING';

      // Row highlight for errors
      const rowBg = isError
        ? 'background:rgba(239,68,68,.04);border-left:2px solid rgba(239,68,68,.3)'
        : isWarning
        ? 'background:rgba(251,191,36,.03);border-left:2px solid rgba(251,191,36,.2)'
        : '';

      const tr = document.createElement('tr');
      tr.style.cssText = rowBg + ';cursor:pointer;transition:background .1s';
      tr.title = 'Click to see AI analysis & fix';

      // Whole-row click = explain
      tr.addEventListener('click', () => logExplainByIndex(idx));
      tr.addEventListener('mouseenter', () => {
        if (!isError && !isWarning) tr.style.background = 'rgba(255,255,255,.02)';
      });
      tr.addEventListener('mouseleave', () => {
        if (!isError && !isWarning) tr.style.background = '';
      });

      tr.innerHTML = `
        <td style="color:var(--text-dim);font-family:var(--mono);font-size:11px;white-space:nowrap;padding:7px 10px">
          🕒 ${row.timestamp || ''}
        </td>
        <td style="padding:7px 8px">${levelBadge(row.level)}</td>
        <td style="font-family:var(--mono);font-size:11px;color:var(--blue);padding:7px 8px">
          ${trunc(row.source, 30)}
        </td>
        <td style="font-family:var(--mono);font-size:11px;color:var(--text-dim);padding:7px 8px">
          ${row.event_id || '—'}
        </td>
        <td class="msg-cell" title="${(row.message || '').replace(/"/g,'&quot;')}" style="padding:7px 8px">
          ${trunc(row.message, 80)}
        </td>
        <td style="padding:6px 10px;white-space:nowrap" onclick="event.stopPropagation()">
          <!-- AI Explain button -->
          <button class="log-ai-btn" title="AI Explain + Fix" onclick="logExplainByIndex(${idx})" style="
            display:inline-flex;align-items:center;gap:5px;
            padding:4px 10px;border-radius:6px;font-size:10px;font-weight:700;
            background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.25);
            color:#60a5fa;cursor:pointer;transition:all .15s;font-family:monospace;
            white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:70px
          " onmouseover="this.style.background='rgba(59,130,246,.2)'"
             onmouseout="this.style.background='rgba(59,130,246,.1)'">
            🤖 Explain
          </button>
          ${isError ? `
          <button class="log-fix-btn" title="Quick Fix" onclick="event.stopPropagation();logQuickFix(${idx})" style="
            display:inline-flex;align-items:center;gap:5px;
            padding:4px 10px;border-radius:6px;font-size:10px;font-weight:700;
            background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);
            color:#4ade80;cursor:pointer;transition:all .15s;font-family:monospace;margin-left:4px;
            white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:55px
          " onmouseover="this.style.background='rgba(34,197,94,.2)'"
             onmouseout="this.style.background='rgba(34,197,94,.1)'">
            🔧 Fix
          </button>` : ''}
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  if (info) info.textContent = `${fmt(total)} logs — page ${page}/${pages}`;
  renderPagination(page, pages);
}

// ─────────────────────────────────────────────────────────────────────────────
//  PAGINATION
// ─────────────────────────────────────────────────────────────────────────────

function renderPagination(page, pages) {
  const el = document.getElementById('logs-pagination');
  if (!el) return;
  el.innerHTML = '';
  const btn = (label, p, disabled=false, active=false) => {
    const b = document.createElement('button');
    b.className = `page-btn${active?' active':''}`;
    b.textContent = label;
    b.disabled = disabled;
    b.onclick = () => { currentPage = p; loadLogs(); };
    return b;
  };
  el.appendChild(btn('‹ Prev', page-1, page<=1));
  const start = Math.max(1, page-2), end = Math.min(pages, page+2);
  for (let i = start; i <= end; i++) el.appendChild(btn(i, i, false, i===page));
  el.appendChild(btn('Next ›', page+1, page>=pages));
}

function onDayFilter(val)   { currentDate  = val; currentPage = 1; loadLogs(); }
function onLevelFilter(val) { currentLevel = val; currentPage = 1; loadLogs(); }

// ══════════════════════════════════════════════════════════════════════════════
//  AI LOG EXPLAIN — opens full detail modal
// ══════════════════════════════════════════════════════════════════════════════

function logExplainByIndex(idx) {
  const log = window._logRows && window._logRows[idx];
  if (!log) { console.error('logExplainByIndex: no data for index', idx); return; }
  logExplainOpen(log);
}

/** Quick fix — opens modal pre-scrolled to fix steps */
function logQuickFix(idx) {
  const log = window._logRows && window._logRows[idx];
  if (!log) return;
  logExplainOpen(log, true);
}

function logExplainOpen(log, scrollToFix = false) {
  if (!log || typeof log !== 'object') {
    try { log = JSON.parse(log); } catch(e) { return; }
  }

  // Show loading immediately
  _logExplainShowModal(log, null, scrollToFix);

  // Fetch AI analysis
  fetch('/api/explain-log', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ log })
  })
  .then(r => r.json())
  .then(data => _logExplainShowModal(log, data, scrollToFix))
  .catch(err => _logExplainShowModal(log, { ok: false, error: err.message }, scrollToFix));
}

// ──────────────────────────────────────────────────────────────────────────────

function _esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

const _SEV_COLS = {
  CRITICAL: { bg:'rgba(239,68,68,.12)',  border:'rgba(239,68,68,.3)',   text:'#ef4444', glow:'rgba(239,68,68,.2)' },
  HIGH:     { bg:'rgba(249,115,22,.10)', border:'rgba(249,115,22,.25)', text:'#f97316', glow:'rgba(249,115,22,.15)' },
  MEDIUM:   { bg:'rgba(245,158,11,.10)', border:'rgba(245,158,11,.25)', text:'#f59e0b', glow:'rgba(245,158,11,.1)' },
  LOW:      { bg:'rgba(34,197,94,.08)',  border:'rgba(34,197,94,.2)',   text:'#22c55e', glow:'rgba(34,197,94,.1)' },
  INFO:     { bg:'rgba(59,130,246,.08)', border:'rgba(59,130,246,.2)',  text:'#3b82f6', glow:'rgba(59,130,246,.1)' },
  ERROR:    { bg:'rgba(249,115,22,.10)', border:'rgba(249,115,22,.25)', text:'#f97316', glow:'rgba(249,115,22,.1)' },
  WARNING:  { bg:'rgba(245,158,11,.10)', border:'rgba(245,158,11,.25)', text:'#f59e0b', glow:'rgba(245,158,11,.1)' },
};

function _logExplainShowModal(log, data, scrollToFix = false) {
  let modal = document.getElementById('log-explain-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'log-explain-modal';
    document.body.appendChild(modal);
  }

  const loading  = !data;
  const sev      = (data && (data.severity || data.level || '')) || (log.level || 'INFO');
  const sevUpper = sev.toUpperCase();
  const isThreat = !!(data && data.is_threat);
  const aiSrc    = (data && data.ai_source) || '';
  const model    = (data && data.groq_model) || '';
  const cols     = _SEV_COLS[sevUpper] || _SEV_COLS.INFO;

  const aiLabel = aiSrc === 'perplexity' ? '⚡ Perplexity AI'
                : aiSrc === 'groq'       ? `🤖 Groq · ${model || 'gemma2-9b-it'}`
                : '📚 Knowledge Base';

  const e = _esc;

  const bullets = (arr, col) => {
    if (!arr || !arr.length) return '<p style="color:#64748b;font-size:13px">—</p>';
    return (Array.isArray(arr) ? arr : [arr]).map(item =>
      `<div style="display:flex;gap:10px;margin-bottom:9px;align-items:flex-start">
        <span style="width:6px;height:6px;border-radius:50%;background:${col||'#3b82f6'};
          margin-top:7px;flex-shrink:0;display:inline-block"></span>
        <span style="font-size:13px;color:#cbd5e1;line-height:1.7">${e(item)}</span>
      </div>`
    ).join('');
  };

  const steps = (arr) => {
    if (!arr || !arr.length) return '<p style="color:#64748b;font-size:13px">—</p>';
    return (Array.isArray(arr) ? arr : [arr]).map((item, i) =>
      `<div style="display:flex;gap:12px;margin-bottom:10px;align-items:flex-start">
        <span style="width:22px;height:22px;border-radius:50%;background:rgba(59,130,246,.15);
          color:#60a5fa;font-size:10px;font-weight:800;display:flex;align-items:center;
          justify-content:center;flex-shrink:0;border:1px solid rgba(59,130,246,.25)">${i+1}</span>
        <span style="font-size:13px;color:#cbd5e1;line-height:1.7;padding-top:2px">${e(item)}</span>
      </div>`
    ).join('');
  };

  const secHdr = (icon, label, col) =>
    `<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;
      padding-bottom:10px;border-bottom:1px solid rgba(255,255,255,.06)">
      <span style="width:22px;height:22px;border-radius:6px;background:${col}22;
        display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0">${icon}</span>
      <span style="font-size:10px;font-weight:800;color:${col};text-transform:uppercase;
        letter-spacing:.1em;font-family:monospace">${label}</span>
    </div>`;

  // ── Build the PowerShell fix commands from the AI response ──
  // Priority: use the real powershell_commands[] returned by the explain
  // endpoint (these are runnable commands). Fall back to fix_steps converted
  // to comments only if the AI did not give us commands.
  const buildPsScript = (data) => {
    var cmds = data && data.powershell_commands;
    if (Array.isArray(cmds) && cmds.length) {
      return cmds.map(function (c) { return String(c).trim(); }).filter(Boolean).join('\n');
    }
    // Last resort — turn human steps into comments (won't execute, but at
    // least documents the intent)
    var steps = data && data.fix_steps;
    if (Array.isArray(steps) && steps.length) {
      return steps.map((s, i) => `# Step ${i+1}: ${s}`).join('\n');
    }
    return '';
  };

  const fixScript = data ? buildPsScript(data) : '';

  modal.innerHTML = `
    <div onclick="logExplainClose()" style="
      position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(8px);
      z-index:9990;display:flex;align-items:center;justify-content:center;padding:16px
    ">
      <div id="lem-inner" onclick="event.stopPropagation()" style="
        background:#0a1018;border:1px solid rgba(255,255,255,.1);border-radius:14px;
        width:100%;max-width:820px;max-height:92vh;overflow-y:auto;
        box-shadow:0 32px 100px rgba(0,0,0,.8),0 0 0 1px rgba(255,255,255,.05);
        animation:lemSlideIn .22s cubic-bezier(.16,1,.3,1)
      ">
        <style>
          @keyframes lemSlideIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
          @keyframes spin{to{transform:rotate(360deg)}}
          .copy-flash{animation:copyFlash .4s ease}
          @keyframes copyFlash{0%,100%{background:rgba(59,130,246,.1)}50%{background:rgba(59,130,246,.35)}}
        </style>

        <!-- ═══ HEADER ═══ -->
        <div style="
          padding:20px 24px 16px;
          background:linear-gradient(135deg,#0d1626 0%,#0f1a2e 100%);
          border-radius:14px 14px 0 0;border-bottom:1px solid rgba(255,255,255,.07);
          position:relative;overflow:hidden
        ">
          <div style="position:absolute;top:0;left:0;right:0;height:2px;
            background:linear-gradient(90deg,${cols.text},#8b5cf6 50%,${cols.text})"></div>

          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px">
                <span style="font-size:16px;font-weight:800;color:#fff;letter-spacing:-.01em">
                  ${loading ? '⏳ AI Analysing…' : e(data.event_name || 'Log Analysis')}
                </span>
                ${!loading && data.severity ? `<span style="padding:3px 10px;border-radius:5px;font-size:10px;
                  font-weight:800;background:${cols.bg};color:${cols.text};border:1px solid ${cols.border};
                  font-family:monospace;text-transform:uppercase;letter-spacing:.07em">${e(data.severity)}</span>` : ''}
                ${!loading && isThreat ? `<span style="padding:3px 10px;border-radius:5px;font-size:10px;
                  font-weight:800;background:rgba(239,68,68,.15);color:#ef4444;
                  border:1px solid rgba(239,68,68,.3)">⚠ THREAT</span>` : ''}
              </div>
              <div style="display:flex;flex-wrap:wrap;gap:6px">
                ${log.timestamp ? `<span style="padding:3px 9px;border-radius:5px;
                  background:rgba(255,255,255,.05);color:#64748b;font-size:10px;font-family:monospace">
                  🕐 ${e(log.timestamp)}</span>` : ''}
                ${log.level ? `<span style="padding:3px 9px;border-radius:5px;
                  background:${cols.bg};color:${cols.text};font-size:10px;font-family:monospace;font-weight:700">
                  ${e(log.level)}</span>` : ''}
                ${log.source ? `<span style="padding:3px 9px;border-radius:5px;
                  background:rgba(255,255,255,.05);color:#8faac8;font-size:10px;font-family:monospace"
                  title="${e(log.source)}">📡 ${e((log.source||'').substring(0,40))}</span>` : ''}
                ${log.event_id ? `<span style="padding:3px 9px;border-radius:5px;
                  background:rgba(59,130,246,.12);color:#60a5fa;font-size:10px;
                  font-family:monospace;font-weight:800;border:1px solid rgba(59,130,246,.2)">
                  EID ${e(String(log.event_id))}</span>` : ''}
              </div>
            </div>
            <button onclick="logExplainClose()" style="
              background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);
              color:#94a3b8;width:32px;height:32px;border-radius:8px;cursor:pointer;
              font-size:15px;display:flex;align-items:center;justify-content:center;flex-shrink:0
            ">✕</button>
          </div>
        </div>

        <!-- ═══ ORIGINAL MESSAGE ═══ -->
        ${log.message ? `
        <div style="margin:14px 20px 0;padding:10px 14px;
          background:rgba(0,0,0,.35);border-radius:8px;
          border-left:3px solid rgba(100,116,139,.35)">
          <div style="font-size:9px;font-weight:700;color:#445566;text-transform:uppercase;
            letter-spacing:.1em;margin-bottom:5px;font-family:monospace">Original Log Message</div>
          <div style="font-size:11px;color:#8899aa;font-family:monospace;line-height:1.65;
            word-break:break-all">${e(log.message)}</div>
        </div>` : ''}

        <!-- ═══ LOADING ═══ -->
        ${loading ? `
        <div style="padding:56px 24px;text-align:center">
          <div style="width:40px;height:40px;border:2px solid rgba(59,130,246,.15);
            border-top-color:#3b82f6;border-radius:50%;animation:spin .75s linear infinite;
            margin:0 auto 14px"></div>
          <div style="color:#4a6080;font-size:13px;font-family:monospace">
            AI is analysing this log and preparing fix steps…</div>
        </div>` : ''}

        <!-- ═══ AI CONTENT ═══ -->
        ${!loading && data && data.ok !== false ? `

        <!-- AI badge row -->
        <div style="padding:12px 20px 4px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;
            border-radius:20px;font-size:10px;font-weight:700;font-family:monospace;
            background:rgba(59,130,246,.1);color:#60a5fa;border:1px solid rgba(59,130,246,.2)">
            <span style="width:5px;height:5px;border-radius:50%;background:#3b82f6;
              box-shadow:0 0 5px #3b82f6;display:inline-block"></span>
            ${aiLabel}
          </span>
          ${data.category ? `<span style="padding:4px 10px;border-radius:5px;font-size:10px;
            font-weight:600;background:rgba(255,255,255,.05);color:#64748b;font-family:monospace">
            ${e(data.category)}</span>` : ''}
          ${data.threat_level && data.threat_level !== 'None' ? `<span style="padding:4px 10px;
            border-radius:5px;font-size:10px;font-weight:700;background:${cols.bg};
            color:${cols.text};border:1px solid ${cols.border};font-family:monospace">
            Threat: ${e(data.threat_level)}</span>` : ''}
        </div>

        <div style="padding:14px 20px 20px;display:flex;flex-direction:column;gap:14px">

          <!-- Overview -->
          <div style="background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);
            border-radius:10px;padding:16px 18px">
            ${secHdr('💬','Overview','#94a3b8')}
            <p style="font-size:14px;color:#cbd5e1;line-height:1.75;margin:0">
              ${e(data.overview || '—')}
            </p>
          </div>

          <!-- Usual Behavior + Warning Signs -->
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
            <div style="background:rgba(34,197,94,.04);border:1px solid rgba(34,197,94,.12);
              border-radius:10px;padding:16px 18px">
              ${secHdr('✅','Usual Behavior','#22c55e')}
              ${bullets(data.usual_behavior, '#22c55e')}
            </div>
            <div style="background:rgba(239,68,68,.04);border:1px solid rgba(239,68,68,.15);
              border-radius:10px;padding:16px 18px">
              ${secHdr('⚠️','Warning Signs','#ef4444')}
              ${bullets(data.warning_signs, '#ef4444')}
            </div>
          </div>

          <!-- This specific event -->
          <div style="background:${isThreat ? cols.bg : 'rgba(59,130,246,.05)'};
            border:1px solid ${isThreat ? cols.border : 'rgba(59,130,246,.15)'};
            border-radius:10px;padding:16px 18px">
            ${secHdr('🔍','Analysis of This Specific Event', isThreat ? cols.text : '#3b82f6')}
            <p style="font-size:13.5px;color:${isThreat ? '#fca5a5' : '#93c5fd'};
              line-height:1.75;margin:0;font-weight:${isThreat ? '500' : '400'}">
              ${e(data.this_specific_event || '—')}
            </p>
          </div>

          <!-- Immediate Action -->
          ${data.immediate_action ? `
          <div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);
            border-radius:10px;padding:14px 18px;display:flex;gap:12px;align-items:flex-start">
            <span style="font-size:18px;flex-shrink:0;margin-top:1px">⚡</span>
            <div>
              <div style="font-size:9px;font-weight:800;color:#d97706;text-transform:uppercase;
                letter-spacing:.1em;margin-bottom:5px;font-family:monospace">Immediate Action</div>
              <div style="font-size:13.5px;color:#fde68a;line-height:1.7;font-weight:500">
                ${e(data.immediate_action)}
              </div>
            </div>
          </div>` : ''}

          <!-- ══ AUTO-RESOLVE: Step-by-Step Fix + Copy/Run buttons ══ -->
          <div id="lem-fix-section" style="background:rgba(34,197,94,.04);
            border:1px solid rgba(34,197,94,.2);border-radius:10px;padding:16px 18px">
            ${secHdr('🔧','Auto-Resolve — Step-by-Step Fix','#22c55e')}

            <!-- Steps -->
            <div style="margin-bottom:14px">${steps(data.fix_steps)}</div>

            <!-- Copy buttons -->
            ${fixScript ? `
            <div style="background:rgba(0,0,0,.3);border-radius:8px;border:1px solid rgba(255,255,255,.07);
              overflow:hidden;margin-top:4px">
              <div style="padding:8px 14px;background:rgba(0,0,0,.3);
                border-bottom:1px solid rgba(255,255,255,.06);
                display:flex;align-items:center;justify-content:space-between">
                <span style="font-size:10px;font-weight:700;color:#475569;font-family:monospace;
                  text-transform:uppercase;letter-spacing:.07em">📋 Fix Script (PowerShell / CMD)</span>
                <div style="display:flex;gap:6px">
                  <button id="lem-run-btn" onclick="_lemRunFix()" style="
                    padding:4px 12px;border-radius:5px;font-size:10px;font-weight:700;
                    background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.35);
                    color:#fca5a5;cursor:pointer;font-family:monospace;transition:all .15s
                  " onmouseover="this.style.background='rgba(239,68,68,.3)'"
                     onmouseout="this.style.background='rgba(239,68,68,.15)'"
                     title="Execute this script in PowerShell as Administrator on the server host">
                    ▶ Run Now
                  </button>
                  <button id="lem-copy-btn" onclick="_lemCopyFix()" style="
                    padding:4px 12px;border-radius:5px;font-size:10px;font-weight:700;
                    background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);
                    color:#60a5fa;cursor:pointer;font-family:monospace;transition:all .15s
                  " onmouseover="this.style.background='rgba(59,130,246,.3)'"
                     onmouseout="this.style.background='rgba(59,130,246,.15)'">
                    📋 Copy to Clipboard
                  </button>
                  <button onclick="_lemOpenTerminal()" style="
                    padding:4px 12px;border-radius:5px;font-size:10px;font-weight:700;
                    background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);
                    color:#4ade80;cursor:pointer;font-family:monospace;transition:all .15s
                  " onmouseover="this.style.background='rgba(34,197,94,.25)'"
                     onmouseout="this.style.background='rgba(34,197,94,.1)'">
                    💻 How to Run
                  </button>
                </div>
              </div>
              <pre id="lem-fix-code" style="margin:0;padding:12px 14px;font-family:monospace;
                font-size:11px;color:#7dd3fc;line-height:1.7;white-space:pre-wrap;
                word-break:break-all;background:transparent">${e(fixScript)}</pre>
            </div>` : ''}
          </div>

          <!-- Prevention + Related -->
          <div style="display:grid;grid-template-columns:${data.related_events && data.related_events.length ? '1fr 1fr' : '1fr'};gap:14px">
            <div style="background:rgba(167,139,250,.04);border:1px solid rgba(167,139,250,.15);
              border-radius:10px;padding:16px 18px">
              ${secHdr('🛡️','Prevention','#a78bfa')}
              <p style="font-size:13px;color:#c4b5fd;line-height:1.75;margin:0">
                ${e(data.prevention || '—')}
              </p>
            </div>
            ${data.related_events && data.related_events.length ? `
            <div style="background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);
              border-radius:10px;padding:16px 18px">
              ${secHdr('🔗','Related Event IDs','#94a3b8')}
              <div style="display:flex;flex-wrap:wrap;gap:7px">
                ${(Array.isArray(data.related_events) ? data.related_events : String(data.related_events).split(','))
                  .map(eid => eid.trim()).filter(Boolean).map(eid =>
                    `<span style="padding:4px 10px;border-radius:5px;
                      background:rgba(59,130,246,.12);color:#60a5fa;font-size:12px;
                      font-family:monospace;font-weight:700;border:1px solid rgba(59,130,246,.2)">${e(eid)}</span>`
                  ).join('')}
              </div>
            </div>` : ''}
          </div>

        </div>` : ''}

        <!-- ═══ ERROR STATE ═══ -->
        ${!loading && data && data.ok === false ? `
        <div style="padding:40px 24px;text-align:center">
          <div style="font-size:28px;margin-bottom:12px">⚠️</div>
          <div style="font-size:14px;color:#f87171;margin-bottom:8px">${e(data.error||'AI analysis failed')}</div>
          <div style="font-size:12px;color:#64748b">
            Add GROQ_API_KEY to your .env file and restart the app for full AI analysis.
          </div>
        </div>` : ''}

        <!-- ═══ FOOTER ═══ -->
        <div style="padding:12px 20px;border-top:1px solid rgba(255,255,255,.06);
          display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;
          background:rgba(0,0,0,.2);border-radius:0 0 14px 14px">
          <div style="font-size:10px;color:#334155;font-family:monospace">
            ${aiSrc === 'groq' ? `Groq · ${model || 'gemma2-9b-it'} (free tier · 14,400 req/day)`
            : aiSrc === 'perplexity' ? 'Perplexity · sonar (free tier)'
            : 'Built-in Knowledge Base — add GROQ_API_KEY for full AI analysis'}
          </div>
          <button onclick="logExplainClose()" style="
            background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);
            color:#94a3b8;padding:7px 20px;border-radius:7px;cursor:pointer;
            font-size:12px;font-weight:600
          ">Close</button>
        </div>
      </div>
    </div>
  `;

  // Scroll to fix section if requested
  if (scrollToFix && !loading) {
    setTimeout(() => {
      const fixEl = document.getElementById('lem-fix-section');
      if (fixEl) fixEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  }

  // Store fix script + context for copy / run
  window._lemCurrentFixScript = fixScript;
  window._lemCurrentEventId   = (data && data.event_id) || (log && log.event_id) || '';
  window._lemCurrentRuleId    = (data && data.rule_id)  || '';
}

function _lemCopyFix() {
  const script = window._lemCurrentFixScript || '';
  if (!script) return;
  navigator.clipboard.writeText(script).then(() => {
    const btn = document.getElementById('lem-copy-btn');
    if (btn) {
      btn.textContent = '✅ Copied!';
      btn.classList.add('copy-flash');
      setTimeout(() => { btn.textContent = '📋 Copy to Clipboard'; btn.classList.remove('copy-flash'); }, 2000);
    }
  }).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = script;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  });
}

/* ──────────────────────────────────────────────────────────────────────────
 * _lemRunFix — actually execute the PowerShell remediation script.
 *
 * Flow:
 *   1. Show the user the exact script that will run, ask for confirmation.
 *   2. POST to /api/threat/run-fix-script with {script, event_id, rule_id, confirmed:true}.
 *   3. Replace the fix-script panel with the live output (stdout / stderr).
 * ────────────────────────────────────────────────────────────────────────── */
async function _lemRunFix() {
  const script  = window._lemCurrentFixScript || '';
  const eventId = window._lemCurrentEventId   || '';
  const ruleId  = window._lemCurrentRuleId    || '';
  const btn     = document.getElementById('lem-run-btn');

  if (!script.trim()) {
    alert('Nothing to run — no fix script available for this event.');
    return;
  }

  // Refuse to run a script that's all comments (fix_steps fallback)
  const isAllComments = script.split('\n').every(function (l) {
    var t = l.trim(); return !t || t.startsWith('#');
  });
  if (isAllComments) {
    alert(
      'This fix script contains only descriptive comments, not runnable commands. ' +
      'Add a GROQ_API_KEY to your .env file so the AI can generate real PowerShell ' +
      'commands for this event.'
    );
    return;
  }

  // ── Custom themed confirmation modal (replaces the native confirm()
  //    so the dialog matches the app's dark UI instead of showing a
  //    plain "localhost:5000" browser popup).
  const confirmed = await _lemConfirmRunModal(script);
  if (!confirmed) return;

  // ── Visual feedback: live elapsed counter + the actual commands ──────
  //    Replaces the bare "⏳ Running…" so the user can see what's
  //    happening while sfc /scannow etc. takes 3-5 minutes.
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '⏳ Running…';
    btn.style.background = 'rgba(245,158,11,.2)';
  }
  const progressHandle = _lemShowRunProgress(script);

  try {
    const r = await fetch('/api/threat/run-fix-script', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        script:    script,
        event_id:  eventId,
        rule_id:   ruleId,
        confirmed: true,
      })
    });
    const d = await r.json().catch(function () {
      return { ok: false, error: 'Invalid JSON response (HTTP ' + r.status + ')' };
    });
    if (progressHandle) progressHandle.stop();
    _lemRenderRunResult(d);
  } catch (e) {
    if (progressHandle) progressHandle.stop();
    _lemRenderRunResult({ ok: false, error: 'Network error: ' + e.message });
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '▶ Run Again';
      btn.style.background = 'rgba(239,68,68,.15)';
    }
  }
}


/* ──────────────────────────────────────────────────────────────────────────
 * _lemConfirmRunModal — themed replacement for the native confirm() popup.
 *
 * Returns a Promise that resolves to `true` (OK) or `false` (Cancel).
 * Style mirrors the rest of the dark UI — no more "localhost:5000" popup.
 * ────────────────────────────────────────────────────────────────────────── */
function _lemConfirmRunModal(script) {
  return new Promise(function (resolve) {
    const esc = function (s) {
      return String(s).replace(/[&<>"']/g, function (c) {
        return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
      });
    };
    const lines    = script.split('\n');
    const preview  = lines.slice(0, 14).join('\n');
    const overflow = lines.length > 14 ? '\n… (+' + (lines.length - 14) + ' more line' +
                     (lines.length - 14 !== 1 ? 's' : '') + ')' : '';

    const overlay = document.createElement('div');
    overlay.className = 'lem-confirm-overlay';
    overlay.innerHTML =
      '<div class="lem-confirm-modal" role="dialog" aria-modal="true">' +
      '  <div class="lem-confirm-title">⚠️ Run Fix Script on the Server Host?</div>' +
      '  <div class="lem-confirm-sub">' +
      '    The following commands will execute in PowerShell on the host where ' +
      '    Secure Eye Trust+ is running. Review carefully before continuing.' +
      '  </div>' +
      '  <pre class="lem-confirm-code">' + esc(preview + overflow) + '</pre>' +
      '  <div class="lem-confirm-hint">' +
      '    💡 The server must be running as <strong>Administrator</strong> for ' +
      '    system-level commands (sfc, schtasks, services, registry) to take effect.' +
      '  </div>' +
      '  <div class="lem-confirm-row">' +
      '    <button class="lem-confirm-btn lem-confirm-btn--cancel" data-act="cancel" type="button">Cancel</button>' +
      '    <button class="lem-confirm-btn lem-confirm-btn--ok"     data-act="ok"     type="button">▶ Run Script</button>' +
      '  </div>' +
      '</div>';

    // One-time CSS injection (idempotent — only the first call paints)
    if (!document.getElementById('lem-confirm-css')) {
      const css = document.createElement('style');
      css.id = 'lem-confirm-css';
      css.textContent = [
        '.lem-confirm-overlay{position:fixed;inset:0;z-index:10002;',
        '  background:rgba(0,0,0,.7);backdrop-filter:blur(6px);',
        '  display:flex;align-items:center;justify-content:center;',
        '  animation:lem-confirm-fadein .15s ease both}',
        '@keyframes lem-confirm-fadein{from{opacity:0}to{opacity:1}}',
        '.lem-confirm-modal{background:#0d1626;border:1px solid rgba(255,255,255,.1);',
        '  border-radius:14px;max-width:680px;width:92%;padding:24px 26px;',
        '  box-shadow:0 24px 64px rgba(0,0,0,.6);color:#cbd5e1;font-family:inherit}',
        '.lem-confirm-title{font-size:17px;font-weight:800;color:#fff;margin-bottom:8px;letter-spacing:.01em}',
        '.lem-confirm-sub{font-size:13px;color:#94a3b8;line-height:1.6;margin-bottom:14px}',
        '.lem-confirm-code{background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.07);',
        '  border-radius:8px;padding:12px 14px;font-family:JetBrains Mono,Consolas,monospace;',
        '  font-size:11.5px;color:#7dd3fc;line-height:1.7;white-space:pre-wrap;',
        '  word-break:break-word;max-height:280px;overflow:auto;margin:0 0 14px}',
        '.lem-confirm-hint{font-size:12px;color:#94a3b8;line-height:1.6;margin-bottom:18px;',
        '  background:rgba(245,158,11,.05);border-left:3px solid rgba(245,158,11,.45);',
        '  padding:10px 14px;border-radius:6px}',
        '.lem-confirm-hint strong{color:#fbbf24}',
        '.lem-confirm-row{display:flex;gap:10px;justify-content:flex-end}',
        '.lem-confirm-btn{padding:10px 20px;border-radius:9px;font-size:13px;',
        '  font-weight:700;cursor:pointer;border:1px solid transparent;letter-spacing:.02em;',
        '  transition:background .12s ease, transform .12s ease}',
        '.lem-confirm-btn--cancel{background:rgba(255,255,255,.04);color:#cbd5e1;',
        '  border-color:rgba(255,255,255,.08)}',
        '.lem-confirm-btn--cancel:hover{background:rgba(255,255,255,.09)}',
        '.lem-confirm-btn--ok{background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);',
        '  color:#fff;border-color:#dc2626;box-shadow:0 4px 14px rgba(239,68,68,.35)}',
        '.lem-confirm-btn--ok:hover{transform:translateY(-1px);box-shadow:0 8px 22px rgba(239,68,68,.5)}',
        // ── live progress panel ─────────────────────────────────────────
        '.lem-run-progress{margin-top:14px;background:rgba(245,158,11,.05);',
        '  border:1px solid rgba(245,158,11,.25);border-radius:10px;padding:14px 16px}',
        '.lem-run-progress-head{display:flex;align-items:center;justify-content:space-between;',
        '  margin-bottom:10px;font-size:12px}',
        '.lem-run-progress-title{color:#fbbf24;font-weight:800;letter-spacing:.02em}',
        '.lem-run-progress-timer{color:#fde68a;font-family:JetBrains Mono,monospace;font-weight:700}',
        '.lem-run-progress-stage{color:#cbd5e1;font-size:11.5px;line-height:1.65;margin-top:6px}',
        '.lem-run-progress-cmds{margin-top:10px;background:rgba(0,0,0,.3);',
        '  border-radius:6px;padding:10px 12px;font-family:JetBrains Mono,monospace;',
        '  font-size:10.5px;color:#94a3b8;line-height:1.75;max-height:160px;overflow:auto}',
        '.lem-run-progress-cmd-active{color:#fbbf24;font-weight:700}',
        '.lem-run-progress-spinner{display:inline-block;animation:lem-spin 1.2s linear infinite}',
        '@keyframes lem-spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}',
      ].join('');
      document.head.appendChild(css);
    }
    document.body.appendChild(overlay);

    function finish(value) {
      overlay.remove();
      resolve(value);
    }
    overlay.querySelector('[data-act="cancel"]').addEventListener('click', function () { finish(false); });
    overlay.querySelector('[data-act="ok"]').addEventListener('click',     function () { finish(true);  });
    overlay.addEventListener('click', function (e) { if (e.target === overlay) finish(false); });
    document.addEventListener('keydown', function escListener(e) {
      if (e.key === 'Escape') { finish(false); document.removeEventListener('keydown', escListener); }
    });
  });
}


/* ──────────────────────────────────────────────────────────────────────────
 * _lemShowRunProgress — live progress panel while the script runs.
 *
 * Replaces the bare "⏳ Running…" text. Shows the commands queued, the
 * one currently executing (best-effort guess by elapsed time and command
 * weight), and a 0:00 stopwatch — so the user understands why sfc /scannow
 * is taking minutes instead of seconds.
 *
 * Returns { stop() } so the caller can tear it down on completion.
 * ────────────────────────────────────────────────────────────────────────── */
function _lemShowRunProgress(script) {
  const fixSection = document.getElementById('lem-fix-section');
  if (!fixSection) return null;

  // Remove a previous progress panel if one is hanging around
  const prev = document.getElementById('lem-run-progress');
  if (prev) prev.remove();

  // Heuristic "weights" — how long each kind of command typically takes.
  // Numbers are seconds at the high end; the active highlight advances
  // through the list using these as anchors. Pure cosmetic — the actual
  // call is one POST.
  const COMMAND_WEIGHTS = [
    { match: /sfc\s*\/scannow/i,           sec: 240, label: 'Scanning Windows system files (sfc /scannow) — this is the slow step' },
    { match: /DISM[^|]*RestoreHealth/i,    sec: 180, label: 'Running DISM /RestoreHealth — repairing the component store' },
    { match: /chkdsk/i,                    sec: 120, label: 'Running chkdsk on the volume' },
    { match: /Get-WinEvent/i,              sec:   3, label: 'Querying Windows event logs' },
    { match: /Get-Process|Get-Service/i,   sec:   1, label: 'Listing processes / services' },
    { match: /Get-ScheduledTask|schtasks/i,sec:   2, label: 'Inspecting scheduled tasks' },
    { match: /reg\s+(query|add|delete)/i,  sec:   1, label: 'Reading or writing the registry' },
    { match: /netstat|Get-NetTCPConn/i,    sec:   2, label: 'Inspecting open network connections' },
  ];
  const lines = script.split('\n').filter(function (l) {
    var t = l.trim(); return t && !t.startsWith('#');
  });

  // Build per-line weight + label
  const enriched = lines.map(function (l) {
    for (let i = 0; i < COMMAND_WEIGHTS.length; i++) {
      if (COMMAND_WEIGHTS[i].match.test(l)) {
        return { line: l, sec: COMMAND_WEIGHTS[i].sec, label: COMMAND_WEIGHTS[i].label };
      }
    }
    return { line: l, sec: 2, label: 'Running PowerShell command' };
  });
  const total = enriched.reduce(function (s, x) { return s + x.sec; }, 0);

  const esc = function (s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
    });
  };

  const panel = document.createElement('div');
  panel.id = 'lem-run-progress';
  panel.className = 'lem-run-progress';
  panel.innerHTML =
    '<div class="lem-run-progress-head">' +
    '  <span class="lem-run-progress-title"><span class="lem-run-progress-spinner">⏳</span> Running fix script on the server…</span>' +
    '  <span class="lem-run-progress-timer" id="lem-run-timer">0:00</span>' +
    '</div>' +
    '<div class="lem-run-progress-stage" id="lem-run-stage">Initializing…</div>' +
    '<div class="lem-run-progress-cmds" id="lem-run-cmds">' +
      enriched.map(function (e, i) {
        return '<div data-i="' + i + '">' + (i + 1) + '. ' + esc(e.line) + '</div>';
      }).join('') +
    '</div>';
  fixSection.appendChild(panel);

  const t0 = Date.now();
  const stage = panel.querySelector('#lem-run-stage');
  const timer = panel.querySelector('#lem-run-timer');
  const cmds  = panel.querySelector('#lem-run-cmds');

  const interval = setInterval(function () {
    const sec = Math.floor((Date.now() - t0) / 1000);
    const mm  = Math.floor(sec / 60);
    const ss  = String(sec % 60).padStart(2, '0');
    timer.textContent = mm + ':' + ss;

    // Which step is "currently active" given elapsed time?
    let acc = 0, active = enriched.length - 1;
    for (let i = 0; i < enriched.length; i++) {
      if (sec < acc + enriched[i].sec) { active = i; break; }
      acc += enriched[i].sec;
    }
    stage.textContent = enriched[active] ? enriched[active].label : 'Finalizing…';
    Array.prototype.forEach.call(cmds.children, function (c, idx) {
      c.className = idx === active ? 'lem-run-progress-cmd-active' : '';
    });
  }, 250);

  return {
    stop: function () {
      clearInterval(interval);
      const p = document.getElementById('lem-run-progress');
      if (p) p.remove();
    }
  };
}

function _lemRenderRunResult(d) {
  // Find the fix section and append a result panel below it
  const fixSection = document.getElementById('lem-fix-section');
  if (!fixSection) { alert(d.ok ? 'OK' : (d.error || 'Failed')); return; }

  // Remove any previous result panel so we don't stack them
  const prev = document.getElementById('lem-run-result');
  if (prev) prev.remove();

  const ok      = !!d.ok;
  const blocked = !!d.blocked;
  const stdout  = (d.stdout || '').trim();
  const stderr  = (d.stderr || '').trim();
  const message = d.message || (d.error || '');

  const colorBorder = blocked ? '#dc2626' : (ok ? '#16a34a' : '#dc2626');
  const colorBg     = blocked ? 'rgba(220,38,38,.06)' : (ok ? 'rgba(22,163,74,.06)' : 'rgba(220,38,38,.06)');
  const colorText   = blocked ? '#fca5a5' : (ok ? '#86efac' : '#fca5a5');
  const headerIcon  = blocked ? '🚫' : (ok ? '✅' : '⚠️');
  const headerText  = blocked ? 'Blocked — unsafe command' :
                      ok ? 'Fix script executed successfully' :
                      'Fix script failed';

  const esc = function (s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
    });
  };

  const html =
    '<div id="lem-run-result" style="margin-top:14px;background:' + colorBg +
       ';border:1px solid ' + colorBorder + '55;border-radius:10px;padding:14px 16px">' +
      '<div style="font-size:12px;font-weight:800;color:' + colorText +
        ';margin-bottom:8px;letter-spacing:.04em">' +
        headerIcon + '  ' + esc(headerText) +
        (typeof d.rc === 'number' ? ' (exit ' + d.rc + ')' : '') +
      '</div>' +
      (message ? '<div style="font-size:12px;color:#cbd5e1;margin-bottom:8px;line-height:1.6">' +
                   esc(message) + '</div>' : '') +
      (stdout ? '<div style="font-size:10px;color:#94a3b8;letter-spacing:.07em;font-family:monospace;margin:8px 0 4px">STDOUT</div>' +
                '<pre style="background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.06);' +
                  'border-radius:6px;padding:10px 12px;font-size:11.5px;color:#a3e8a3;' +
                  'line-height:1.55;white-space:pre-wrap;word-break:break-word;margin:0;max-height:240px;overflow:auto">' +
                  esc(stdout) + '</pre>' : '') +
      (stderr ? '<div style="font-size:10px;color:#94a3b8;letter-spacing:.07em;font-family:monospace;margin:8px 0 4px">STDERR</div>' +
                '<pre style="background:rgba(0,0,0,.4);border:1px solid rgba(220,38,38,.18);' +
                  'border-radius:6px;padding:10px 12px;font-size:11.5px;color:#fca5a5;' +
                  'line-height:1.55;white-space:pre-wrap;word-break:break-word;margin:0;max-height:240px;overflow:auto">' +
                  esc(stderr) + '</pre>' : '') +
      (!ok && !stderr && d.error ?
                '<div style="font-size:11.5px;color:#fca5a5;font-family:monospace;margin-top:6px">' +
                  esc(d.error) + '</div>' : '') +
    '</div>';

  fixSection.insertAdjacentHTML('beforeend', html);
  setTimeout(function () {
    var el = document.getElementById('lem-run-result');
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, 50);
}

function _lemOpenTerminal() {
  // Show a small tooltip explaining how to run
  const btn = event.target;
  const tip = document.createElement('div');
  tip.style.cssText = `
    position:fixed;z-index:99999;background:#1e293b;border:1px solid rgba(255,255,255,.15);
    border-radius:8px;padding:12px 16px;font-size:12px;color:#cbd5e1;
    max-width:320px;box-shadow:0 8px 32px rgba(0,0,0,.5);line-height:1.7
  `;
  tip.innerHTML = `
    <div style="font-weight:700;color:#60a5fa;margin-bottom:8px">💻 How to Run These Fix Steps</div>
    <div style="color:#94a3b8;font-size:11px">
      1. Copy the script above (📋 button)<br>
      2. Open <strong style="color:#e2e8f0">PowerShell as Administrator</strong><br>
         (Right-click Start → "Windows Terminal (Admin)")<br>
      3. Paste and press Enter<br><br>
      <em style="color:#475569">Or open Event Viewer (eventvwr.msc) and follow the manual steps.</em>
    </div>
    <button onclick="this.parentElement.remove()" style="
      margin-top:10px;padding:4px 12px;border-radius:5px;
      background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);
      color:#60a5fa;cursor:pointer;font-size:11px;width:100%">Got it</button>
  `;
  const rect = btn.getBoundingClientRect();
  tip.style.top  = (rect.bottom + 8) + 'px';
  tip.style.right = (window.innerWidth - rect.right) + 'px';
  document.body.appendChild(tip);
  setTimeout(() => tip.remove(), 8000);
}

function logExplainClose() {
  const modal = document.getElementById('log-explain-modal');
  if (modal) modal.remove();
}

// Close on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') logExplainClose();
});

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// Expose for realtime.js notification click
window.logExplainOpen  = logExplainOpen;
window.logExplainClose = logExplainClose;
