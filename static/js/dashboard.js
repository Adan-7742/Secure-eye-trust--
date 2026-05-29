/**
 * static/js/dashboard.js
 * =======================
 * Dashboard page — stat cards + charts
 *
 * DATA FLOW:
 *   GET /api/stats         → stat cards (total/errors/warnings per category)
 *   GET /api/analyze/timeline → line chart (daily log volume over 60 days)
 *   Chart.js renders two charts: category pie + timeline line
 */

let catChartInst, timelineChartInst;
let _dashboardFIMEvents = [];
let _dashboardFIMFilter = 'ALL';

async function loadDashboard() {
  // Fetch stats — always show something even on error
  let stats = {};
  try {
    stats = await api('/api/stats');
  } catch(e) {
    console.error('Stats load error:', e);
    // Show zeros so cards never stay "—"
    stats = {
      application:    {total:0, errors:0, warnings:0},
      system:         {total:0, errors:0, warnings:0},
      security:       {total:0, errors:0, warnings:0},
      windows_update: {total:0, errors:0, warnings:0},
    };
  }
  renderStatCards(stats);
  renderNavBadges(stats);
  renderCategoryChart(stats);

  // Timeline is optional — don't let it block stats
  try {
    const timeline = await api('/api/analyze/timeline');
    renderTimelineChart(timeline);
  } catch(e) {
    console.warn('Timeline load error:', e);
  }

  // Load File Integrity Monitoring summary for dashboard
  try {
    await loadFIMDashboard();
  } catch(e) {
    console.warn('FIM load error:', e);
  }
}

function renderStatCards(stats) {
  const map = {
    application:    { id: 'stat-app', errId: 'errs-app', rateId: 'rate-app' },
    system:         { id: 'stat-sys', errId: 'errs-sys', rateId: 'rate-sys' },
    security:       { id: 'stat-sec', errId: 'errs-sec', rateId: 'rate-sec' },
    windows_update: { id: 'stat-upd', errId: 'errs-upd', rateId: 'rate-upd' },
  };
  for (const [cat, ids] of Object.entries(map)) {
    const d = stats[cat] || {};
    const rate = d.total ? ((d.errors / d.total) * 100).toFixed(1) : '0.0';
    _setSysText(ids.id,     fmt(d.total   ?? 0));
    _setSysText(ids.errId,  `${fmt(d.errors ?? 0)} errors`);
    _setSysText(ids.rateId, `${rate}% err`);
  }
}

function renderNavBadges(stats) {
  for (const [cat, data] of Object.entries(stats)) {
    const el = document.getElementById(`badge-${cat}`);
    if (!el) continue;
    el.textContent = fmt(data.total);
    if (data.errors > 0) el.classList.add('error');
    else el.classList.remove('error');
  }
}

function renderCategoryChart(stats) {
  const ctx = document.getElementById('category-chart');
  if (!ctx) return;
  if (catChartInst) catChartInst.destroy();
  const colors = ['#38bdf8','#f59e0b','#ef4444','#10b981'];
  const labels = ['Application','System','Security','Win Update'];
  const data   = [
    stats.application?.total    || 0,
    stats.system?.total         || 0,
    stats.security?.total       || 0,
    stats.windows_update?.total || 0,
  ];
  catChartInst = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      plugins: { legend: { labels: { color: '#c8d8f0', font: { size: 11 } } } },
      cutout: '68%',
    }
  });
}

function renderTimelineChart(timeline) {
  const ctx = document.getElementById('timeline-chart');
  if (!ctx) return;
  if (timelineChartInst) timelineChartInst.destroy();

  // Collect all dates
  const dateSet = new Set();
  for (const cat of ['application','system','security','windows_update']) {
    (timeline[cat] || []).forEach(d => dateSet.add(d.date));
  }
  const dates = [...dateSet].sort().slice(-30);

  const makeData = (cat, color) => ({
    label: cat,
    data:  dates.map(d => {
      const found = (timeline[cat] || []).find(x => x.date === d);
      return found ? found.count : 0;
    }),
    borderColor: color, backgroundColor: color + '22',
    borderWidth: 2, pointRadius: 2, fill: false, tension: 0.3,
  });

  timelineChartInst = new Chart(ctx, {
    type: 'line',
    data: {
      labels: dates,
      datasets: [
        makeData('application',    '#38bdf8'),
        makeData('system',         '#f59e0b'),
        makeData('security',       '#ef4444'),
        makeData('windows_update', '#10b981'),
      ]
    },
    options: {
      plugins: { legend: { labels: { color: '#c8d8f0', font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: '#4a6080', maxTicksLimit: 10 }, grid: { color: '#1a2540' } },
        y: { ticks: { color: '#4a6080' }, grid: { color: '#1a2540' } },
      },
    }
  });
}

async function loadFIMDashboard() {
  const elTotal = document.getElementById('pa-fim-total');
  if (!elTotal) return;

  try {
    const res = await fetch('/api/fim-events');
    if (!res.ok) throw new Error('FIM API request failed');
    const data = await res.json();
    const fim = (data && data.fim) ? data.fim : {};
    _dashboardFIMEvents = fim.events || [];
    renderFIMSummary(fim);
  } catch (err) {
    console.warn('FIM API failed:', err);
    _dashboardFIMEvents = [];
    renderFIMSummary({});
  }
}

function dashboardFIMSetFilter(filter) {
  _dashboardFIMFilter = filter;
  const allBtn = document.getElementById('pa-fim-filter-all');
  const changedBtn = document.getElementById('pa-fim-filter-changed');
  if (allBtn) allBtn.style.background = filter === 'ALL' ? 'rgba(56,189,248,.12)' : 'rgba(255,255,255,.04)';
  if (changedBtn) changedBtn.style.background = filter === 'CHANGED' ? 'rgba(248,113,113,.12)' : 'rgba(255,255,255,.04)';
  renderFIMTable(_dashboardFIMEvents);
}

function renderFIMSummary(fim) {
  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };

  setText('pa-fim-total',   (fim.total   || 0).toLocaleString());
  setText('pa-fim-crit',    (fim.critical || 0).toLocaleString());
  setText('pa-fim-high',    (fim.high    || 0).toLocaleString());
  setText('pa-fim-actions', Object.keys(fim.by_action || {}).length.toLocaleString());

  _dashboardFIMEvents = fim.events || [];
  renderFIMDescription(fim);
  dashboardFIMSetFilter(_dashboardFIMFilter);
}

function renderFIMDescription(fim) {
  const descEl = document.getElementById('pa-fim-ai-desc');
  if (!descEl) return;

  const CHANGED_ACTIONS = new Set(['DELETE','MODIFIED','WRITE','WRITE/MODIFIED','EXECUTE','APPEND']);
  const events = fim.events || [];
  const changed = events.filter(e => CHANGED_ACTIONS.has(String(e.action || '').toUpperCase()));
  const critical = events.filter(e => e.critical);
  const topFiles = (fim.top_files || []).slice(0,3).map(f => `${f.file} (${f.count})`).join(', ');
  const fileList = topFiles ? `Most active files: ${topFiles}.` : '';

  if (!events.length) {
    descEl.textContent = 'No file integrity events were found. Enable Windows Object Access auditing and rerun analysis to capture changes. If you need to troubleshoot, check Local Security Policy > Advanced Audit Policy Configuration > Object Access.';
    return;
  }

  descEl.textContent = `${changed.length} changed file event${changed.length !== 1 ? 's' : ''} detected${critical.length ? `, including ${critical.length} critical item${critical.length !== 1 ? 's' : ''}` : ''}. ${fileList} Use the table rows to inspect individual file paths, actions, and users. To verify suspicious files, review the full path, compare hashes with Get-FileHash, and confirm auditing is enabled on the file system.`;
}

function renderFIMTable(events) {
  const tbody = document.getElementById('pa-fim-tbody');
  if (!tbody) return;

  const CHANGED_ACTIONS = new Set(['DELETE','MODIFIED','WRITE','WRITE/MODIFIED','EXECUTE','APPEND']);
  const displayEvents = _dashboardFIMFilter === 'CHANGED'
    ? events.filter(e => CHANGED_ACTIONS.has(String(e.action || '').toUpperCase()))
    : events.slice();

  if (!displayEvents.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="padding:20px;text-align:center;color:var(--text-dim);font-size:12px">' +
      'No matching file integrity events in this view.<br>' +
      '<span style="font-size:11px">Switch to All Events or rerun analysis to refresh.</span>' +
      '</td></tr>';
    return;
  }

  const SCOL = {CRITICAL:'#f87171', HIGH:'#fb923c', MEDIUM:'#fbbf24', LOW:'#4ade80'};
  const ACOL = {DELETE:'#f87171', MODIFIED:'#fb923c', WRITE:'#fb923c', EXECUTE:'#a78bfa', READ:'#4ade80', ACCESS:'#4da6ff'};

  tbody.innerHTML = displayEvents.map((ev, idx) => {
    const sc = SCOL[ev.severity] || '#94a3b8';
    const ac = ACOL[ev.action] || '#94a3b8';
    const critRow = ev.critical ? 'background:rgba(248,113,113,.04);' : '';
    const critMark = ev.critical ? '<span style="color:#f87171;font-size:9px;margin-left:4px">■</span>' : '';
    return '<tr onclick="dashboardFIMToggleRow(' + idx + ')" style="cursor:pointer;' + critRow + 'border-bottom:1px solid var(--border)">' +
      '<td style="padding:9px 14px;font-family:var(--mono);font-size:11px;color:var(--text-bright);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
        (ev.file || '—') + critMark + '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-dim)">' + (ev.host || 'LOCAL') + '</td>' +
      '<td style="padding:9px 14px">' +
        '<span style="background:' + ac + '18;color:' + ac + ';border:1px solid ' + ac + '44;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">' +
        (ev.action || 'ACCESS') + '</span>' +
      '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-muted);font-family:var(--mono)">' + (ev.user || 'UNKNOWN') + '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-dim);font-family:var(--mono)">' + ((ev.timestamp||'').substring(11,19) || '—') + '</td>' +
      '<td style="padding:9px 14px">' +
        '<span style="color:' + sc + ';font-size:10px;font-weight:700">' + (ev.severity || 'LOW') + '</span>' +
      '</td>' +
    '</tr>' +
    '<tr id="pa-fim-detail-' + idx + '" style="display:none;background:rgba(255,255,255,.03)">' +
      '<td colspan="6" style="padding:10px 14px;font-size:11px;color:var(--text-dim);line-height:1.5;border-bottom:1px solid var(--border)">' +
        '<strong>Path:</strong> ' + (ev.full_path || 'N/A') + '<br>' +
        '<strong>Message:</strong> ' + ((ev.message || 'No message').replace(/</g, '&lt;').replace(/>/g, '&gt;')) + '<br>' +
        '<strong>Source:</strong> ' + (ev.source || 'UNKNOWN') +
      '</td>' +
    '</tr>';
  }).join('');
}

function dashboardFIMToggleRow(idx) {
  const row = document.getElementById('pa-fim-detail-' + idx);
  if (!row) return;
  row.style.display = row.style.display === 'table-row' ? 'none' : 'table-row';
}

// ── helpers ──────────────────────────────────────────────────────────────────
function _setSysText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}




/* ═══ REAL SYSTEM STATS — dark cards, animated, live polling ═══ */
let _sysTimer = null;
let _prevCpuPct = 0;

async function loadSystemStats() {
  try {
    const res = await fetch('/api/system-stats');
    if (!res.ok) {
      console.warn('system-stats HTTP', res.status);
      _showStatsError();
      return;
    }
    const s = await res.json();
    if (s.error) {
      console.warn('system-stats error:', s.error);
      // Show specific message if psutil missing
      if (s.error.includes('psutil')) {
        ['cpu-value','mem-value','disk-value'].forEach(id => _setEl(id, 'N/A'));
        _setEl('sys-uptime', 'pip install psutil');
      } else {
        _showStatsError();
      }
      return;
    }
    _renderSysStats(s);
  } catch(e) {
    console.warn('loadSystemStats failed:', e.message);
    _showStatsError();
  }
}

function _showStatsError() {
  ['cpu-value','mem-value','disk-value','sys-uptime'].forEach(id => _setEl(id, 'N/A'));
  ['cpu-bar','mem-bar','disk-bar'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.width = '0%';
  });
}

function _renderSysStats(s) {
  const cpu = s.cpu || {};
  const mem = s.memory || {};
  const dsk = s.disk || {};
  const net = s.network || {};

  /* CPU */
  _animateNum('cpu-value', _prevCpuPct, cpu.percent || 0, '%', 700);
  _prevCpuPct = cpu.percent || 0;
  _setBar('cpu-bar', 'cpu', cpu.percent || 0);
  _setBadge('cpu-status-badge', cpu.status || 'Normal');

  /* Memory */
  _setEl('mem-value',  (mem.percent || 0) + '%');
  _setBar('mem-bar', 'memory', mem.percent || 0);
  _setBadge('mem-status-badge', mem.status || 'Normal');
  _setEl('mem-avail', (mem.avail_gb || '—') + ' GB');
  _setEl('mem-total', (mem.total_gb || '—') + ' GB');

  /* Disk */
  _setEl('disk-value', (dsk.percent || 0) + '%');
  _setBar('disk-bar', 'disk', dsk.percent || 0);
  _setBadge('disk-status-badge', dsk.status || 'Normal');
  _setEl('disk-free',  (dsk.free_gb  || '—') + ' GB');
  _setEl('disk-total', (dsk.total_gb || '—') + ' GB');

  /* System Info */
  _setEl('sys-uptime',   s.uptime   || '—');
  _setEl('sys-hostname', s.platform || '—');
  _setEl('sys-net-recv', (net.bytes_recv_mb || 0) + ' MB');
  _setEl('sys-net-sent', (net.bytes_sent_mb || 0) + ' MB');

  /* Critical alerts */
  // Threshold alerts handled by /api/live-alerts — no duplicates here
}

/* Smooth count-up animation */
function _animateNum(id, from, to, suffix, dur) {
  const el = document.getElementById(id);
  if (!el) return;
  const t0 = performance.now();
  const d  = to - from;
  (function step(now) {
    const t = Math.min(1, (now - t0) / dur);
    const e = t < .5 ? 2*t*t : -1+(4-2*t)*t;
    el.textContent = (from + d * e).toFixed(1) + suffix;
    if (t < 1) requestAnimationFrame(step);
  })(t0);
}

function _setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function _setBar(id, type, pct) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = Math.min(100, Math.max(0, pct)) + '%';
  el.className = 'sys-bar-fill ' + type;
  if (pct > 90)      el.classList.add('critical');
  else if (pct > 70) el.classList.add('high');
}

function _setBadge(id, status) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = status;
  el.className = 'sys-status-badge';
  if (status === 'Critical')  el.classList.add('status-critical');
  else if (status === 'High') el.classList.add('status-high');
  else                        el.classList.add('status-normal');
}

/* Live polling — starts when dashboard opens, stops when leaving */
function startSysPolling() {
  if (_sysTimer) return;
  loadSystemStats(); // immediate first call
  _sysTimer = setInterval(loadSystemStats, 4000);
}

function stopSysPolling() {
  if (_sysTimer) { clearInterval(_sysTimer); _sysTimer = null; }
}

/* Hook into loadDashboard */
const _origLoadDashboard = typeof loadDashboard === 'function' ? loadDashboard : null;
loadDashboard = async function() {
  if (_origLoadDashboard) await _origLoadDashboard();
  startSysPolling();
};
