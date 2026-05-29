/**
 * static/js/sysmon_dashboard.js
 * ==============================
 * Sysmon v2 Dashboard Widgets — Secure Eye Trust+
 *
 * Five self-contained widgets, each polling their own API endpoint.
 * All widgets degrade gracefully when Sysmon is not installed.
 *
 * WIDGETS:
 *   1. Suspicious Downloads   → /api/sysmon/file-drops
 *   2. Process Tree           → /api/sysmon/processes  (Office→shell focus)
 *   3. Registry Changes       → /api/sysmon/registry
 *   4. Sigma Hits             → /api/sysmon/stats  (office_shell_spawns count)
 *   5. Risk Timeline          → /api/sysmon/stats  + existing risk data
 *
 * USAGE — add to index.html (before closing </body>):
 *   <script src="/static/js/sysmon_dashboard.js"></script>
 *
 * Then call  initSysmonWidgets()  after the page loads:
 *   document.addEventListener('DOMContentLoaded', initSysmonWidgets);
 *
 * HTML PLACEHOLDERS — add these divs anywhere in index.html:
 *   <div id="sysmon-file-drops"></div>
 *   <div id="sysmon-process-tree"></div>
 *   <div id="sysmon-registry"></div>
 *   <div id="sysmon-sigma-hits"></div>
 *   <div id="sysmon-risk-timeline"></div>
 *   <div id="sysmon-stats-bar"></div>
 *
 * REFRESH:   Each widget auto-refreshes every 15 seconds.
 * THEMING:   Reads CSS variables from the existing LogVault stylesheet.
 */

'use strict';

// ── Config ────────────────────────────────────────────────────────────────────

const SYSMON_REFRESH_MS  = 15_000;   // 15 s auto-refresh
const SYSMON_MAX_ROWS    = 20;       // rows per widget table

// ── Utility helpers ───────────────────────────────────────────────────────────

/**
 * Thin fetch wrapper — matches the existing api() pattern in api.js
 * but is self-contained so this file has no dependency on api.js.
 */
async function _sysmonFetch(url) {
  const resp = await fetch(url, {
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    credentials: 'same-origin',
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} — ${url}`);
  return resp.json();
}

/** Set element text safely; no-op if element missing. */
function _setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text ?? '—';
}

/** Set element innerHTML safely; no-op if element missing. */
function _setHTML(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

/** Format a timestamp string to HH:MM:SS DD/MM. */
function _fmtTs(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts.replace(' ', 'T'));
    const hms = d.toTimeString().slice(0, 8);
    const dmy = `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}`;
    return `${hms} ${dmy}`;
  } catch { return ts.slice(0, 16); }
}

/** Truncate a string to maxLen chars, appending '…' if cut. */
function _trunc(str, maxLen) {
  if (!str) return '—';
  return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
}

/** Return a severity badge HTML span. */
function _badge(label, cls) {
  return `<span class="sysmon-badge sysmon-badge--${cls}">${label}</span>`;
}

/** Basename of a Windows path. */
function _basename(path) {
  if (!path) return '—';
  return path.split('\\').pop() || path;
}

/** Return true if IP is external (non-RFC1918). */
function _isExternalIp(ip) {
  if (!ip) return false;
  return !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1)/.test(ip);
}

// ── Shared "Sysmon not installed" banner ──────────────────────────────────────

function _notInstalledBanner() {
  return `
    <div class="sysmon-notice">
      <strong>⚠ Sysmon not detected.</strong>
      Install Sysmon to enable process, file, network and registry monitoring.<br>
      <code>sysmon64.exe -accepteula -i</code>
      &nbsp;·&nbsp;
      <a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
         target="_blank" rel="noreferrer">Download Sysmon</a>
    </div>`;
}

// ── Widget 1: Suspicious Downloads ────────────────────────────────────────────

async function loadSysmonFileDrops() {
  const containerId = 'sysmon-file-drops';
  const container   = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = '<div class="sysmon-loading">Loading suspicious downloads…</div>';

  try {
    const data = await _sysmonFetch('/api/sysmon/file-drops?limit=20&hours=24');

    if (!data.sysmon_installed) {
      container.innerHTML = _notInstalledBanner();
      return;
    }

    const drops = data.file_drops || [];

    if (drops.length === 0) {
      container.innerHTML = `
        <div class="sysmon-empty">
          ✅ No suspicious file drops in the last 24 hours.
        </div>`;
      return;
    }

    const rows = drops.slice(0, SYSMON_MAX_ROWS).map(d => {
      const suspClass = d.suspicious ? 'sysmon-row--danger' : '';
      const fname     = _trunc(_basename(d.target_filename), 38);
      const dirPart   = _trunc((d.target_filename || '').rsplit
        ? (d.target_filename || '').replace(/\\[^\\]+$/, '') : '…', 38);
      const ts        = _fmtTs(d.timestamp);
      const suspBadge = d.suspicious
        ? _badge('SUSPICIOUS', 'danger')
        : _badge('MONITOR', 'warn');
      return `
        <tr class="${suspClass}">
          <td title="${d.target_filename || ''}">${fname}</td>
          <td class="sysmon-dim" title="${d.target_filename || ''}">${
            _trunc((d.target_filename || '').replace(/\\[^\\]+$/, ''), 32)
          }</td>
          <td>${suspBadge}</td>
          <td class="sysmon-ts">${ts}</td>
        </tr>`;
    }).join('');

    container.innerHTML = `
      <div class="sysmon-widget-header">
        <span class="sysmon-widget-title">🔽 Suspicious Downloads</span>
        <span class="sysmon-count">${drops.length} file${drops.length !== 1 ? 's' : ''}</span>
      </div>
      <table class="sysmon-table">
        <thead>
          <tr>
            <th>Filename</th><th>Directory</th><th>Status</th><th>Time</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch (err) {
    container.innerHTML = `<div class="sysmon-error">File drops error: ${err.message}</div>`;
  }
}

// ── Widget 2: Process Tree (Office → Shell focus) ─────────────────────────────

async function loadSysmonProcessTree() {
  const containerId = 'sysmon-process-tree';
  const container   = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = '<div class="sysmon-loading">Loading process activity…</div>';

  try {
    // Fetch recent process creates; focus on suspicious parent-child chains
    const data = await _sysmonFetch('/api/sysmon/processes?limit=30&hours=24&suspicious=false');

    if (!data.sysmon_installed) {
      container.innerHTML = _notInstalledBanner();
      return;
    }

    const procs = data.processes || [];

    if (procs.length === 0) {
      container.innerHTML = `
        <div class="sysmon-empty">
          ✅ No process creation events in the last 24 hours.
        </div>`;
      return;
    }

    const rows = procs.slice(0, SYSMON_MAX_ROWS).map(p => {
      const rowCls    = p.suspicious ? 'sysmon-row--danger' : '';
      const image     = _trunc(_basename(p.command_line || ''), 30);
      const parent    = _trunc(_basename(p.parent_image || ''), 22);
      const cmd       = _trunc(p.command_line || '', 42);
      const ts        = _fmtTs(p.timestamp);
      const badge     = p.suspicious
        ? _badge('⚠ MACRO?', 'danger')
        : _badge('OK', 'ok');
      return `
        <tr class="${rowCls}" title="${p.command_line || ''}">
          <td class="sysmon-mono">${parent}</td>
          <td class="sysmon-mono">${image}</td>
          <td class="sysmon-dim sysmon-cmd">${cmd}</td>
          <td>${badge}</td>
          <td class="sysmon-ts">${ts}</td>
        </tr>`;
    }).join('');

    const suspiciousCount = procs.filter(p => p.suspicious).length;
    const headerClass     = suspiciousCount > 0 ? 'sysmon-widget-header--alert' : '';

    container.innerHTML = `
      <div class="sysmon-widget-header ${headerClass}">
        <span class="sysmon-widget-title">🌲 Process Tree</span>
        <span class="sysmon-count">
          ${suspiciousCount > 0
            ? `<span class="sysmon-danger-count">⚠ ${suspiciousCount} suspicious</span> / `
            : ''}
          ${procs.length} total
        </span>
      </div>
      <table class="sysmon-table">
        <thead>
          <tr>
            <th>Parent</th><th>Image</th><th>CommandLine</th>
            <th>Status</th><th>Time</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch (err) {
    container.innerHTML = `<div class="sysmon-error">Process tree error: ${err.message}</div>`;
  }
}

// ── Widget 3: Registry Changes ────────────────────────────────────────────────

async function loadSysmonRegistry() {
  const containerId = 'sysmon-registry';
  const container   = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = '<div class="sysmon-loading">Loading registry changes…</div>';

  try {
    const data = await _sysmonFetch('/api/sysmon/registry?limit=20&hours=24');

    if (!data.sysmon_installed) {
      container.innerHTML = _notInstalledBanner();
      return;
    }

    const changes = data.registry_changes || [];

    if (changes.length === 0) {
      container.innerHTML = `
        <div class="sysmon-empty">
          ✅ No registry persistence changes in the last 24 hours.
        </div>`;
      return;
    }

    const rows = changes.slice(0, SYSMON_MAX_ROWS).map(r => {
      const rowCls  = r.is_persistence_key ? 'sysmon-row--danger' : '';
      const key     = _trunc(r.target_object || '', 50);
      const ts      = _fmtTs(r.timestamp);
      const badge   = r.is_persistence_key
        ? _badge('PERSIST', 'danger')
        : _badge('REGISTRY', 'info');
      return `
        <tr class="${rowCls}" title="${r.target_object || ''}">
          <td class="sysmon-mono sysmon-regkey">${key}</td>
          <td>${badge}</td>
          <td class="sysmon-ts">${ts}</td>
        </tr>`;
    }).join('');

    const persistCount = changes.filter(r => r.is_persistence_key).length;

    container.innerHTML = `
      <div class="sysmon-widget-header ${persistCount > 0 ? 'sysmon-widget-header--alert' : ''}">
        <span class="sysmon-widget-title">🔑 Registry Changes</span>
        <span class="sysmon-count">
          ${persistCount > 0
            ? `<span class="sysmon-danger-count">⚠ ${persistCount} persistence keys</span> / `
            : ''}
          ${changes.length} total
        </span>
      </div>
      <table class="sysmon-table">
        <thead>
          <tr><th>Registry Key</th><th>Type</th><th>Time</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch (err) {
    container.innerHTML = `<div class="sysmon-error">Registry error: ${err.message}</div>`;
  }
}

// ── Widget 4: Sigma Hits (correlator chain hit counter) ───────────────────────

async function loadSysmonSigmaHits() {
  const containerId = 'sysmon-sigma-hits';
  const container   = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = '<div class="sysmon-loading">Loading Sigma hits…</div>';

  try {
    const stats = await _sysmonFetch('/api/sysmon/stats');

    if (!stats.sysmon_installed) {
      container.innerHTML = _notInstalledBanner();
      return;
    }

    // Sigma "hits" mapped from stats counters
    const hits = [
      {
        label:   'Office → Shell Spawns',
        count:   stats.office_shell_spawns ?? 0,
        rule:    'SUSPICIOUS_PARENT_CHAIN',
        mitre:   'T1566.001',
        severity: (stats.office_shell_spawns ?? 0) > 0 ? 'CRITICAL' : 'OK',
      },
      {
        label:   'Suspicious File Drops',
        count:   stats.suspicious_file_drops ?? 0,
        rule:    'UNSIGNED_EXECUTABLE',
        mitre:   'T1204.002',
        severity: (stats.suspicious_file_drops ?? 0) > 0 ? 'HIGH' : 'OK',
      },
      {
        label:   'Registry Persistence Keys',
        count:   stats.persistence_registry_hits ?? 0,
        rule:    'REGISTRY_PERSISTENCE',
        mitre:   'T1547.001',
        severity: (stats.persistence_registry_hits ?? 0) > 0 ? 'HIGH' : 'OK',
      },
    ];

    const totalHits = hits.reduce((s, h) => s + h.count, 0);

    const rows = hits.map(h => {
      const cls   = h.severity === 'CRITICAL' ? 'danger'
                  : h.severity === 'HIGH'     ? 'warn'
                  :                             'ok';
      const badge = h.count > 0
        ? _badge(h.severity, cls)
        : _badge('CLEAR', 'ok');
      return `
        <tr>
          <td>${h.label}</td>
          <td class="sysmon-mono sysmon-dim">${h.rule}</td>
          <td class="sysmon-mono sysmon-dim">${h.mitre}</td>
          <td class="sysmon-count-cell">${h.count}</td>
          <td>${badge}</td>
        </tr>`;
    }).join('');

    const headerCls = totalHits > 0 ? 'sysmon-widget-header--alert' : '';

    container.innerHTML = `
      <div class="sysmon-widget-header ${headerCls}">
        <span class="sysmon-widget-title">🎯 Sigma / Detection Hits</span>
        <span class="sysmon-count">
          ${totalHits > 0
            ? `<span class="sysmon-danger-count">⚠ ${totalHits} total hits</span>`
            : '✅ No hits'}
          &nbsp;·&nbsp; last 24h
        </span>
      </div>
      <table class="sysmon-table">
        <thead>
          <tr>
            <th>Detection Rule</th>
            <th>Rule ID</th>
            <th>MITRE</th>
            <th>Count</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch (err) {
    container.innerHTML = `<div class="sysmon-error">Sigma hits error: ${err.message}</div>`;
  }
}

// ── Widget 5: Risk Timeline (Sysmon event volume over time) ───────────────────

async function loadSysmonRiskTimeline() {
  const containerId = 'sysmon-risk-timeline';
  const container   = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = '<div class="sysmon-loading">Loading risk timeline…</div>';

  try {
    const stats = await _sysmonFetch('/api/sysmon/stats');

    if (!stats.sysmon_installed) {
      container.innerHTML = _notInstalledBanner();
      return;
    }

    // Build a mini bar chart from the stats counts (last 24h totals)
    const metrics = [
      { label: 'Process Creates',    value: stats.process_creates    ?? 0, color: '#4e9af1', eid: 1  },
      { label: 'Network Connections',value: stats.network_connections ?? 0, color: '#e67e22', eid: 3  },
      { label: 'File Creates',       value: stats.file_creates        ?? 0, color: '#27ae60', eid: 11 },
      { label: 'Registry Sets',      value: stats.registry_sets       ?? 0, color: '#e74c3c', eid: 13 },
      { label: 'DNS Queries',        value: stats.dns_queries          ?? 0, color: '#9b59b6', eid: 22 },
    ];

    const maxVal = Math.max(...metrics.map(m => m.value), 1);
    const lastEvent = stats.latest_event ? _fmtTs(stats.latest_event) : 'None';

    const bars = metrics.map(m => {
      const pct = Math.round((m.value / maxVal) * 100);
      return `
        <div class="sysmon-bar-row">
          <div class="sysmon-bar-label">
            EID&nbsp;${m.eid}&nbsp;·&nbsp;${m.label}
          </div>
          <div class="sysmon-bar-track">
            <div class="sysmon-bar-fill"
                 style="width:${pct}%;background:${m.color};"
                 title="${m.value} events"></div>
          </div>
          <div class="sysmon-bar-count">${m.value.toLocaleString()}</div>
        </div>`;
    }).join('');

    container.innerHTML = `
      <div class="sysmon-widget-header">
        <span class="sysmon-widget-title">📊 Risk Timeline (24h)</span>
        <span class="sysmon-count">
          ${stats.total_24h ?? 0} total events
          &nbsp;·&nbsp; latest: ${lastEvent}
        </span>
      </div>
      <div class="sysmon-bar-chart">${bars}</div>`;

  } catch (err) {
    container.innerHTML = `<div class="sysmon-error">Timeline error: ${err.message}</div>`;
  }
}

// ── Widget 6: Compact stats bar (header strip) ────────────────────────────────

async function loadSysmonStatsBar() {
  const containerId = 'sysmon-stats-bar';
  const container   = document.getElementById(containerId);
  if (!container) return;

  try {
    const stats = await _sysmonFetch('/api/sysmon/stats');

    if (!stats.sysmon_installed) {
      container.innerHTML = `<span class="sysmon-stats-chip sysmon-stats-chip--warn">
        ⚠ Sysmon not installed
      </span>`;
      return;
    }

    const chips = [
      { label: 'Proc',    val: stats.process_creates    ?? 0, icon: '⚙',  danger: false },
      { label: 'Net',     val: stats.network_connections ?? 0, icon: '🌐', danger: false },
      { label: 'Files',   val: stats.suspicious_file_drops ?? 0, icon: '📁', danger: (stats.suspicious_file_drops ?? 0) > 0 },
      { label: 'Reg',     val: stats.persistence_registry_hits ?? 0, icon: '🔑', danger: (stats.persistence_registry_hits ?? 0) > 0 },
      { label: 'Macros?', val: stats.office_shell_spawns ?? 0, icon: '⚠', danger: (stats.office_shell_spawns ?? 0) > 0 },
    ].map(c => {
      const cls = c.danger ? 'sysmon-stats-chip--danger' : 'sysmon-stats-chip--normal';
      return `<span class="sysmon-stats-chip ${cls}">${c.icon} ${c.val} ${c.label}</span>`;
    }).join('');

    container.innerHTML = chips;

  } catch (err) {
    container.innerHTML = `<span class="sysmon-stats-chip sysmon-stats-chip--warn">Sysmon err</span>`;
  }
}

// ── Auto-refresh manager ──────────────────────────────────────────────────────

const _sysmonTimers = [];

function _schedule(fn) {
  fn();  // run immediately
  const id = setInterval(fn, SYSMON_REFRESH_MS);
  _sysmonTimers.push(id);
}

function stopSysmonWidgets() {
  _sysmonTimers.forEach(id => clearInterval(id));
  _sysmonTimers.length = 0;
}

// ── Public entry point ────────────────────────────────────────────────────────

/**
 * initSysmonWidgets()
 *
 * Starts all six Sysmon widgets.  Each polls its API and refreshes every 15s.
 * Safe to call multiple times — stops existing timers first.
 *
 * @param {Object} options
 * @param {boolean} [options.fileDrops=true]    Enable Suspicious Downloads widget
 * @param {boolean} [options.processTree=true]  Enable Process Tree widget
 * @param {boolean} [options.registry=true]     Enable Registry Changes widget
 * @param {boolean} [options.sigmaHits=true]    Enable Sigma Hits widget
 * @param {boolean} [options.riskTimeline=true] Enable Risk Timeline widget
 * @param {boolean} [options.statsBar=true]     Enable compact stats bar
 */
function initSysmonWidgets(options = {}) {
  stopSysmonWidgets();

  const cfg = {
    fileDrops:    true,
    processTree:  true,
    registry:     true,
    sigmaHits:    true,
    riskTimeline: true,
    statsBar:     true,
    ...options,
  };

  if (cfg.fileDrops    && document.getElementById('sysmon-file-drops'))    _schedule(loadSysmonFileDrops);
  if (cfg.processTree  && document.getElementById('sysmon-process-tree'))   _schedule(loadSysmonProcessTree);
  if (cfg.registry     && document.getElementById('sysmon-registry'))       _schedule(loadSysmonRegistry);
  if (cfg.sigmaHits    && document.getElementById('sysmon-sigma-hits'))     _schedule(loadSysmonSigmaHits);
  if (cfg.riskTimeline && document.getElementById('sysmon-risk-timeline'))  _schedule(loadSysmonRiskTimeline);
  if (cfg.statsBar     && document.getElementById('sysmon-stats-bar'))      _schedule(loadSysmonStatsBar);
}

// Auto-init if DOM already ready (e.g. script loaded deferred)
if (document.readyState !== 'loading') {
  initSysmonWidgets();
} else {
  document.addEventListener('DOMContentLoaded', () => initSysmonWidgets());
}
