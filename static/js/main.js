/**
 * static/js/main.js
 * ==================
 * Shared utilities used by ALL other JS files.
 * - api()       → fetch wrapper for JSON API calls
 * - toast()     → bottom notification
 * - showPage()  → SPA navigation
 * - levelBadge()→ HTML badge for log levels
 *
 * HOW JAVASCRIPT TALKS TO PYTHON:
 *   JavaScript uses fetch() to call Flask API endpoints.
 *   Example:
 *     const data = await api('/api/stats');
 *   This calls GET http://localhost:5000/api/stats
 *   Flask runs analyze_api.py → queries SQLite → returns JSON
 *   JavaScript receives the JSON and renders it in the DOM.
 *
 * ALL API CALLS ARE ASYNC (async/await pattern).
 * No page reloads — everything updates in place.
 */

'use strict';

// ── Global state ────────────────────────────────────────────────────────────
window.LV = {
  currentPage: 'dashboard',
  currentLogsCategory: 'application',
};

// ── API Helper ───────────────────────────────────────────────────────────────
/**
 * api(path, options) → JSON response
 * Wraps fetch() with error handling and JSON parsing.
 * Usage: const data = await api('/api/stats');
 *        const data = await api('/api/fetch-real', { method: 'POST' });
 */
async function api(path, options = {}) {
  try {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.error(`API error [${path}]:`, err);
    throw err;
  }
}

// ── Toast notification ───────────────────────────────────────────────────────
let _toastTimer = null;
function toast(msg, duration = 3000) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), duration);
}

// ── SPA Navigation ───────────────────────────────────────────────────────────
/**
 * showPage(name, clickedEl)
 * Hides all .page divs, shows #page-{name}, marks nav item active.
 * Special pages trigger their load functions.
 */
function showPage(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const target = document.getElementById('page-' + name);
  if (target) target.classList.add('active');

  document.querySelectorAll('.nav-item, .analysis-item').forEach(n => n.classList.remove('active'));
  if (el) el.classList.add('active');

  window.LV.currentPage = name;

  // Trigger page-specific loaders
  if (name === 'dashboard')    loadDashboard();
  if (name === 'frequency')    loadFrequency();
  if (name === 'anomaly')      loadAnomaly();
  if (name === 'threats')      loadThreats();
  if (name === 'fullanalysis') document.getElementById('analysis-results').style.display = 'none';
  if (name === 'chat')         onChatPageOpen();
  if (name === 'perform')      if (typeof initPerformAnalysis === 'function') initPerformAnalysis();
}

async function showLogsPage(category, el) {
  window.LV.currentLogsCategory = category;
  showPage('logs', el);

  const labels = {
    application: 'Application', system: 'System',
    security: 'Security', windows_update: 'Win Update'
  };
  const titleEl = document.getElementById('logs-page-title');
  if (titleEl) titleEl.textContent = `📋 ${labels[category] || category} Logs`;

  const levelFilter = document.getElementById('level-filter');
  if (levelFilter) levelFilter.value = '';

  // Load available days for this category
  try {
    const dayData = await api(`/api/days/${category}`);
    const daySelect = document.getElementById('day-filter');
    if (daySelect) {
      daySelect.innerHTML = '<option value="">All Days</option>';
      (dayData.days || []).forEach(d => {
        const opt = document.createElement('option');
        opt.value = d.date;
        const errBadge = d.errors > 0 ? ` ⚠${d.errors}` : '';
        opt.textContent = `${d.date} (${d.total}${errBadge})`;
        daySelect.appendChild(opt);
      });
    }
  } catch (e) {}

  loadLogs(category, '', '', 1);
}

// ── Level badge HTML ─────────────────────────────────────────────────────────
function levelBadge(level) {
  const map = {
    ERROR:    'badge-error',
    CRITICAL: 'badge-critical',
    WARNING:  'badge-warning',
    INFO:     'badge-info',
    SUCCESS:  'badge-success',
    FAILURE:  'badge-error',
  };
  const cls = map[level] || 'badge-info';
  return `<span class="badge ${cls}">${level || 'INFO'}</span>`;
}

// ── Severity color ───────────────────────────────────────────────────────────
function severityColor(sev) {
  return {
    CRITICAL: 'var(--red)', HIGH: 'var(--orange)',
    MEDIUM: 'var(--yellow)', LOW: 'var(--green)'
  }[sev] || 'var(--text-dim)';
}

// ── Format timestamp ─────────────────────────────────────────────────────────
function fmtTs(ts) {
  if (!ts) return '—';
  return ts.replace('T', ' ').slice(0, 19);
}

// ── Escape HTML ──────────────────────────────────────────────────────────────
function esc(str) {
  return String(str || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadDashboard();
  startActivityFeed();
  checkChatStatus();
});

window.addEventListener('focus', function() {
  if (window.LV && window.LV.currentPage === 'perform' && typeof initPerformAnalysis === 'function') {
    initPerformAnalysis();
  }
});
