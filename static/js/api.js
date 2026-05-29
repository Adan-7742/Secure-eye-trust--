/**
 * static/js/api.js
 * ================
 * Shared HTTP helpers used by every other JS module.
 *
 * HOW JS ↔ PYTHON WORKS:
 *   1. Browser calls api('/api/stats')
 *   2. Flask receives GET /api/stats → runs api/system_api.py → stats()
 *   3. Python queries SQLite → returns JSON
 *   4. JS receives JSON object → other modules render it in the DOM
 *
 * All endpoints are defined in api/*.py (Flask blueprints).
 */

const BASE = '';   // same origin

/**
 * GET helper — returns parsed JSON or throws
 */
async function api(path) {
  const r = await fetch(BASE + path);
  if (!r.ok) throw new Error(`HTTP ${r.status} — ${path}`);
  return r.json();
}

/**
 * POST helper
 */
async function apiPost(path, body = {}) {
  const r = await fetch(BASE + path, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status} — ${path}`);
  return r.json();
}

/**
 * Show toast notification
 */
function toast(msg, duration = 3000) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), duration);
}

/**
 * Level badge HTML
 */
function levelBadge(level) {
  const l = (level || 'INFO').toUpperCase();
  return `<span class="badge badge-${l}">${l}</span>`;
}

/**
 * Severity color helper
 */
const SEV_COLOR = {
  CRITICAL: 'var(--red)',
  HIGH:     'var(--orange)',
  MEDIUM:   'var(--yellow)',
  LOW:      'var(--green)',
  INFO:     'var(--blue)',
};
const SEV_ICON = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢', INFO: '⚪' };

/**
 * Format number with commas
 */
function fmt(n) {
  return (n ?? 0).toLocaleString();
}

/**
 * Truncate long strings
 */
function trunc(s, n = 80) {
  return s && s.length > n ? s.slice(0, n) + '…' : (s || '');
}
