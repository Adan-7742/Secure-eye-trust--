/**
 * static/js/realtime.js  — v2.1  (clean notifications)
 * =======================================================
 * Fixes the notification flood:
 *  ✅ Client-side dedup  — same EID+source within 90s = no new toast
 *  ✅ Max 3 toasts on screen at once — queue the rest, show when space opens
 *  ✅ Repeat counter     — "×4 more occurrences" on grouped events
 *  ✅ Client-side suppression list as safety net (matches server list)
 *  ✅ Bell badge capped at 99 and shows grouped count, not raw spam count
 */

'use strict';

let sseSource         = null;
let _liveCount        = 0;
let _notifHistory     = [];
let _unreadNotifCount = 0;

// Client-side dedup: "source|eid" → timestamp last shown
const _clientDedup    = new Map();
const _DEDUP_MS       = 90_000;   // 90 seconds
const _MAX_TOASTS     = 3;        // max visible toasts simultaneously
let   _toastQueue     = [];       // overflow queue
let   _activeToasts   = 0;

// Mirror of server suppression list — client safety net
const _SUPPRESSED_EIDS = new Set([
  '5152','5157','5158','4634','4624','4656','10016','5447'
]);

// ── SSE Connection ──────────────────────────────────────────────────────────

function startSSE() {
  if (sseSource) return;
  try {
    sseSource = new EventSource('/api/events');
    sseSource.onopen = () => setRealtimeBadge('🟢 Live', '#0c8');

    sseSource.onmessage = (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch(e) { return; }
      switch (data.type) {
        case 'live_update': {
          const n = data.payload?.new || 0;
          _liveCount += n;
          setRealtimeBadge(`🟢 Live +${_liveCount}`, '#0c8');
          showInfoToast(`📥 ${n} new Windows events captured`);
          loadDashboard?.();
          updateContextStrip?.();
          const active = document.querySelector('.page.active');
          if (active?.id === 'page-logs') loadLogs?.();
          if (data.payload?.errors?.length)
            data.payload.errors.forEach(e => _addToBellOnly(e));
          break;
        }
        case 'new_error':
          if (data.payload) _addToBellOnly(data.payload);  // bell only, no popup
          break;
        case 'fetch_start':
          setRealtimeBadge('⟳ Fetching…', '#fa0');
          break;
        case 'fetch_done': {
          setRealtimeBadge('🟢 Live', '#0c8');
          _liveCount = 0;
          loadDashboard?.();
          updateContextStrip?.();
          const n = data.payload?.counts;
          if (n) {
            const total = Object.values(n).reduce((a,b)=>a+b,0);
            showInfoToast(`✅ Fetched ${fmt(total)} events in ${data.payload?.elapsed}s`);
          }
          break;
        }
        case 'analysis_run':
          setRealtimeBadge('🧠 Analysing…', '#58a6ff');
          setTimeout(() => setRealtimeBadge('🟢 Live', '#0c8'), 4000);
          break;
      }
    };

    sseSource.onerror = () => {
      setRealtimeBadge('⚪ Reconnecting…', '#6e7681');
      sseSource.close(); sseSource = null;
      setTimeout(startSSE, 5000);
    };
  } catch(e) { console.warn('SSE not supported:', e); }
}

function setRealtimeBadge(text, color) {
  const el = document.getElementById('realtime-badge');
  if (!el) return;
  el.textContent    = text;
  el.style.color    = color;
  el.style.borderColor = color + '55';
}

// ══════════════════════════════════════════════════════════════════════════════
//  ERROR NOTIFICATION — deduplicated, rate-limited, grouped
// ══════════════════════════════════════════════════════════════════════════════

function showErrorNotification(log) {
  if (!log) return;

  const eid = String(log.event_id || '').trim();
  const src = String(log.source   || '').trim();
  const lvl = String(log.level    || 'ERROR').toUpperCase();

  // 1. Client-side EID suppression (safety net)
  if (_SUPPRESSED_EIDS.has(eid)) return;

  // 2. Client-side dedup
  const key     = `${src}|${eid}`;
  const lastSeen = _clientDedup.get(key) || 0;
  if (Date.now() - lastSeen < _DEDUP_MS) return;
  _clientDedup.set(key, Date.now());

  // 3. Build notification record
  const notif = {
    id:           Date.now() + '_' + Math.random().toString(36).slice(2),
    log,
    ts:           log.timestamp || new Date().toLocaleTimeString(),
    read:         false,
    level:        lvl,
    repeat_count: log.repeat_count || 1,
  };
  _notifHistory.unshift(notif);
  if (_notifHistory.length > 30) _notifHistory.pop();

  // 4. Unread badge — count unique events, not spam
  _unreadNotifCount = Math.min(_unreadNotifCount + 1, 99);
  _updateNotifBadge();

  // 5. Queue or show
  if (_activeToasts >= _MAX_TOASTS) {
    _toastQueue.push(notif);
  } else {
    _showToast(notif);
  }
}

function _showToast(notif) {
  _activeToasts++;

  const SEV = {
    CRITICAL: { border:'#ef4444', bg:'rgba(239,68,68,.13)',  icon:'🔴' },
    ERROR:    { border:'#f97316', bg:'rgba(249,115,22,.12)', icon:'🟠' },
    FAILURE:  { border:'#ef4444', bg:'rgba(239,68,68,.13)',  icon:'🔴' },
    WARNING:  { border:'#fbbf24', bg:'rgba(251,191,36,.1)',  icon:'🟡' },
  };
  const sev = SEV[notif.level] || SEV.ERROR;
  const log = notif.log;
  const src = (log.source  || 'Unknown Source').substring(0, 36);
  const msg = (log.message || 'No message').substring(0, 72);
  const eid = log.event_id ? ` · EID ${log.event_id}` : '';
  const rep = notif.repeat_count > 1
    ? `<span style="font-size:9px;color:${sev.border};font-family:monospace;margin-left:4px">×${notif.repeat_count} occurrences</span>`
    : '';

  const container = _getToastContainer();
  const toast     = document.createElement('div');
  toast.setAttribute('data-toast-id', notif.id);
  toast.style.cssText = `
    position:relative;overflow:hidden;padding:11px 13px 9px;border-radius:10px;
    background:#0d1626;border:1px solid rgba(255,255,255,.09);
    border-left:3px solid ${sev.border};color:#e2e8f0;font-size:12px;cursor:pointer;
    animation:rtToastIn .25s cubic-bezier(.16,1,.3,1);transition:transform .15s,opacity .2s;
    max-width:320px;min-width:260px;pointer-events:all;
    box-shadow:0 6px 24px rgba(0,0,0,.5);
  `;

  toast.innerHTML = `
    <div style="position:absolute;bottom:0;left:0;height:2px;background:${sev.border};
      opacity:.4;animation:rtProgress 7s linear forwards"></div>
    <div style="display:flex;gap:9px;align-items:flex-start">
      <span style="font-size:13px;flex-shrink:0;margin-top:1px">${sev.icon}</span>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:5px;margin-bottom:3px;flex-wrap:wrap">
          <span style="font-size:9px;font-weight:800;padding:1px 6px;border-radius:3px;
            background:${sev.bg};color:${sev.border};font-family:monospace;letter-spacing:.05em">${notif.level}</span>
          <span style="font-size:9px;color:#475569;font-family:monospace">${eid}</span>
          ${rep}
          <span style="font-size:9px;color:#2d3d50;margin-left:auto">${notif.ts.substring(0,19)}</span>
        </div>
        <div style="font-size:11px;font-weight:700;color:#c8d8e8;margin-bottom:2px;
          white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${_esc(src)}">${_esc(src)}</div>
        <div style="font-size:10px;color:#4a6070;line-height:1.4;
          overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${_esc(msg)}</div>
        <div style="margin-top:6px;font-size:9px;font-weight:700;color:${sev.border};
          padding:2px 8px;border-radius:3px;border:1px solid ${sev.border}33;
          background:${sev.bg};display:inline-block">
          🤖 Click for AI Fix
        </div>
      </div>
      <button onclick="event.stopPropagation();_dismissToastEl(this.closest('[data-toast-id]'))" style="
        background:none;border:none;color:#2d3d50;cursor:pointer;
        font-size:13px;padding:0;flex-shrink:0;line-height:1">✕</button>
    </div>
  `;

  toast.addEventListener('click', () => {
    _dismissToastEl(toast);
    notif.read = true;
    window.logExplainOpen?.(log);
  });

  container.appendChild(toast);

  // Auto dismiss after 7s
  const timer = setTimeout(() => _dismissToastEl(toast), 7000);
  toast._dismissTimer = timer;
}

function _dismissToastEl(el) {
  if (!el || el._dismissing) return;
  el._dismissing = true;
  clearTimeout(el._dismissTimer);
  el.style.opacity   = '0';
  el.style.transform = 'translateX(16px)';
  setTimeout(() => {
    el.remove();
    _activeToasts = Math.max(0, _activeToasts - 1);
    // Show next from queue
    if (_toastQueue.length > 0) {
      const next = _toastQueue.shift();
      _showToast(next);
    }
  }, 200);
}

function _dismissToast(notifId) {
  const el = document.querySelector(`[data-toast-id="${notifId}"]`);
  if (el) _dismissToastEl(el);
}

/** Simple info toast (non-error, small, non-clickable) */
function showInfoToast(message) {
  const container = _getToastContainer();
  const toast = document.createElement('div');
  toast.style.cssText = `
    padding:8px 12px;border-radius:8px;background:#0d1626;
    border:1px solid rgba(255,255,255,.07);border-left:3px solid #3b82f6;
    color:#6a8090;font-size:10px;animation:rtToastIn .25s ease;
    max-width:280px;pointer-events:none;
  `;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity='0'; setTimeout(()=>toast.remove(),200); }, 3000);
}

/** Legacy shim */
function toast(msg) { showInfoToast(msg); }

function _esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function _getToastContainer() {
  let c = document.getElementById('rt-toast-container');
  if (!c) {
    c = document.createElement('div');
    c.id = 'rt-toast-container';
    c.style.cssText = `
      position:fixed;bottom:20px;right:20px;z-index:10001;
      display:flex;flex-direction:column;gap:7px;pointer-events:none;
    `;
    document.body.appendChild(c);

    if (!document.getElementById('rt-toast-styles')) {
      const s = document.createElement('style');
      s.id = 'rt-toast-styles';
      s.textContent = `
        @keyframes rtToastIn  { from{opacity:0;transform:translateX(16px)} to{opacity:1;transform:translateX(0)} }
        @keyframes rtProgress { from{width:100%} to{width:0} }
        #rt-toast-container > * { pointer-events:all; }
        #rt-toast-container > *:hover { transform:translateY(-2px); }
      `;
      document.head.appendChild(s);
    }
  }
  return c;
}

// ── Badge ───────────────────────────────────────────────────────────────────

function _updateNotifBadge() {
  const count = _unreadNotifCount;
  const label = count > 99 ? '99+' : String(count);
  const show  = count > 0;

  const b1 = document.getElementById('alert-badge-count');
  if (b1) { b1.textContent = label; b1.classList.toggle('hidden', !show); }

  const b2 = document.getElementById('alert-badge');
  if (b2) { b2.style.display = show ? 'flex' : 'none'; b2.textContent = label; }
}

function clearUnreadNotifCount() {
  _unreadNotifCount = 0;
  _notifHistory.forEach(n => n.read = true);
  _updateNotifBadge();
}

function getNotifHistory() { return _notifHistory; }

// ── Expose ──────────────────────────────────────────────────────────────────
window.showErrorNotification = showErrorNotification;
window.showInfoToast         = showInfoToast;
window.toast                 = toast;
window.clearUnreadNotifCount = clearUnreadNotifCount;
window.getNotifHistory       = getNotifHistory;

document.addEventListener('DOMContentLoaded', startSSE);

// ── Dedicated error stream ──────────────────────────────────────────────────
let _errorStreamSrc = null;

function _startErrorStream() {
  if (_errorStreamSrc) return;
  try {
    _errorStreamSrc = new EventSource('/api/error-stream');
    _errorStreamSrc.onmessage = (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch(e) { return; }
      if (data.type === 'new_error' && data.payload) {
        // ✅ Only update the bell badge — do NOT show popup toasts automatically
        _addToBellOnly(data.payload);
      }
    };
    _errorStreamSrc.onerror = () => {
      _errorStreamSrc?.close(); _errorStreamSrc = null;
      setTimeout(_startErrorStream, 7000);
    };
  } catch(e) { console.warn('Error stream N/A:', e); }
}

/** Add event to bell history + badge WITHOUT showing a popup toast */
function _addToBellOnly(log) {
  if (!log) return;
  const eid = String(log.event_id || '').trim();
  if (_SUPPRESSED_EIDS.has(eid)) return;

  const key = `${log.source||''}|${eid}`;
  const lastSeen = _clientDedup.get(key) || 0;
  if (Date.now() - lastSeen < _DEDUP_MS) return;
  _clientDedup.set(key, Date.now());

  const notif = {
    id:           Date.now() + '_' + Math.random().toString(36).slice(2),
    log,
    ts:           log.timestamp || new Date().toLocaleTimeString(),
    read:         false,
    level:        String(log.level || 'ERROR').toUpperCase(),
    repeat_count: log.repeat_count || 1,
  };
  _notifHistory.unshift(notif);
  if (_notifHistory.length > 50) _notifHistory.pop();
  _unreadNotifCount = Math.min(_unreadNotifCount + 1, 99);
  _updateNotifBadge();
}

document.addEventListener('DOMContentLoaded', _startErrorStream);
