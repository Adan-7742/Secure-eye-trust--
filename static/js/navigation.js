/**
 * navigation.js — Secure Eye Trust+ v4
 * Chat is now a NORMAL PAGE TAB (not a floating overlay).
 * Network SSE torn down on every tab change.
 */
let _networkActive = false;

function showPage(name, el) {
  // Always stop network streams first
  if (_networkActive) {
    _networkActive = false;
    try { teardownNetwork?.(); } catch(e) {}
  }

  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

  // Show target
  const target = document.getElementById('page-' + name);
  if (target) target.classList.add('active');

  // Nav highlight — covers both nav-item and analysis-item
  document.querySelectorAll('.nav-item, .analysis-item').forEach(n => n.classList.remove('active'));
  if (el) el.classList.add('active');

  // Per-page init
  if (name === 'dashboard') {
    loadDashboard?.();
  } else {
    stopSysPolling?.();
  }
  if (name === 'frequency')   loadFrequency?.();
  if (name === 'anomaly')     loadAnomaly?.();
  if (name === 'network') {
    _networkActive = true;
    setTimeout(() => { if (_networkActive) initNetwork?.(); }, 100);
  }
  if (name === 'reports') {
    loadReportsFromServer?.();
  }
  if (name === 'intruder') {
    startIntruderPolling?.();
  } else {
    stopIntruderPolling?.();
  }
  if (name === 'locker') {
    initLocker?.();
  }
  if (name === 'perform') {
    initPerformAnalysis?.();
  }
  if (name === 'analyzer') {
    initLogAnalyzer?.();
    initAnalyzerDrop?.();
  }
  if (name === 'fullanalysis') {
    const r = document.getElementById('analysis-results');
    if (r) r.style.display = 'none';
  }
  if (name === 'chat') {
    initChat?.();
    document.getElementById('chat-unread-dot')?.classList.remove('show');
    setTimeout(() => document.getElementById('chat-input')?.focus(), 150);
  }
}

async function doFetch() {
  const btn = document.getElementById('fetch-btn');
  if (!btn) return;

  btn.disabled = true;
  btn.textContent = '⟳ Fetching…';

  try {
    const data = await apiPost('/api/fetch-real');

    if (data.error) {
      toast('❌ ' + data.error, 5000);
      return;
    }

    const counts  = data.counts || {};
    const total   = Object.values(counts).reduce((a, b) => a + b, 0);
    const parts   = Object.entries(counts)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => `${k}: ${fmt(v)}`);

    const summary  = parts.length ? parts.join(' · ') : 'No events found';
    const secNote  = (counts.security === 0)
      ? ' ⚠ Security: 0 (needs Admin)'
      : '';

    toast(`✅ Fetched ${fmt(total)} events in ${data.elapsed}s — ${summary}${secNote}`, 5000);
    loadDashboard?.();
    updateContextStrip?.();

  } catch(e) {
    const msg = e.message || String(e);
    if (msg.includes('400')) {
      toast('❌ pywin32 not installed — run: pip install pywin32', 6000);
    } else if (msg.includes('401') || msg.includes('403')) {
      toast('❌ Session expired — please log in again', 5000);
    } else if (msg.includes('500')) {
      toast('❌ Server error — check terminal for details', 5000);
    } else {
      toast('❌ Fetch failed: ' + msg, 5000);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = '🪟 Fetch Logs';
  }
}

async function clearLogs() {
  if (!confirm('Clear all logs from database?')) return;
  await apiPost('/api/clear');
  toast('🗑 Logs cleared');
  loadDashboard?.();
}
