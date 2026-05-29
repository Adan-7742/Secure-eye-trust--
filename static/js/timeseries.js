/**
 * static/js/timeseries.js — Secure Eye Trust+
 * =============================================
 * Time-Series Analysis page.
 * Streams: Failed Logins · Error Spikes · Shutdown/Restart Patterns
 *          Network Blocks · Privilege Escalations
 *
 * APIs:
 *   GET /api/timeseries/summary      → all 5 streams last 60 days
 *   GET /api/timeseries/logins       → failed + success logins over time
 *   GET /api/timeseries/errors       → error spikes by category
 *   GET /api/timeseries/shutdowns    → shutdown/restart events
 *   GET /api/timeseries/custom       → any event ID over time
 */

'use strict';

var TS = {
  charts:  {},      // chart instances keyed by canvas id
  data:    {},      // last loaded data
  loading: false,
};

/* ═══════════════════════════════════════════════════════════════
   ENTRY POINT — called by nav or page load
═══════════════════════════════════════════════════════════════ */

async function loadTimeSeries() {
  if (TS.loading) return;
  TS.loading = true;

  _tsStatus('loading');

  try {
    var resp = await fetch('/api/timeseries/summary');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    if (!data.ok) throw new Error(data.error || 'API error');

    TS.data = data;
    _tsRenderAll(data);
    _tsStatus('done');
  } catch(e) {
    console.error('[timeseries]', e);
    _tsStatus('error', e.message);
  } finally {
    TS.loading = false;
  }
}

/* Refresh one stream with custom params */
async function tsRefreshStream(stream) {
  var interval = document.getElementById('ts-interval-' + stream)?.value || '1h';
  var date     = document.getElementById('ts-date-' + stream)?.value || '';
  var category = document.getElementById('ts-cat-' + stream)?.value || 'system';

  var url = '/api/timeseries/' + stream + '?interval=' + interval;
  if (date)     url += '&date=' + date;
  if (category) url += '&category=' + category;

  var btn = document.getElementById('ts-run-' + stream);
  if (btn) { btn.disabled = true; btn.textContent = '⟳'; }

  try {
    var resp = await fetch(url);
    var data = await resp.json();

    if (stream === 'logins')    _tsRenderLogins(data);
    if (stream === 'errors')    _tsRenderErrors(data);
    if (stream === 'shutdowns') _tsRenderShutdowns(data);
  } catch(e) {
    console.error('[timeseries] stream error:', e);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '▶ Run'; }
  }
}

async function tsRunCustom() {
  var eid      = document.getElementById('ts-custom-eid')?.value || '';
  var kw       = document.getElementById('ts-custom-kw')?.value || '';
  var cat      = document.getElementById('ts-custom-cat')?.value || 'security';
  var interval = document.getElementById('ts-custom-interval')?.value || '1h';

  if (!eid && !kw) { _tsToast('Enter an Event ID or keyword'); return; }

  var url = '/api/timeseries/custom?interval=' + interval + '&category=' + cat;
  if (eid) url += '&event_id=' + eid;
  if (kw)  url += '&keyword=' + encodeURIComponent(kw);

  var btn = document.getElementById('ts-custom-run');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Running…'; }

  try {
    var resp = await fetch(url);
    var data = await resp.json();
    _tsRenderCustom(data.result || {}, eid, kw);
  } catch(e) {
    console.error('[timeseries] custom error:', e);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '▶ Run'; }
  }
}

/* ═══════════════════════════════════════════════════════════════
   RENDER ALL STREAMS
═══════════════════════════════════════════════════════════════ */

function _tsRenderAll(data) {
  _tsRenderSummaryCards(data);
  _tsRenderLoginChart(data.logins);
  _tsRenderErrorChart(data.errors);
  _tsRenderShutdownChart(data.shutdowns);
  _tsRenderNetworkChart(data.network);
  _tsRenderPrivilegeChart(data.privileges);
  _tsRenderAnomalyLog(data);
  _tsRenderEventLog(data);
}

/* ── Summary stat cards ───────────────────────────────────────── */
function _tsRenderSummaryCards(data) {
  function _card(id, val, label, color) {
    var el = document.getElementById(id);
    if (!el) return;
    el.innerHTML =
      '<div style="font-size:28px;font-weight:900;color:' + color + ';line-height:1;margin-bottom:4px">' + val + '</div>' +
      '<div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.08em;font-weight:700">' + label + '</div>';
  }

  var anom = 0;
  ['logins','errors','shutdowns','network','privileges'].forEach(function(k){
    anom += (data[k]?.anomalies?.length || 0);
  });

  _card('ts-card-logins',    _fmtN(data.logins?.total)    || '—', 'Failed Login Events',     '#ef4444');
  _card('ts-card-errors',    _fmtN(data.errors?.total)    || '—', 'Error Spike Events',      '#f97316');
  _card('ts-card-shutdowns', _fmtN(data.shutdowns?.total) || '—', 'Shutdown Events',         '#fbbf24');
  _card('ts-card-anomalies', anom || '—',                         'Anomaly Spikes Detected', '#a78bfa');
}

/* ═══════════════════════════════════════════════════════════════
   CHART BUILDERS
═══════════════════════════════════════════════════════════════ */

function _tsChart(canvasId, config) {
  var ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (TS.charts[canvasId]) TS.charts[canvasId].destroy();
  TS.charts[canvasId] = new Chart(ctx, config);
}

var _GRID  = 'rgba(255,255,255,.04)';
var _TICK  = { color:'#475569', font:{ size:10 } };
var _COMMON_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 600, easing: 'easeOutQuart' },
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: 'rgba(15,23,42,.95)',
      titleColor: '#e2e8f0',
      bodyColor: '#94a3b8',
      borderColor: 'rgba(255,255,255,.1)',
      borderWidth: 1,
      padding: 10,
    }
  },
  scales: {
    x: { ticks: { color:'#475569', font:{size:10}, maxTicksLimit: 12, maxRotation: 45 }, grid: { color: _GRID } },
    y: { ticks: { color:'#475569', font:{size:10} }, grid: { color: _GRID }, beginAtZero: true },
  }
};

/* ── Login chart ─────────────────────────────────────────────── */
function _tsRenderLoginChart(loginData) {
  if (!loginData?.buckets?.length) return;

  var buckets = loginData.buckets;
  var labels  = buckets.map(function(b){ return b.label; });
  var counts  = buckets.map(function(b){ return b.count; });
  var colors  = buckets.map(function(b){
    return b.is_anomaly ? 'rgba(239,68,68,.9)' : 'rgba(248,113,113,.45)';
  });
  var borders = buckets.map(function(b){
    return b.is_anomaly ? '#ef4444' : '#f87171';
  });

  _tsChart('ts-chart-logins', {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Failed Logins',
        data:  counts,
        backgroundColor: colors,
        borderColor:     borders,
        borderWidth: 1,
        borderRadius: 3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 600, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(15,23,42,.95)',
          titleColor: '#e2e8f0',
          bodyColor: '#94a3b8',
          borderColor: 'rgba(255,255,255,.1)',
          borderWidth: 1,
          padding: 10,
          callbacks: {
            label: function(ctx) {
              var b = buckets[ctx.dataIndex];
              var lines = ['Events: ' + b.count];
              if (b.is_anomaly) lines.push('⚠ ANOMALY — Z=' + b.z_score);
              return lines;
            }
          }
        }
      },
      scales: {
        x: { ticks:{ color:'#475569', font:{size:10}, maxTicksLimit:12, maxRotation:45 }, grid:{ color:_GRID } },
        y: { ticks:{ color:'#475569', font:{size:10} }, grid:{ color:_GRID }, beginAtZero:true },
      }
    }
  });

  _tsRenderStreamPanel('ts-stream-logins', loginData);
}

/* ── Error chart ─────────────────────────────────────────────── */
function _tsRenderErrorChart(errorData) {
  if (!errorData?.buckets?.length) return;

  var buckets = errorData.buckets;
  var labels  = buckets.map(function(b){ return b.label; });
  var counts  = buckets.map(function(b){ return b.count; });
  var colors  = buckets.map(function(b){
    return b.is_anomaly ? 'rgba(251,146,60,.9)' : 'rgba(251,146,60,.4)';
  });

  _tsChart('ts-chart-errors', {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'Error Events',
        data:  counts,
        borderColor: '#f97316',
        backgroundColor: 'rgba(249,115,22,.08)',
        fill: true,
        tension: .4,
        pointRadius: buckets.map(function(b){ return b.is_anomaly ? 7 : 2; }),
        pointBackgroundColor: buckets.map(function(b){ return b.is_anomaly ? '#ef4444' : '#f97316'; }),
        pointBorderColor:     buckets.map(function(b){ return b.is_anomaly ? '#ef4444' : '#f97316'; }),
        borderWidth: 2,
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      animation:{ duration:600, easing:'easeOutQuart' },
      plugins:{ legend:{display:false}, tooltip:{ backgroundColor:'rgba(15,23,42,.95)', titleColor:'#e2e8f0', bodyColor:'#94a3b8', borderColor:'rgba(255,255,255,.1)', borderWidth:1, padding:10 } },
      scales:{ x:{ ticks:{color:'#475569',font:{size:10},maxTicksLimit:12,maxRotation:45}, grid:{color:_GRID} }, y:{ ticks:{color:'#475569',font:{size:10}}, grid:{color:_GRID}, beginAtZero:true } }
    },
  });

  _tsRenderStreamPanel('ts-stream-errors', errorData);
}

/* ── Shutdown chart ──────────────────────────────────────────── */
function _tsRenderShutdownChart(shutdownData) {
  if (!shutdownData?.buckets?.length) return;

  var buckets = shutdownData.buckets;
  var labels  = buckets.map(function(b){ return b.label; });
  var counts  = buckets.map(function(b){ return b.count; });

  _tsChart('ts-chart-shutdowns', {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Shutdown Events',
        data:  counts,
        backgroundColor: buckets.map(function(b){
          return b.count > (shutdownData.stats?.mean || 0) * 2
            ? 'rgba(239,68,68,.8)' : 'rgba(251,191,36,.5)';
        }),
        borderColor: '#fbbf24',
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      animation:{ duration:600, easing:'easeOutQuart' },
      plugins:{ legend:{display:false}, tooltip:{ backgroundColor:'rgba(15,23,42,.95)', titleColor:'#e2e8f0', bodyColor:'#94a3b8', borderColor:'rgba(255,255,255,.1)', borderWidth:1, padding:10 } },
      scales:{ x:{ ticks:{color:'#475569',font:{size:10},maxTicksLimit:12,maxRotation:45}, grid:{color:_GRID} }, y:{ ticks:{color:'#475569',font:{size:10}}, grid:{color:_GRID}, beginAtZero:true } }
    },
  });

  _tsRenderStreamPanel('ts-stream-shutdowns', shutdownData);
}

/* ── Network blocks chart ────────────────────────────────────── */
function _tsRenderNetworkChart(netData) {
  if (!netData?.buckets?.length) return;

  var buckets = netData.buckets;
  _tsChart('ts-chart-network', {
    type: 'line',
    data: {
      labels: buckets.map(function(b){ return b.label; }),
      datasets: [{
        label: 'Network Blocks (EID 5152/5157)',
        data:  buckets.map(function(b){ return b.count; }),
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56,189,248,.06)',
        fill: true, tension: .4, borderWidth: 2,
        pointRadius: buckets.map(function(b){ return b.is_anomaly ? 6 : 2; }),
        pointBackgroundColor: buckets.map(function(b){ return b.is_anomaly ? '#ef4444' : '#38bdf8'; }),
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      animation:{ duration:600, easing:'easeOutQuart' },
      plugins:{ legend:{display:false}, tooltip:{ backgroundColor:'rgba(15,23,42,.95)', titleColor:'#e2e8f0', bodyColor:'#94a3b8', borderColor:'rgba(255,255,255,.1)', borderWidth:1, padding:10 } },
      scales:{ x:{ ticks:{color:'#475569',font:{size:10},maxTicksLimit:12,maxRotation:45}, grid:{color:_GRID} }, y:{ ticks:{color:'#475569',font:{size:10}}, grid:{color:_GRID}, beginAtZero:true } }
    },
  });

  _tsRenderStreamPanel('ts-stream-network', netData);
}

/* ── Privilege escalation chart ──────────────────────────────── */
function _tsRenderPrivilegeChart(privData) {
  if (!privData?.buckets?.length) return;

  var buckets = privData.buckets;
  _tsChart('ts-chart-privileges', {
    type: 'bar',
    data: {
      labels: buckets.map(function(b){ return b.label; }),
      datasets: [{
        label: 'Privilege Escalations (EID 4672/4673)',
        data:  buckets.map(function(b){ return b.count; }),
        backgroundColor: buckets.map(function(b){
          return b.is_anomaly ? 'rgba(167,139,250,.9)' : 'rgba(167,139,250,.45)';
        }),
        borderColor: '#a78bfa', borderWidth: 1, borderRadius: 3,
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      animation:{ duration:600, easing:'easeOutQuart' },
      plugins:{ legend:{display:false}, tooltip:{ backgroundColor:'rgba(15,23,42,.95)', titleColor:'#e2e8f0', bodyColor:'#94a3b8', borderColor:'rgba(255,255,255,.1)', borderWidth:1, padding:10 } },
      scales:{ x:{ ticks:{color:'#475569',font:{size:10},maxTicksLimit:12,maxRotation:45}, grid:{color:_GRID} }, y:{ ticks:{color:'#475569',font:{size:10}}, grid:{color:_GRID}, beginAtZero:true } }
    },
  });

  _tsRenderStreamPanel('ts-stream-privileges', privData);
}

/* ── Custom event chart ──────────────────────────────────────── */
function _tsRenderCustom(result, eid, kw) {
  var title = eid ? 'EID ' + eid : '"' + kw + '"';
  var titleEl = document.getElementById('ts-custom-title');
  if (titleEl) titleEl.textContent = title + ' over time';

  var wrap = document.getElementById('ts-custom-result');
  if (wrap) wrap.style.display = 'block';

  if (!result?.buckets?.length) {
    var el = document.getElementById('ts-custom-empty');
    if (el) el.style.display = 'block';
    return;
  }

  var buckets = result.buckets;
  _tsChart('ts-chart-custom', {
    type: 'bar',
    data: {
      labels: buckets.map(function(b){ return b.label; }),
      datasets: [{
        label: title,
        data:  buckets.map(function(b){ return b.count; }),
        backgroundColor: buckets.map(function(b){
          return b.is_anomaly ? 'rgba(239,68,68,.8)' : 'rgba(88,166,255,.5)';
        }),
        borderColor: '#58a6ff', borderWidth: 1, borderRadius: 3,
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      animation:{ duration:600, easing:'easeOutQuart' },
      plugins:{ legend:{display:false}, tooltip:{ backgroundColor:'rgba(15,23,42,.95)', titleColor:'#e2e8f0', bodyColor:'#94a3b8', borderColor:'rgba(255,255,255,.1)', borderWidth:1, padding:10 } },
      scales:{ x:{ ticks:{color:'#475569',font:{size:10},maxTicksLimit:12,maxRotation:45}, grid:{color:_GRID} }, y:{ ticks:{color:'#475569',font:{size:10}}, grid:{color:_GRID}, beginAtZero:true } }
    },
  });

  _tsRenderStreamPanel('ts-custom-stats', result);
}

/* ── Stream panel: stats + anomaly list + ticker ─────────────── */
function _tsRenderStreamPanel(id, streamData) {
  var el = document.getElementById(id);
  if (!el || !streamData) return;

  var s     = streamData.stats || {};
  var anoms = streamData.anomalies || [];
  var peak  = streamData.peak;

  var anomHtml = anoms.length
    ? anoms.map(function(a){
        return '<div class="ts-anomaly-row">' +
          '<span class="ts-anomaly-time">' + a.label + '</span>' +
          '<span class="ts-anomaly-count">' + a.count.toLocaleString() + '</span>' +
          '<span class="ts-anomaly-z">Z=' + a.z_score + '</span>' +
          '<span class="ts-anomaly-warn">⚠ spike</span>' +
        '</div>';
      }).join('')
    : '<div style="color:#4ade80;font-size:11px;padding:6px 0">✅ No anomalies in this window</div>';

  el.innerHTML =
    '<div class="ts-stats-row">' +
      _tsStatPill('Total',    _fmtN(streamData.total), '#e2e8f0') +
      _tsStatPill('Mean/hr',  s.mean || '—',           '#94a3b8') +
      _tsStatPill('Std Dev',  s.std_dev || '—',        '#64748b') +
      _tsStatPill('Peak',     peak ? peak.count + ' @ ' + peak.label : '—', '#f97316') +
      _tsStatPill('Anomalies', anoms.length,            anoms.length > 0 ? '#ef4444' : '#4ade80') +
    '</div>' +
    '<div class="ts-anomaly-list">' +
      '<div class="ts-anomaly-list-title">⚠ Anomalous Buckets (Z &gt; 2.5)</div>' +
      anomHtml +
    '</div>';
}

function _tsStatPill(label, val, color) {
  return '<div class="ts-stat-pill">' +
    '<div style="font-size:16px;font-weight:900;color:' + color + '">' + val + '</div>' +
    '<div class="ts-stat-label">' + label + '</div>' +
  '</div>';
}

/* ── Global anomaly log ───────────────────────────────────────── */
function _tsRenderAnomalyLog(data) {
  var el = document.getElementById('ts-anomaly-log');
  if (!el) return;

  var allAnoms = [];
  var STREAM_COLORS = {
    logins:'#ef4444', errors:'#f97316', shutdowns:'#fbbf24',
    network:'#38bdf8', privileges:'#a78bfa'
  };
  var STREAM_NAMES = {
    logins:'Failed Logins', errors:'Error Spikes', shutdowns:'Shutdowns',
    network:'Network Blocks', privileges:'Privilege Escalation'
  };

  Object.keys(STREAM_COLORS).forEach(function(key) {
    var stream = data[key];
    if (!stream?.anomalies?.length) return;
    stream.anomalies.forEach(function(a) {
      allAnoms.push({
        stream: key,
        name:   STREAM_NAMES[key],
        color:  STREAM_COLORS[key],
        label:  a.label,
        count:  a.count,
        z:      a.z_score,
      });
    });
  });

  if (!allAnoms.length) {
    el.innerHTML = '<div style="color:#4ade80;padding:18px;text-align:center;font-size:13px">✅ No anomalies detected across all streams in this period</div>';
    return;
  }

  // Sort by Z-score descending
  allAnoms.sort(function(a,b){ return Math.abs(b.z) - Math.abs(a.z); });

  el.innerHTML = allAnoms.map(function(a) {
    var zAbs = Math.abs(a.z);
    var sev  = zAbs > 4 ? 'CRITICAL' : zAbs > 3 ? 'HIGH' : 'MEDIUM';
    var sevColor = { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#fbbf24' }[sev];
    return '<div class="ts-anom-entry">' +
      '<div style="width:3px;height:100%;background:' + a.color + ';flex-shrink:0;border-radius:2px"></div>' +
      '<div style="flex:1;padding:10px 14px">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">' +
          '<span style="font-size:9px;font-weight:800;padding:2px 7px;border-radius:10px;background:' + sevColor + '18;color:' + sevColor + ';border:1px solid ' + sevColor + '44">' + sev + '</span>' +
          '<span style="font-size:12px;font-weight:700;color:#e2e8f0">' + _tsEsc(a.name) + '</span>' +
          '<span style="font-size:11px;color:#475569;font-family:monospace">' + _tsEsc(a.label) + '</span>' +
        '</div>' +
        '<div style="font-size:11px;color:#64748b">' +
          a.count.toLocaleString() + ' events this bucket &nbsp;·&nbsp; ' +
          'Z-score = <strong style="color:' + sevColor + '">' + a.z + '</strong>' +
          (zAbs > 3 ? ' &nbsp;·&nbsp; <span style="color:#ef4444">🔥 Statistical outlier — likely attack or incident</span>' : '') +
        '</div>' +
      '</div>' +
    '</div>';
  }).join('');
}

/* ── CLI-style event ticker ───────────────────────────────────── */
function _tsRenderEventLog(data) {
  var el = document.getElementById('ts-event-ticker');
  if (!el) return;

  // Build time-ordered buckets across all streams for the ASCII-style display
  var STREAMS = {
    logins:     { label:'Failed Logins',          col:'#ef4444', char:'🔐' },
    errors:     { label:'Error Events',           col:'#f97316', char:'🔥' },
    shutdowns:  { label:'Shutdown Events',        col:'#fbbf24', char:'⚡' },
    network:    { label:'Network Blocks',         col:'#38bdf8', char:'🌐' },
    privileges: { label:'Privilege Escalations',  col:'#a78bfa', char:'⬆' },
  };

  var allRows = [];
  Object.entries(STREAMS).forEach(function(entry) {
    var key = entry[0], meta = entry[1];
    var stream = data[key];
    if (!stream?.buckets?.length) return;

    // Only show non-zero + anomaly buckets in ticker
    stream.buckets.forEach(function(b) {
      if (b.count === 0) return;
      allRows.push({ label: b.label, count: b.count, is_anomaly: b.is_anomaly,
        z: b.z_score, meta: meta, key: key });
    });
  });

  allRows.sort(function(a,b){ return (a.label < b.label) ? -1 : 1; });

  if (!allRows.length) {
    el.innerHTML = '<div style="color:#475569;font-family:monospace;font-size:11px;padding:8px">No events in selected window</div>';
    return;
  }

  var maxCount = Math.max.apply(null, allRows.map(function(r){ return r.count; }));

  el.innerHTML = allRows.map(function(r) {
    var barLen = Math.max(1, Math.round(r.count / maxCount * 30));
    var bar    = '█'.repeat(barLen);
    var aFlag  = r.is_anomaly ? ' ⚠ <span style="color:#ef4444;font-weight:700">anomaly</span>' : '';
    return '<div class="ts-ticker-row" style="border-left:2px solid ' + r.meta.col + '22">' +
      '<span class="ts-ticker-time">' + r.meta.char + ' ' + r.label + '</span>' +
      '<span class="ts-ticker-stream" style="color:' + r.meta.col + '88">' + r.meta.label.substring(0,12) + '</span>' +
      '<span class="ts-ticker-bar" style="color:' + r.meta.col + '">' + bar + '</span>' +
      '<span class="ts-ticker-count" style="color:' + r.meta.col + '">' + r.count.toLocaleString() + '</span>' +
      aFlag +
    '</div>';
  }).join('');
}

/* ── Stream-specific re-render (called from tsRefreshStream) ─── */
function _tsRenderLogins(data)    { _tsRenderLoginChart(data.failed);   _tsRenderStreamPanel('ts-stream-logins', data.failed); }
function _tsRenderErrors(data)    { _tsRenderErrorChart(data.errors);   _tsRenderStreamPanel('ts-stream-errors', data.errors); }
function _tsRenderShutdowns(data) { _tsRenderShutdownChart(data.all);   _tsRenderStreamPanel('ts-stream-shutdowns', data.all); }

/* ═══════════════════════════════════════════════════════════════
   UI HELPERS
═══════════════════════════════════════════════════════════════ */

function _tsStatus(state, msg) {
  var spinner = document.getElementById('ts-loading');
  var content = document.getElementById('ts-content');
  var error   = document.getElementById('ts-error');

  if (state === 'loading') {
    if (spinner) spinner.style.display = 'flex';
    if (content) content.style.display = 'none';
    if (error)   error.style.display   = 'none';
  } else if (state === 'done') {
    if (spinner) spinner.style.display = 'none';
    if (content) content.style.display = 'block';
    if (error)   error.style.display   = 'none';
  } else if (state === 'error') {
    if (spinner) spinner.style.display = 'none';
    if (content) content.style.display = 'block'; // show partial if any
    if (error)   { error.style.display = 'block'; error.textContent = '⚠ ' + (msg || 'Error loading data'); }
  }
}

function _tsToast(msg) {
  if (typeof toast === 'function') { toast(msg); return; }
  var t = document.createElement('div');
  t.textContent = msg;
  t.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#1e293b;color:#e2e8f0;padding:10px 16px;border-radius:8px;font-size:13px;z-index:9999;border:1px solid rgba(255,255,255,.1)';
  document.body.appendChild(t);
  setTimeout(function(){ t.remove(); }, 3000);
}

function _fmtN(n) { return (n !== undefined && n !== null) ? Number(n).toLocaleString() : '—'; }
function _tsEsc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
