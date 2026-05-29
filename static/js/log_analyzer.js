/**
 * log_analyzer.js — Secure Eye Trust+
 * Isolated log file analyzer — no main DB writes.
 */

let _analyzerChart1 = null;
let _analyzerChart2 = null;
let _analyzerChart3 = null;

function initLogAnalyzer() {
  // nothing needed on init
}

async function analyzerUpload() {
  const fi  = document.getElementById('analyzer-file');
  const btn = document.getElementById('analyzer-btn');
  if (!fi || !fi.files.length) { toast('Select a log file first'); return; }

  const file = fi.files[0];

  // Show loading state
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-sm"></span> Analyzing…';
  document.getElementById('analyzer-results').style.display = 'none';
  document.getElementById('analyzer-empty').style.display = 'none';
  document.getElementById('analyzer-loading').style.display = 'flex';

  const form = new FormData();
  form.append('file', file);

  try {
    const r = await fetch('/api/analyze-upload', { method: 'POST', body: form });
    const d = await r.json();

    if (!d.ok) {
      toast('❌ ' + (d.error || 'Could not parse file'));
      document.getElementById('analyzer-loading').style.display = 'none';
      document.getElementById('analyzer-empty').style.display = 'flex';
      return;
    }

    _renderAnalyzerResults(d, file.name);
  } catch(e) {
    toast('❌ Analysis failed: ' + e.message);
    document.getElementById('analyzer-loading').style.display = 'none';
    document.getElementById('analyzer-empty').style.display = 'flex';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🔍 Analyze File';
  }
}

function _renderAnalyzerResults(d, filename) {
  document.getElementById('analyzer-loading').style.display = 'none';
  document.getElementById('analyzer-empty').style.display   = 'none';
  const results = document.getElementById('analyzer-results');
  results.style.display = 'block';

  // ── Header ──────────────────────────────────────────────────
  document.getElementById('az-filename').textContent  = filename;
  document.getElementById('az-total').textContent     = (d.total || 0).toLocaleString();
  document.getElementById('az-rawlines').textContent  = (d.raw_lines || 0).toLocaleString();

  // ── Risk badge ──────────────────────────────────────────────
  const riskEl = document.getElementById('az-risk');
  const riskColors = { Low:'#4ade80', Medium:'#fcd34d', High:'#fb923c', Critical:'#f87171' };
  const rc = riskColors[d.risk_label] || '#94a3b8';
  riskEl.textContent = d.risk_label + ' · ' + d.risk_score + '/100';
  riskEl.style.cssText = `background:${rc}18;color:${rc};border:1px solid ${rc}44;padding:5px 14px;border-radius:20px;font-size:13px;font-weight:700`;

  // ── Level summary cards ──────────────────────────────────────
  const lc = d.level_counts || {};
  const setStat = (id, v) => { const el=document.getElementById(id); if(el) el.textContent=(v||0).toLocaleString(); };
  setStat('az-critical', (lc.CRITICAL||0));
  setStat('az-errors',   (lc.ERROR||0) + (lc.FAILURE||0));
  setStat('az-warnings', lc.WARNING||0);
  setStat('az-info',     (lc.INFO||0) + (lc.SUCCESS||0));

  // ── Key Findings ─────────────────────────────────────────────
  const findingsEl = document.getElementById('az-findings');
  if (d.findings && d.findings.length > 0) {
    const icons = { critical:'🔴', error:'🟠', warning:'🟡', info:'🔵' };
    findingsEl.innerHTML = d.findings.map(f =>
      `<div class="az-finding az-finding-${f.type}">
        <span>${icons[f.type]||'•'}</span>
        <span>${f.text}</span>
      </div>`
    ).join('');
  } else {
    findingsEl.innerHTML = '<div style="color:var(--text-dim);font-size:13px;padding:8px 0">✅ No major issues detected</div>';
  }

  // ── Charts ───────────────────────────────────────────────────
  _buildLevelChart(d.level_counts);
  _buildTimelineChart(d.timeline);
  _buildHourlyChart(d.hourly);

  // ── Top Errors table ──────────────────────────────────────────
  const errTbl = document.getElementById('az-errors-table');
  if (d.top_errors && d.top_errors.length > 0) {
    errTbl.innerHTML = d.top_errors.map(e => {
      const cls = e.level === 'CRITICAL' ? '#f87171' : '#fb923c';
      return `<div class="az-err-row">
        <span class="az-err-badge" style="background:${cls}18;color:${cls}">${e.level}</span>
        <span class="az-err-ts">${e.ts}</span>
        <span class="az-err-msg">${_esc(e.message)}</span>
      </div>`;
    }).join('');
  } else {
    errTbl.innerHTML = '<div style="color:var(--text-dim);font-size:12px;padding:12px">No errors found</div>';
  }

  // ── Top Sources ───────────────────────────────────────────────
  const srcEl = document.getElementById('az-sources');
  if (d.top_sources && d.top_sources.length > 0) {
    const max = d.top_sources[0].count;
    srcEl.innerHTML = d.top_sources.map(s =>
      `<div class="az-src-row">
        <span class="az-src-name">${_esc(s.source)}</span>
        <div class="az-src-bar-wrap">
          <div class="az-src-bar" style="width:${Math.round(s.count/max*100)}%"></div>
        </div>
        <span class="az-src-count">${s.count.toLocaleString()}</span>
      </div>`
    ).join('');
  }

  // Scroll to results
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function _buildLevelChart(lc) {
  const ctx = document.getElementById('az-chart-level');
  if (!ctx) return;
  if (_analyzerChart1) { _analyzerChart1.destroy(); _analyzerChart1 = null; }
  const labels = ['Critical','Error/Failure','Warning','Info/Success'];
  const data   = [
    lc.CRITICAL||0,
    (lc.ERROR||0)+(lc.FAILURE||0),
    lc.WARNING||0,
    (lc.INFO||0)+(lc.SUCCESS||0)
  ];
  _analyzerChart1 = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: ['#f87171','#fb923c','#fcd34d','#4ade80'],
        borderWidth: 0,
        hoverOffset: 6,
      }]
    },
    options: {
      cutout: '65%',
      plugins: {
        legend: { position:'bottom', labels:{ color:'#8faac8', font:{size:11}, padding:10 } }
      }
    }
  });
}

function _buildTimelineChart(timeline) {
  const ctx = document.getElementById('az-chart-timeline');
  if (!ctx) return;
  if (_analyzerChart2) { _analyzerChart2.destroy(); _analyzerChart2 = null; }
  if (!timeline || timeline.length === 0) return;
  _analyzerChart2 = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: timeline.map(t => t.date),
      datasets: [{
        label: 'Log Entries',
        data:  timeline.map(t => t.count),
        backgroundColor: '#1a8cff44',
        borderColor:     '#1a8cff',
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color:'#4a6080', maxTicksLimit:8 }, grid: { color:'#1a2540' } },
        y: { ticks: { color:'#4a6080' }, grid: { color:'#1a2540' }, beginAtZero: true },
      }
    }
  });
}

function _buildHourlyChart(hourly) {
  const ctx = document.getElementById('az-chart-hourly');
  if (!ctx) return;
  if (_analyzerChart3) { _analyzerChart3.destroy(); _analyzerChart3 = null; }
  if (!hourly || hourly.length === 0) return;
  const maxVal = Math.max(...hourly.map(h => h.count), 1);
  _analyzerChart3 = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: hourly.map(h => h.hour),
      datasets: [{
        label: 'Activity',
        data:  hourly.map(h => h.count),
        backgroundColor: hourly.map(h => {
          const pct = h.count / maxVal;
          if (pct > 0.7) return '#ef444488';
          if (pct > 0.4) return '#f59e0b88';
          return '#1a8cff44';
        }),
        borderColor: hourly.map(h => {
          const pct = h.count / maxVal;
          if (pct > 0.7) return '#ef4444';
          if (pct > 0.4) return '#f59e0b';
          return '#1a8cff';
        }),
        borderWidth: 1,
        borderRadius: 2,
      }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color:'#4a6080', maxRotation:0, maxTicksLimit:12 }, grid: { color:'#1a2540' } },
        y: { ticks: { color:'#4a6080' }, grid: { color:'#1a2540' }, beginAtZero: true },
      }
    }
  });
}

function _esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Drag & drop support
function initAnalyzerDrop() {
  const zone = document.getElementById('analyzer-drop-zone');
  if (!zone) return;
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) {
      const fi = document.getElementById('analyzer-file');
      // Create a DataTransfer to set files on input
      const dt = new DataTransfer();
      dt.items.add(file);
      fi.files = dt.files;
      document.getElementById('az-selected-name').textContent = file.name;
      document.getElementById('az-selected-info').style.display = 'flex';
    }
  });
  document.getElementById('analyzer-file').addEventListener('change', function() {
    if (this.files[0]) {
      document.getElementById('az-selected-name').textContent = this.files[0].name;
      document.getElementById('az-selected-info').style.display = 'flex';
    }
  });
}
