/**
 * static/js/analysis.js
 * =====================
 * Analysis pages: frequency, anomaly, patterns, full analysis
 *
 * DATA FLOW:
 *   GET /api/analyze/frequency  → core/ml_engine/analyzer.run_frequency_analysis()
 *   GET /api/analyze/anomaly    → core/ml_engine/analyzer.run_anomaly_detection()
 *   GET /api/analyze/patterns   → core/ml_engine/analyzer.run_pattern_scan()
 *   GET /api/analyze/full       → core/ml_engine/analyzer.run_full_analysis()
 */

let freqChartInst, anomalyChartInst;

// ── Frequency Analysis ────────────────────────────────────────────────────────
async function loadFrequency() {
  const cat  = document.getElementById('freq-cat')?.value || 'application';
  const date = document.getElementById('freq-date')?.value || '';
  const el   = document.getElementById('freq-results');
  if (el) el.innerHTML = '<div class="loading"><div class="spinner"></div> Analyzing…</div>';

  const data = await api(`/api/analyze/frequency?category=${cat}&date=${date}`);
  renderFreqChart(data.data || {}, data.he_method || '');
}

function renderFreqChart(freq, heMethod) {
  const ctx = document.getElementById('freq-chart');
  if (ctx) {
    if (freqChartInst) freqChartInst.destroy();
    const labels = Object.keys(freq).slice(0, 20);
    const values = labels.map(k => freq[k]);
    freqChartInst = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{ label: 'Error Count', data: values,
          backgroundColor: '#ff4d6a88', borderColor: '#ef4444', borderWidth: 1 }]
      },
      options: {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#4a6080' }, grid: { color: '#1a2540' } },
          y: { ticks: { color: '#c8d8f0', font: { size: 10 } }, grid: { color: '#1a2540' } },
        }
      }
    });
  }

  const el = document.getElementById('freq-he-method');
  if (el) el.textContent = `🔐 HE: ${heMethod}`;
}

// ── Anomaly Detection ─────────────────────────────────────────────────────────
async function loadAnomaly() {
  const el = document.getElementById('anomaly-results');
  if (el) el.innerHTML = '<div class="loading"><div class="spinner"></div> Running Z-score analysis…</div>';

  const data = await api('/api/analyze/anomaly');
  renderAnomalyChart(data.series || []);
  renderAnomalyTable(data);
}

function renderAnomalyChart(series) {
  const ctx = document.getElementById('anomaly-chart');
  if (!ctx || !series.length) return;
  if (anomalyChartInst) anomalyChartInst.destroy();

  const labels  = series.map(d => d.date);
  const counts  = series.map(d => d.count);
  const colors  = series.map(d => d.is_anomaly ? '#ef4444' : 'rgba(56,189,248,.35)');

  anomalyChartInst = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Errors/day', data: counts, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#4a6080', maxTicksLimit: 15 }, grid: { color: '#1a2540' } },
        y: { ticks: { color: '#4a6080' }, grid: { color: '#1a2540' } },
      }
    }
  });
}

function renderAnomalyTable(data) {
  const el = document.getElementById('anomaly-results');
  if (!el) return;
  const anomalies = (data.series || []).filter(d => d.is_anomaly);

  if (!anomalies.length) {
    el.innerHTML = `<div style="color:var(--emerald);padding:14px">✅ No anomalies detected — error distribution appears normal</div>`;
    return;
  }

  let html = `<div style="margin-bottom:10px;color:var(--text-dim);font-size:12px">
    ${anomalies.length} anomalous days detected (|Z-score| > 2.0) — <code style="color:var(--emerald)">${data.method||''}</code>
  </div>`;

  html += '<table class="log-table"><thead><tr><th>Date</th><th>Errors</th><th>Z-Score</th><th>Severity</th></tr></thead><tbody>';
  anomalies.forEach(a => {
    const col = a.severity === 'CRITICAL' ? 'var(--red)' : 'var(--orange)';
    html += `<tr>
      <td style="font-family:var(--mono)">${a.date}</td>
      <td style="font-family:var(--mono)">${fmt(a.count)}</td>
      <td style="font-family:var(--mono);color:${col}">${a.zscore}</td>
      <td>${levelBadge(a.severity)}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}

// ── Full Analysis ─────────────────────────────────────────────────────────────
async function runFullAnalysis() {
  const btn = document.getElementById('run-analysis-btn');
  if (btn) btn.disabled = true;
  const loading = document.getElementById('analysis-loading');
  const results = document.getElementById('analysis-results');
  if (loading) loading.style.display = 'flex';
  if (results) results.style.display = 'none';

  try {
    const data = await api('/api/analyze/full');
    if (loading) loading.style.display = 'none';
    if (results) results.style.display = 'block';
    renderPatterns(data.patterns || [], 'pattern-results');
  } catch (e) {
    if (loading) loading.style.display = 'none';
    toast('❌ Analysis failed: ' + e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderPatterns(patterns, targetId) {
  const el = document.getElementById(targetId);
  if (!el) return;
  if (!patterns.length) { el.innerHTML = '<div style="color:var(--emerald);padding:14px">✅ No threat patterns matched</div>'; return; }

  let html = '';
  patterns.forEach(p => {
    const col  = SEV_COLOR[p.severity] || 'var(--text-dim)';
    const icon = SEV_ICON[p.severity]  || '⚪';
    html += `<div style="margin-bottom:12px;padding:14px;background:var(--bg);border:1px solid var(--border);border-left:3px solid ${col};border-radius:6px">
      <div style="display:flex;justify-content:space-between;margin-bottom:6px">
        <span style="font-weight:600;color:var(--text-bright)">${icon} ${p.pattern}</span>
        <span style="font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(0,0,0,.3);color:${col}">${p.severity} · ${fmt(p.hit_count)} hits</span>
      </div>
      <div style="font-size:12px;color:var(--text-dim);margin-bottom:5px">${p.description}</div>
      <div style="font-size:11px;font-family:var(--mono);color:var(--text-dim)">${trunc(p.sample,120)}</div>
    </div>`;
  });
  el.innerHTML = html;
}

